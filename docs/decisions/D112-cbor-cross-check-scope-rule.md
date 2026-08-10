# D112 — Q130: how the CBOR cross-check decides scope, and why the registry flag is not Q130's to build

- **Status: RESOLVED — the registry flag IS the right answer, IS built, and is
  NOT Q130's.** It already has an owner with a fuller specification and a
  *measured* instance: **F31**, open since 2026-07-28, `tasks/F.md:426-437`,
  whose `Do` names `FROZEN.sha256`'s `#! kind` directives as the home in the
  same words Q130 reaches for twelve days later. **Q54** then binds the two
  together — *"Land it with F31's CBOR flag rather than beside it — two columns
  on one directive line and one parser, not two mechanisms over the same
  registry"* — so Q130 building a one-column flag would force exactly the second
  directive edit Q54 exists to forbid. **Q130's own subject is the DUPLICATION,
  and that is a Python-internal change plus one Rust scrape.** The brief's
  decisive question — *is a defence against a hypothetical worth a freeze
  event?* — is answered twice over and both times against the premise it
  assumes. **There is no freeze event**: `testdata/vectors/v1/FROZEN.sha256`'s
  own bytes are pinned by nothing, its `#! kind` block has been appended to
  **three times post-freeze** (S4 2026-08-01, R12, A22 2026-08-09), and
  `vector-freeze.sh`'s frozen append-only guard iterates `grep -v '^#'` — it
  cannot see a directive line at all. **And the threat is not hypothetical**:
  `crypto/manifest-aead.json`'s `manifest_bytes` is CBOR-*shaped*, **not
  well-formed** (`5820` declares 32 bytes over a 30-byte literal; `581e` was
  meant), carries no sidecar, is checked by no CBOR checker, and sat through a
  format freeze. F31 measured it; this decision re-measured it. The false
  *negative* is live in the tree today and the false *positive* is the
  hypothetical — the row has them the wrong way round.
- **Date: 2026-08-10** (M2 wave 12 planning round; briefed to rule on whether to
  build the flag, and the answer is *yes, and not here*)
- **Owning tasks: Q130** (the ruling; closed by it), **F31** (the flag — bound
  by §4 R5–R9), **Q54** (the second column on the same directive), **F14**
  (the checker), **Q6** (the directive vocabulary and its parser)
- **Amends**: **`TODO.md:560`** — three of its statements are false and one is
  backwards (§1.1, §1.2, §1.6); **`docs/testing/cbor-cross-check.md` §7 and
  §8.1**, whose *"Tracked as **Q130**"* misroutes the flag away from its owner;
  **`testdata/vectors/v1/crosscheck_cbor.py:877-904`**, whose known-limitation
  comment is right about the limitation and wrong about who closes it.
  **Supersedes**: nothing. **Binds against**: D31 §6 (no vector or case name
  hard-coded in this checker), D31 §8 (cbor2 decodes only), F19, Q6, Q14, F31,
  Q54, D101 §5.

---

## The problem, in one sentence

Q130 says the honest fix for the CBOR cross-check's scope sniff is a
registry-level flag on the kind and that the duplication was already repaired;
measured, the flag belongs to a task that has owned it for twelve days with a
better specification, the duplication is **still live** in the file the row
declares fixed, and the freeze cost the brief warns about does not exist.

---

## 1. What was measured

Everything below was executed at `5fbc48d` on 2026-08-10. Commands and verdicts
are in §6.3.

### 1.1 `_in_scope` is NOT the single predicate. The duplication the row declares repaired is still there.

The row states: *"Both now share one `_in_scope` helper."* They do not.

`_in_scope` is defined **inside `self_test`**, at `crosscheck_cbor.py:958-959`:

```
    def _in_scope(case: dict) -> bool:
        return isinstance(case.get("diagnostic"), dict)
```

`run` does not call it and cannot — it is a closure in another function. `run`
carries its own copy of the expression inline, at `:905-909`:

```
        subject = [
            c
            for c in vector.get("expect", {}).get("cases", []) if isinstance(c.get("diagnostic"), dict)
        ]
```

`grep -n "_in_scope" testdata/vectors/v1/crosscheck_cbor.py` returns four hits —
one `def` and three references, **all four inside `self_test`** (`:958`, `:965`,
`:970`, plus the comment at `:949-957`). So the predicate is still written
**twice**, in two functions, and what holds them together is a **comment**:

> *"Both selectors below MUST use the same in-scope predicate as `run_check`"*
> — `:949`

That is precisely the instrument the brief's item 4 rules out (*"not a comment
asking people to remember"*), and it is what the previous wave shipped believing
it had removed. **The two copies happen to read the same text today**, which is
why nothing is red; the *mechanism* that let them diverge on 2026-08-09 is
unchanged.

Two lesser confirmations from the same read: the comment at `:949` and `:952`
names a function called **`run_check`**, and `grep -n "def run_check"` returns
nothing — the function is `run` (`:860`). And the comment's account of the
incident is accurate in every other respect.

### 1.2 The row's vector census is wrong, and the corrected figure sharpens its own argument

The row says *"only `bundle` ×10 and `manifest` ×6 carry the field, all
dict-valued"*. Counted over all 14 committed v1 vector files:

| kind | cases | cases carrying `diagnostic` | value type |
| --- | --- | --- | --- |
| `bundle` | 10 | **10** | `dict` |
| `manifest` | 6 | **6** | `dict` |
| `anchor` | 7 | **7** | `str` ×1, `null` ×6 |
| every other kind | 96 | 0 | — |

**Twenty-three cases carry the field, not sixteen.** Sixteen are dict-valued.
The seven `anchor` cases carry it in every case — six as JSON `null`, one as the
string code — which is the collision itself, and stating it as *"only bundle and
manifest carry the field"* removes the evidence from the row that reports it.
Confirmed against the executor: `vectors_anchor.rs:533` emits
`"diagnostic": verdict.diagnostic().map(|d| d.code())`, an `Option<&str>`.

### 1.3 The `#! kind` directive: real shape, real parser, and it is LENIENT exactly where a flag would go

The shape is `#! kind <name> <since>` — the manifest's own legend at
`FROZEN.sha256:35` says `kind <name> <since>`, and `testdata/vectors/README.md:383`
and `:423` say `<task>`. Thirteen lines, `:54-64`, `:71`, `:91`, matching
`KNOWN_KINDS`'s thirteen entries exactly.

The parser is `crates/antseal-core/tests/freeze_manifest/mod.rs:153-160`:

```
                "kind" => {
                    let (name, since) = split_word(rest);
                    require_nonempty(name, "kind name", &at)?;
                    require_nonempty(since, "kind introducing task", &at)?;
```

with `split_word` (`:283-288`) splitting on the **first** whitespace and
returning the whole remainder as the tail. So `since` absorbs everything after
the name. **I compiled the real parser, unmodified except for deleting the one
`sha2`-dependent helper `parse_manifest` does not call, and ran it against seven
probes:**

```
ACCEPTED  two tokens (today's shape)          kinds = ["bundle => \"F13\""]
ACCEPTED  THREE tokens (a flag appended)      kinds = ["bundle => \"F13 cbor\""]
ACCEPTED  FOUR tokens                         kinds = ["bundle => \"F13 cbor extra\""]
ACCEPTED  typo'd flag                         kinds = ["bundle => \"F13 cbro\""]
ACCEPTED  flag but NO task                    kinds = ["bundle => \"cbor\""]
REJECTED  three tokens on `status`            status must be `pre-freeze` or `frozen`, got `frozen extra`
REJECTED  three tokens on `format-version`    `format-version` given twice
```

**`kind` is the only directive arm in the vocabulary that swallows arbitrary
trailing content.** `status` rejects it by closed vocabulary,
`manifest-version` by `u64::parse`, `format-version` and `freeze-gate` by
consuming the whole remainder (so a second word makes the value wrong, and a
repeat trips `set_once`). Only `pending` is deliberately free-text, and only in
its **last** field.

Two consequences, both load-bearing:

1. **A flag can be appended without the parser rejecting it** — which sounds
   like good news and is the danger. `#! kind bundle F13 cbro` parses clean and
   `since` silently becomes `"F13 cbro"`.
2. **Nothing asserts `since` at all.** `vector_freeze_records_every_registered_kind`
   (`vector_freeze.rs:367-381`) builds `recorded` from `r.kinds.keys()` and
   compares to `KNOWN_KINDS`. The map's **values** — the `since` tokens — are
   parsed, stored, and read by no assertion in the repo. A flag pasted into that
   slot would be as unchecked as the task ids are today.

So the flag's parser work is **not** "make the parser accept a third token" —
it already does. It is "make the parser **refuse** everything that is not the
declared vocabulary", which is a strictly larger change than the row implies.

### 1.4 The decisive measurement: `FROZEN.sha256` is pinned by NOTHING, and a `#! kind` edit is not a freeze event

This is the question the brief calls load-bearing, and the answer is
unambiguous in four independent ways.

**(a) It cannot pin itself.** The vector `EntryPolicy`
(`vector_freeze.rs:72-77`) allows only `.json` suffixes, so `FROZEN.sha256`
could not be listed in its own entry block even deliberately —
`parse_entry` rejects it as *"not part of the golden-vector freeze"*.

**(b) Nothing else pins it.** `grep -rn "FROZEN"` over every `.rs`, `.sh`,
`.py`, `.yml`, `.toml` and `.json` in the tree finds it named in eleven places,
and **every one treats it as an auxiliary**: `vector_runner.rs:96` and
`wasm-bitmatch/build.rs:176` whitelist it by name and skip it (the build script
embeds `*.json` only); `docs/format/FROZEN.sha256` — the registry freeze that
*is* tag-bound under D108 §3 — does not list it and carries no `#! kind`
directives at all (its four directives are `manifest-version`,
`format-version`, `status`, `freeze-gate`).

**(c) `--update`'s frozen guard cannot see a directive.**
`scripts/vector-freeze.sh:256-260` computes `old="$(grep -v '^#' "${manifest}")"`
and requires each of *those* lines to survive. Comment and directive lines are
re-emitted verbatim by `grep '^#' "${manifest}" > "${tmp}"` (`:283`). A `#! kind`
edit is invisible to the append-only check.

**(d) It has already happened, three times, post-freeze.** `git log` on the
file: **twelve** commits, and Q14 flipped `status` to `frozen` on 2026-07-28.
After that flip: **S4** (`075cfd7`, 2026-08-01) appended `#! kind storage-address S4`;
**R12** (`5f758de`) touched it; **A22** (`f60d628`, 2026-08-09) appended
`#! kind anchor A22` plus eighteen lines of prose. The A22 diff is pure
addition — no existing digest, directive or comment line moved.

**No re-bless. No `frozen`→`pre-freeze`→`--update` dance. No tag event.** D108
§3's C1/C2/C3 machinery governs `docs/format/registry-v1.{md,json}`, a different
manifest with a different `EntryPolicy` and a published tag; it does not reach
this file. **The brief's premise that the flag "may cost a re-bless" is false,
and the ruling changes because of it.**

### 1.5 The false negative is LIVE in the frozen tree, and F31 already measured it

The brief asks me to weigh the flag against *"a hypothetical — a future kind
whose `diagnostic` is a mapping of something else"*. That is the false
**positive**, and it is indeed hypothetical. The false **negative** is not.

`testdata/vectors/v1/crypto/manifest-aead.json`, `expect.vectors[0].manifest_bytes`,
36 bytes, re-measured here through the checker's own `strict_render`:

```
a2 00 5820 6d616e696665737420626f647920627974657320287374616e642d696e29 01 a0
```

`a2` map(2) · key `00` · `5820` a byte string declaring **32** bytes over a
**30**-byte ASCII literal (`manifest body bytes (stand-in)`), so `01 a0` — the
declared second pair — is swallowed into the byte string and the map never
completes. `strict_render` refuses it: **`truncated: no head byte at offset 36`**.
The head should have been `581e`. This is CBOR-shaped, malformed, sidecar-less,
frozen, and **checked by nothing**.

F31 found this on 2026-07-28 and wrote it up in full. It is the strongest
argument for the flag that exists, it is not in Q130's row, and it is
categorically not a hypothetical.

**Honest framing, carried from F31 and re-confirmed:** this is *not* a format
defect. The manifest AEAD plaintext is opaque in v1, the vector's subject is
`k_m`/nonce/blob, and the Rust executor checks only the AEAD round-trip. It is
the *shape* F31 names, and nothing in the tree would have told anyone.

### 1.6 A structural blindness nobody has named: five kinds cannot enter scope at all

Both `run` and `self_test` read `vector.get("expect", {}).get("cases", [])`.
Measured, the `expect` envelope is **not** uniform across kinds:

| envelope | kinds |
| --- | --- |
| `expect.cases` | `anchor`, `bundle`, `content-model`, `fine-tree`, `manifest`, `report`, `sig-reject`, `storage-address` |
| `expect.vectors` | `commitments`, `hkdf-labels`, `manifest-aead`, `unit-aead` |
| named sub-objects (`ed25519`/`mldsa65`/`hybrid`) | `signatures` |

**Five of thirteen kinds have no `expect.cases` at all**, so `.get("cases", [])`
yields `[]` and they print the neutral line:

> `--  …/crypto/manifest-aead.json: kind 'manifest-aead', no diagnostic sidecar (out of scope for the CBOR cross-check)`

which is **false about the reason**. They do not lack a sidecar; they lack the
container the checker looks in. This is the same two-vocabularies-one-word
defect as the `anchor` collision, one level up — and it lands on
`manifest-aead`, the exact file §1.5 measures. **A registry flag alone does not
fix it**: a `cbor`-flagged kind using `expect.vectors` would go red as *"declares
CBOR but carries no sidecar"*, which is a misdiagnosis.

### 1.7 The self-test is non-vacuous, and its soundness has a live hole

Verified by execution. `--self-test` selects `testdata/vectors/v1/bundle/bundle.json`
case `'empty-anchor-unanchored'` (936 bytes), plants 7 vector mutations plus one
wrong RFC 8949 Appendix A expectation, catches all 8, and passes the unmutated
control. The row's figures are **correct**.

Three defects in the same function that the row does not have:

**(a) A planting failure reads as a caught fault.** `:1025-1031`:

```
    for label, fn in mutations:
        try:
            check_case(cbor2, mutated(fn))
        except CheckFailure as exc:
            report(f"  RED as required  {label}\n …")
```

`mutated(fn)` is evaluated **inside** the `try`. `reorder_a_map` raises
`CheckFailure("self-test: no multi-entry map to reorder")` when it cannot plant
its fault — and that exception is caught by the same handler and reported as
**`RED as required`**. A self-test that cannot plant a fault announces success.
This is the file's own *"decorative evidence is worse than none"* rule
(`:1035`) violated one level down.

**(b) There is no positive non-vacuity assertion.** `:961-972` uses three bare
`next(...)` calls. `StopIteration` is not a `CheckFailure`, so `main`'s handler
(`:1190`) does not see it: the process dies with a traceback and rc 1. Verified
by construction — an uncaught `StopIteration` in this shape exits 1 with
`StopIteration` as the last stderr line. **That is the 2026-08-09 CI red,
exactly.** It failed loudly by accident, not by design; a `next()` that finds
the *wrong* document fails silently.

**(c) The summary line's counts are hardcoded while the scenario count is
computed.** `:1178-1181` interpolates `{count}` (= `len(mutations) + 2` = 9) and
then states **`8 planted faults … (7 vector mutations …)`** as literals. Adding
a mutation makes the sentence lie.

### 1.8 Q130 duplicates F31, and Q54 forbids executing them separately

`tasks/F.md` **F31 — "Make 'commits format CBOR' a registry fact, so no kind
escapes the cross-check"**, open (`TODO.md:116`), M0, S, discovered by F14 on
2026-07-28. Its `Do`:

> *"`testdata/vectors/v1/FROZEN.sha256`'s `#! kind <name> <since>` directives
> (lines 54–64) are the natural home — already per-version, already
> machine-parsed, already union-checked against `KNOWN_KINDS` by
> `crates/antseal-core/tests/vector_freeze.rs:368` … Then turn
> discovery-by-marker into discovery **plus a must-exist list**: every kind
> flagged CBOR-committing must yield at least one in-scope case, and every
> in-scope case must belong to a flagged kind."*

That is Q130's *"honest fix"*, twelve days earlier, with the home, the
biconditional, the generalising precedent (`docs/testing/cross-check.md:221-229`
— *"discovery may return a superset, never a subset"*), the measured instance,
and a four-clause Accept.

`tasks/Q.md` **Q54** (open, `TODO.md:273`) extends the same slot from *"commits
CBOR"* to *"has any vehicle at all"*, and closes with a direct instruction:

> *"Land it with F31's CBOR flag rather than beside it — **two columns on one
> directive line and one parser, not two mechanisms over the same registry**."*

Q130 building a one-column flag would be the third registration of one mechanism
and would force the second directive edit Q54 exists to prevent.

---

## 2. The options, and what kills each

### (a) Q130 builds the registry flag — the row's own lean, and the brief's. Refused, on three kills.

**K1 — it is F31's, and F31 is better specified.** §1.8. Executing it under
Q130 does not close F31; it leaves F31 open over a landed mechanism, which is
how a task becomes un-closable.

**K2 — Q54 forbids the shape.** A one-column flag landed now makes Q54's column
a *second* edit to the same directive with a *second* parser change. Q54 names
this and rejects it in advance.

**K3 — it does not close Q130.** The flag is a statement about *kinds*; Q130's
measured defect is two copies of a predicate inside one Python file (§1.1). A
flag can land with the duplication fully intact — and, if the Python were taught
to read the flag, would land as a **third** parser of the directive syntax
(after `freeze_manifest::parse_manifest` and `vector_index.rs`'s `read_frozen`,
§4 R3), which is Q130's own lesson inverted.

*Not a kill, and recorded because the brief expected it to be one:* the freeze
cost. There is none (§1.4). Had there been one, K1–K3 would still stand.

### (b) `isinstance(diagnostic, dict)` is the end state and no flag is ever built — refused

This is the outcome the brief licenses if I can name the instrument that catches
the next kind. I cannot, because **no instrument over the vectors alone can
exist.** The false negative is *the absence of a sidecar*, and absence is exactly
what a checker reading only the vectors cannot distinguish from "commits no
CBOR" — the checker's own comment says so (`:895-898`) and §7 of the contract
doc says so. Closing it requires a statement no vector contains: an author's
declaration that this kind commits format CBOR. That is a registry fact, and
`crypto/manifest-aead.json` (§1.5) is what it costs to keep not having one.

### (c) Q130 builds the flag AND the Python reads `FROZEN.sha256` — refused

Two kills beyond (a)'s three. It makes the Python a third hand-written parser of
the directive vocabulary. And it couples the independent checker to the freeze
manifest's *format*, giving the cross-check a way to go red for something that
is not a disagreement about bytes — against `docs/testing/cbor-cross-check.md`
§6's independence rule. §4 R7 shows the coupling is unnecessary: the
biconditional asserted in Rust makes the Python's predicate *equal* the declared
set as a proven consequence, with no new reader.

### (d) Q130 closes the duplication; F31 lands the flag under this decision's design — **the ruling**

Each half is complete on its own, testable on its own, and neither blocks the
other. §3.

---

## 3. Ruling

**R-A. The registry flag is BUILT, and it is F31's.** Q130 does not build it,
does not part-build it, and does not add a token to `FROZEN.sha256`. Its design
is fixed by §4 R5–R9 so F31 does not re-derive it and Q54 inherits a slot it can
extend by appending.

**R-B. `isinstance(case.get("diagnostic"), dict)` stays, and it is correct.**
It is the weakest predicate under which `check_case` is defined, and the flag
does not replace it — the flag is what it is *checked against*. What was missing
was never a better predicate; it was a declaration to verify it against (F31)
and a single expression of it (Q130).

**R-C. Q130 closes on: one scope function, two callers, a self-test that sweeps
every in-scope document, computed fault counts, an explicit non-vacuity
failure, the planting-inside-the-`try` hole closed, an honest out-of-scope
message, and one Rust assertion that a second copy of the predicate cannot be
written without going red.** Not a comment.

**R-D. The row's account is amended in three places** (§1.1, §1.2, §1.6) and its
risk ordering is inverted: the live defect is the false **negative**.

---

## 4. Riders — normative, cite by number

### R1 — The single scope function (Q130)

`crosscheck_cbor.py` gains **one** module-level function, placed immediately
above `run`. It is the only expression of scope in the file.

```python
def scope_of(path: pathlib.Path) -> tuple[dict, list[dict], str]:
    """One vector document, parsed, plus the cases this checker checks.

    THE ONLY EXPRESSION OF SCOPE IN THIS FILE. `run` and `self_test` both go
    through it, because a scope rule written twice is a scope rule that will
    diverge: on 2026-08-09 it was written twice, `run` was narrowed to the
    mapping test, `self_test` kept the bare membership test, and `--self-test`
    went red against a green `--check` -- CI runs them as separate steps and
    only the second one selects.
    `crates/antseal-core/tests/cbor_crosscheck_contract.rs` asserts that the
    mapping test below occurs EXACTLY ONCE in this file, prose included.

    Returns ``(vector, cases, note)``. ``note`` is empty when ``cases`` is
    non-empty; otherwise it says WHY, in words that tell the two silences
    apart -- see docs/testing/cbor-cross-check.md section 7.
    """
    try:
        vector = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CheckFailure(f"{_rel(path)}: unreadable vector file: {exc}") from exc
    if vector.get("schema") != "antseal-golden-vector":
        raise CheckFailure(
            f"{_rel(path)}: not a golden-vector envelope (schema={vector.get('schema')!r})"
        )
    expect = vector.get("expect", {})
    if "cases" not in expect:
        return vector, [], (
            f"kind {vector['kind']!r} carries no `expect.cases` (it uses "
            f"{sorted(expect) or 'nothing'}), so this checker cannot reach its payload at "
            f"all -- which is NOT the same as committing no CBOR. See F31"
        )
    cases = [c for c in expect["cases"] if isinstance(c.get("diagnostic"), dict)]
    if not cases:
        return vector, [], (
            f"kind {vector['kind']!r}: {len(expect['cases'])} case(s), none carrying a "
            f"diagnostic sidecar (out of scope for the CBOR cross-check)"
        )
    return vector, cases, ""
```

`run`'s inline comprehension (`:905-909`), its `json.loads`/schema block
(`:868-875`) and its report line (`:910-915`) are **deleted** and replaced by:

```python
        vector, subject, note = scope_of(path)
        if not subject:
            report(f"  --  {_rel(path)}: {note}")
            continue
```

`self_test`'s local `_in_scope` (`:958-959`) is **deleted**. The comment block
at `:949-957` is deleted with it — it exists to hold two copies in step and
there is one copy.

The known-limitation comment at `:877-904` shrinks to a pointer; its essay moves
to the contract doc (R10). Its closing line becomes:

```
        # The limitation is stated in full at docs/testing/cbor-cross-check.md
        # section 7, and the scope rule and its history at section 8.1. The
        # registry-level flag that closes BOTH directions is F31's, not this
        # file's -- see docs/decisions/D112-cbor-cross-check-scope-rule.md.
```

The vacuity guard at `:928-932` is **unchanged**. It is a floor; R7 adds the
coverage statement above it and does not replace it (F31 Accept clause 2).

### R2 — The self-test sweeps every in-scope document, and says so if there are none (Q130)

`self_test`'s three `next(...)` calls (`:961-971`) are replaced by:

```python
    subjects: list[tuple[pathlib.Path, dict]] = []
    for path in discover():
        _vector, cases, _note = scope_of(path)
        if cases:
            subjects.append((path, cases[0]))
    if not subjects:
        raise CheckFailure(
            "self-test: no committed vector carries a diagnostic sidecar, so there is "
            "nothing to plant a fault in and the self-test would pass vacuously. "
            "Discovery is broken, or every CBOR-committing vector is gone"
        )
```

and the mutation loop runs **once per subject**.

*Why sweep rather than pin the subject by name.* D31 §6, restated at
`docs/testing/cbor-cross-check.md` §6, forbids it outright: *"no vector name,
case name, layer name or byte string is hard-coded"*. Sweeping honours that,
**and is strictly stronger than pinning**: it removes the sort-order dependence
that caused the 2026-08-09 incident (`anchor/` sorts before `bundle/`) rather
than working around it, and a future CBOR-committing kind is fault-planted the
day it lands instead of sitting behind whichever document happens to sort first.
Today it costs one extra document and a sub-second run.

Per subject, **before** the mutation loop, two preconditions — hoisted out of
the mutations because a `CheckFailure` raised *inside* a mutation is caught by
the loop's own handler and printed as `RED as required` (§1.7a):

```python
        byte_fields = [k for k in case if k.endswith("_bytes")]
        if len(byte_fields) != 1:
            raise CheckFailure(
                f"self-test: {_rel(path)} case {case['name']!r} has {byte_fields} "
                f"`*_bytes` field(s); exactly one is required to plant a byte-level fault"
            )
        if len(case["diagnostic"]) < 2:
            raise CheckFailure(
                f"self-test: {_rel(path)} case {case['name']!r} has a single-layer sidecar; "
                f"the `reorder a map` and `a diagnostic layer removed` mutations need at "
                f"least two layers to be faults rather than no-ops"
            )
```

### R3 — Planting moves out of the `try` (Q130)

```python
        for label, fn in mutations:
            candidate = mutated(fn)          # planting is NOT inside the try:
            try:                             # a fault we could not plant must never
                check_case(cbor2, candidate) # read as a fault the checker caught
            except CheckFailure as exc:
                report(...)
            else:
                raise CheckFailure(f"self-test FAILED: the checker accepted a vector with {label}")
```

`reorder_a_map`'s internal `raise CheckFailure("self-test: no multi-entry map to
reorder")` **stays** — after this change it is a genuine abort, which is what it
was always written to be.

### R4 — The summary line is computed (Q130)

`main`'s `--self-test` report (`:1178-1181`) becomes:

```python
            planted = count["planted"]
            report(
                f"\nself-test PASSED: {planted + count['controls']} scenarios — {planted} "
                f"planted faults caught ({count['mutations']} vector mutation(s) × "
                f"{count['subjects']} in-scope document(s) + a wrong RFC expectation), "
                f"{count['controls']} control(s) green"
            )
```

`self_test` returns the dict rather than an `int`. **No literal count survives
in that sentence.** Today's values: 7 × 2 + 1 = 15 planted, 2 controls, 17
scenarios.

### R5 — The directive syntax (F31)

```
#! kind <name> <since> <key>=<value> [<key>=<value> …]
```

Attributes are **`key=value`, never positional**. Q54's second column is then a
pure append rather than a re-layout, which is what its *"two columns on one
directive line and one parser"* requires.

The closed vocabulary at F31:

| key | values | meaning |
| --- | --- | --- |
| `cbor` | `yes` \| `no` | whether this kind's vectors commit **format CBOR** |

`vehicle` is **reserved for Q54** and must not be minted by F31.

The thirteen lines become, verbatim:

```
#! kind hkdf-labels C3 cbor=no
#! kind commitments C16 cbor=no
#! kind unit-aead C16 cbor=no
#! kind manifest-aead C16 cbor=no
#! kind signatures C16 cbor=no
#! kind sig-reject C15 cbor=no
#! kind fine-tree G15 cbor=no
#! kind content-model G21 cbor=no
#! kind report R9 cbor=no
#! kind manifest F12 cbor=yes
#! kind bundle F13 cbor=yes
#! kind storage-address S4 cbor=no
#! kind anchor A22 cbor=no
```

`manifest-aead` is **`cbor=no`**, deliberately and with its reason recorded
beside it (R9) — F31's Accept clause 3 requires exactly one recorded state. The
argument: v1 treats the manifest AEAD plaintext as **opaque**, the literal is an
ASCII stand-in in a CBOR-shaped costume, and correcting `5820`→`581e` moves the
plaintext, therefore the ciphertext, therefore a **frozen digest** — that window
closed at Q14 on 2026-07-28 and `--update` refuses it. `cbor=yes` would be a
declaration the format does not make.

**Semantics are "commits format CBOR", not "has a sidecar".** This matters: a
kind that commits CBOR and forgets its sidecar must declare `cbor=yes` and go
**red** (R7). A flag meaning "has a sidecar" would let that kind honestly
declare `no` and stay unchecked — the false negative preserved under a new name.

### R6 — The flag is MANDATORY. There is no default. (F31)

The parser arm at `freeze_manifest/mod.rs:153-160` becomes strict: after `name`
and `since`, every remaining token must be `key=value`; unknown key, duplicate
key, value outside the key's vocabulary, a bare token, and a **missing mandatory
key** are each a parse error naming the line and the legal values. Exact text:

```
{at}: `#! kind {name}` must declare every mandatory attribute; `cbor=yes|no` is missing.
      A kind whose CBOR scope is unstated is a kind the cross-check guesses about, which
      is the defect this directive exists to close (F31, D112 R6)
```
```
{at}: `#! kind {name}`: unknown attribute `{key}`. The vocabulary is: cbor=yes|no
```
```
{at}: `#! kind {name}`: attribute `cbor` must be `yes` or `no`, got `{value}`
```

**Why mandatory rather than either default, argued from what breaks.** Rank the
three by their failure mode when a new kind's author says nothing:

- *Default `yes` (in scope)* — the new kind is pulled into the CBOR checker and
  fails on the missing `*_bytes` field. **Loud, immediate, self-announcing** —
  it is the A22 incident, which cost one gate run and was fixed the same day.
- *Default `no` (out of scope)* — the new kind is silently unchecked, **for
  ever**, and the neutral out-of-scope line actively reassures the reader. That
  is `crypto/manifest-aead.json`: found by inspection, twelve days after the
  freeze, by a task written for the purpose. **Silence is worse than noise**,
  so of the two defaults `no` is the worse and `yes` the safer.
- *Mandatory* — the omission never reaches either behaviour. `vector-freeze.rs`
  fails to parse the manifest and names the missing attribute and the legal
  values. **No default, no silence, and no spurious noise against a kind that
  legitimately commits nothing.**

Mandatory dominates both. It is available only because the manifest is
unfrozen and there are thirteen lines to update (§1.4); if a future version
manifest were genuinely append-only for directives, `yes` would be the default
and this rider would say so.

### R7 — The biconditional, and where it is asserted (F31)

One new test in `crates/antseal-core/tests/vector_freeze.rs`:

```rust
#[test]
fn vector_freeze_cbor_scope_matches_the_committed_sidecars()
```

For each `#! kind` directive, over every committed vector file of that kind:

- **`cbor=yes` ⇒ at least one case whose `diagnostic` is a JSON object.** Failure:
  ```
  kind `{kind}` declares `cbor=yes` but no case in {files:?} carries an object-valued
  `diagnostic`. The CBOR cross-check selects on that field, so this kind's bytes are
  checked by NOTHING. Either the vectors owe a diagnostic sidecar (docs/testing/
  cbor-cross-check.md §3) or the directive owes `cbor=no` with its reason (D112 R9)
  ```
- **`cbor=no` ⇒ no case whose `diagnostic` is a JSON object.** Failure:
  ```
  kind `{kind}` declares `cbor=no` but case `{case}` in `{file}` carries an
  object-valued `diagnostic`, which `crosscheck_cbor.py` will treat as a CBOR
  sidecar and then fail on. Two vocabularies, one word — the A22 defect. Either
  declare `cbor=yes` or rename the field (D112 R7)
  ```
- **`cbor=yes` ⇒ the kind's vectors carry `expect.cases`.** §1.6's blindness,
  stated where it can be seen rather than misdiagnosed as a missing sidecar:
  ```
  kind `{kind}` declares `cbor=yes` but `{file}`'s `expect` carries {keys:?} and no
  `cases`. `crosscheck_cbor.py` reads `expect.cases` only, so this kind is
  unreachable to it regardless of any sidecar (D112 §1.6)
  ```

Asserted **in Rust, over the committed JSON**, not in Python — so no third
parser of the directive vocabulary is created and the independent checker gains
no coupling to the freeze manifest. **The Python needs no change for the flag at
all**: with the biconditional held, its `isinstance(…, dict)` selection *is* the
declared set, as a proven consequence rather than a guess. That is what
"declared rather than sniffed" buys, and it buys it without a new reader.

Tests-of-the-test, in `vector_freeze.rs`'s existing scratch-tree idiom, each
shown red before green: a `cbor=yes` kind with no sidecar; a `cbor=no` kind with
one; a `cbor=yes` kind whose `expect` has no `cases`; a `#! kind` line with no
`cbor=` attribute; `cbor=maybe`; `cbor=yes cbor=no`.

### R8 — Every consumer, updated in one change (F31)

The row's lesson is duplication, so the change is enumerated, not discovered.

**Readers of the directives — three parsers, one of which nobody has named:**

| # | site | reads | effect of R5/R6 |
| --- | --- | --- | --- |
| 1 | `crates/antseal-core/tests/freeze_manifest/mod.rs:153-160` | the authoritative `kind` arm | **rewritten** (R6). Shared with `format_freeze.rs`, whose manifest carries **no** `#! kind` lines (§1.4b) — verified, so the registry consumer is untouched |
| 2 | `crates/antseal-core/tests/vector_index.rs:151-172` (`read_frozen`) | a **second, hand-written** parser: `#! pending` + digest lines; every other `#` line skipped | **no code change**, and that is a finding, not an omission: it is lenient by construction and would swallow a malformed `#! kind` in silence. Gains a one-line comment naming what it deliberately does not read |
| 3 | `scripts/vector-freeze.sh:245`, `:256`, `:283` | `sed` for `status`; `grep -v '^#'` / `grep '^#'` to partition | **no change** — directives are opaque to it (§1.4c). Verified, not assumed |
| — | GNU `sha256sum -c` | all `#` lines are comments | unaffected |

**Places scope is decided:**

| site | today | after |
| --- | --- | --- |
| `crosscheck_cbor.py:905-909` (`run`) | inline comprehension | calls `scope_of` (R1) |
| `crosscheck_cbor.py:958-970` (`self_test`) | local `_in_scope` closure | **deleted**; calls `scope_of` (R1, R2) |
| `vectors_bundle.rs:558-560`, `vectors_manifest.rs` | per-kind executors requiring `diagnostic` | unchanged — a per-kind executor is not a predicate |
| `vector_freeze.rs` | — | **new**: R7's biconditional |

**Fixtures that break on R6 and are easy to miss:** `vector_freeze.rs:462-472`'s
`MANIFEST_HEADER` carries seven `#! kind` lines with no attribute. Under R6 the
scratch tree fails to parse and **all 19 `vector_freeze` tests break**. It is in
the edit set.

**Prose stating the two-token shape:** `FROZEN.sha256:35` (the legend),
`testdata/vectors/README.md:239`, `:333`, `:383`, `:423`. All five move in the
same commit.

### R9 — `manifest-aead`'s reason is recorded at the directive (F31)

`FROZEN.sha256` gains a short paragraph above the `#! kind` block, in the idiom
of its existing S4 and A22 notes, stating: `manifest-aead`'s `manifest_bytes` is
a CBOR-*shaped* ASCII stand-in that is **not well-formed** (`5820` over a
30-byte literal; `581e` was meant), it is `cbor=no` because v1 treats the
manifest AEAD plaintext as opaque, and correcting it would move a frozen digest
— a window Q14 closed on 2026-07-28. Not a format defect; a permanent recorded
artifact.

### R10 — The contract document (Q130)

`docs/testing/cbor-cross-check.md` §7's first bullet is replaced by:

```markdown
- **A kind that commits format CBOR without a sidecar is silently out of
  scope, and one such kind is committed today.** Scope is "the case carries an
  object-valued `diagnostic`", which is what makes the checker generic over
  vectors that have not been written yet — but the *absence* of a sidecar
  reads identically to "this kind commits no CBOR". The measured instance is
  `testdata/vectors/v1/crypto/manifest-aead.json`, whose `manifest_bytes` is
  CBOR-shaped, **not well-formed** (`5820` declares 32 bytes over a 30-byte
  literal) and checked by nothing. Closing this needs a registry-level flag on
  the kind, which is **F31**'s and not this checker's — see
  `docs/decisions/D112-cbor-cross-check-scope-rule.md`.
- **Five kinds cannot enter scope at all, whatever they commit.** Scope is
  read from `expect.cases`, and `commitments`, `hkdf-labels`, `manifest-aead`
  and `unit-aead` carry `expect.vectors` while `signatures` carries named
  sub-objects. The checker now says which of the two silences it means; making
  those kinds *reachable* is F31's.
```

§8.1's title and closing paragraph are replaced by:

```markdown
### 8.1 Scope is decided in exactly one place, and checked against nothing yet

A vector enters the CBOR cross-check when its `expect.cases[]` carry an
object-valued `diagnostic` — a mapping from layer name to that layer's
rendering. There is no kind allow-list, which is deliberate: a future
CBOR-committing kind is covered the day it lands, provided it commits a
sidecar.

That inference has failed in both directions, and the **false negative is the
live one** (§7). The false positive was found by the gate on 2026-08-09, when
A22 landed: the `anchor` kind commits no CBOR, but its cases carry a field also
called `diagnostic` — `AnchorDiagnostic` as a code string or `null` (D101 §3.5),
not a layer mapping — so every anchor case was pulled into scope and failed for
having no `*_bytes` field. Two vocabularies, one word. The repair narrowed the
test from `"diagnostic" in case` to `isinstance(case.get("diagnostic"), dict)`,
the weakest predicate under which `check_case` is defined at all.

**The sharper lesson is where the rule lived, not what it said.** It lived in
two functions. `run` was narrowed and `self_test` was not, so `--self-test`
selected `anchor/anchor.json` — which sorts before `bundle/` — and died on
`StopIteration`, red against a green `--check`, because CI runs them as
separate steps and only the second one selects. It is now written **once**, in
`scope_of`, which both callers use, and
`crates/antseal-core/tests/cbor_crosscheck_contract.rs::the_cbor_scope_predicate_is_written_exactly_once`
fails if a second copy is ever written. The self-test no longer selects a
sample: it sweeps **every** in-scope document, so its selection is the check's
selection in full rather than the first element of it.

The declaration this predicate should be checked against is **F31**'s
registry-level flag on the kind. Its design is fixed by
`docs/decisions/D112-cbor-cross-check-scope-rule.md`.
```

Both edits keep every path token `cbor_crosscheck_contract.rs::the_five_copies_cross_reference_each_other`
requires, and touch no rendering-table row.

### R11 — Ordering

Q130's edits are independent of F31's and may land in either order or the same
wave. If both land in one wave, **Q130 first**: R7's failure text cites §8.1's
new wording, and F31's `MANIFEST_HEADER` change (R8) is the larger blast radius.

---

## 5. Edit set

**Q130 (this row):**

| file | change | rider |
| --- | --- | --- |
| `testdata/vectors/v1/crosscheck_cbor.py` | `scope_of` added; `run`'s inline predicate and `self_test`'s `_in_scope` deleted; `self_test` sweeps all subjects with preconditions hoisted; planting moved out of the `try`; summary computed; `:877-904` shrunk to a pointer | R1–R4 |
| `crates/antseal-core/tests/cbor_crosscheck_contract.rs` | `the_cbor_scope_predicate_is_written_exactly_once` | §6.1 |
| `docs/testing/cbor-cross-check.md` | §7 bullet 1 → two bullets; §8.1 retitled and rewritten | R10 |

**F31 (not this row — its design, fixed here):**

| file | change | rider |
| --- | --- | --- |
| `testdata/vectors/v1/FROZEN.sha256` | 13 `#! kind` lines gain `cbor=yes\|no`; legend at `:35` updated; `manifest-aead` paragraph | R5, R9 |
| `crates/antseal-core/tests/freeze_manifest/mod.rs` | strict `kind` attribute parser | R6 |
| `crates/antseal-core/tests/vector_freeze.rs` | `MANIFEST_HEADER` fixture; `vector_freeze_cbor_scope_matches_the_committed_sidecars` + 6 tests-of-the-test | R7, R8 |
| `crates/antseal-core/tests/vector_index.rs` | one comment naming what `read_frozen` does not read | R8 |
| `testdata/vectors/README.md` | `:239`, `:333`, `:383`, `:423` | R8 |

**Not touched by either:** any `*.json` vector, any digest line, `INDEX.json`,
`scripts/vector-freeze.sh`, `scripts/cross-check.sh`, CI. **Zero frozen bytes
move** — the manifest's own bytes are not frozen (§1.4) and no listed file is
edited.

---

## 6. Instruments

### 6.1 The one that makes divergence impossible, then loud

Two layers, because the brief asks for impossibility *or* a loud failure and
both are available.

**Impossible by construction:** after R1 there is one function and two callers.
There is no second predicate to diverge from. After R2 the two halves do not
merely apply the same rule — `--self-test` sweeps the whole set `--check`
sweeps, so "the half that selects is not the half that checks" stops being a
true sentence about this file.

**Loud if reintroduced**, in `cbor_crosscheck_contract.rs` — the file that
already scrapes this Python source for `MAX_JSON_SAFE_INT` and already bans the
literal `cbor2.dumps` *"outright, prose included — paraphrase it if you need to
discuss it"*. Same technique, same precedent, one line:

```rust
/// Scope is decided in exactly ONE place in the Python checker.
///
/// It was decided in two on 2026-08-09: `run` was narrowed to the mapping test
/// and `self_test`'s copy was not, so `--self-test` went red against a green
/// `--check` — CI runs them as separate steps and only the second one selects.
/// The repair routed both through `scope_of`; this is what stops a third
/// expression being written. A literal count, deliberately: it replaces a
/// comment asking the next author to remember, which is what was there.
///
/// The literal is banned in prose too — paraphrase it if you need to discuss
/// it, exactly as `the_cbor2_pin_is_exact_and_dev_tool_only` bans `dumps`.
#[test]
fn the_cbor_scope_predicate_is_written_exactly_once() {
    const PREDICATE: &str = "isinstance(c.get(\"diagnostic\"), dict)";
    let source = read("testdata/vectors/v1/crosscheck_cbor.py");
    let found = source.matches(PREDICATE).count();
    assert_eq!(
        found, 1,
        "testdata/vectors/v1/crosscheck_cbor.py contains {found} copies of the CBOR scope \
         predicate `{PREDICATE}`; there must be exactly ONE, inside `scope_of`, which `run` \
         and `self_test` both call. A scope rule written twice is a scope rule that will \
         diverge — it did on 2026-08-09, and only CI saw it because `--check` and \
         `--self-test` are separate steps and only the second one selects \
         (docs/testing/cbor-cross-check.md §8.1, D112 R1)"
    );
}
```

Shown red two ways before it is trusted: with the predicate deleted (0 found)
and with a second copy pasted into `self_test` (2 found).

### 6.2 Non-vacuity, positively asserted

R2's `if not subjects: raise CheckFailure(…)`. Today it is exercised by 2
subjects, 15 planted faults and 2 controls, all named in the computed summary.
The `StopIteration` path is gone: every self-test abort is now a `CheckFailure`
that reaches `main`'s handler and prints `CROSS-CHECK FAILED` with a diagnosis
instead of a traceback.

### 6.3 What was run, and what it printed

| command | verdict |
| --- | --- |
| `python3 testdata/vectors/v1/crosscheck_cbor.py --help` | rc 0 — flags `--check --setup --self-test --require --home` |
| `./scripts/cross-check.sh --check` | **rc 0** — `cross-check PASSED: 256 checks over 16 case(s) in 2 CBOR-committing vector(s) of 14 committed v1 vector file(s)`; 12 files print the neutral out-of-scope line, `anchor/anchor.json` among them |
| `./scripts/cross-check.sh --self-test` | **rc 0** — `self-test PASSED: every surface was observed failing on a planted fault` |
| `python3 testdata/vectors/v1/crosscheck_cbor.py --self-test` | **rc 0** — subject `bundle/bundle.json` case `'empty-anchor-unanchored'` (936 bytes); `9 scenarios — 8 planted faults caught (7 vector mutations + a wrong RFC expectation), 1 control green` |
| `cargo test -p antseal-core --test vector_freeze` | **rc 0** — 19 passed |
| `rustc` on the real `freeze_manifest` parser, 7 directive probes | §1.3's table — `#! kind` accepts three, four and typo'd tokens; `status` and `format-version` reject theirs |
| `python3` census over all 14 committed vectors | §1.2's and §1.6's tables |
| `strict_render` over `manifest-aead`'s `manifest_bytes` | `truncated: no head byte at offset 36` |
| `git log --since=2026-07-28 -- testdata/vectors/v1/FROZEN.sha256` | 3 post-freeze commits; A22's diff is pure addition |

---

## 7. What this does not do

- **It does not correct `crypto/manifest-aead.json`.** `5820`→`581e` moves the
  AEAD plaintext, therefore the ciphertext, therefore a frozen digest. That
  window closed at Q14 on 2026-07-28 and F31's own Notes say so. R9 records it;
  nothing reopens it.
- **It does not touch `signatures`, `commitments`, `unit-aead` or
  `hkdf-labels`'s envelopes.** §1.6 measures the blindness and R1 makes the
  checker *say* which silence it means; making those kinds reachable is F31's
  R7 third clause, and only for a kind that declares `cbor=yes`.
- **It does not mint `vehicle`.** That is Q54's column in R5's slot.
- **It does not change `KNOWN_KINDS`, any executor, or any `*.json` vector.**
- **It does not rule on Q54's or F31's sequencing against the M2 gate.** Both
  are M0-milestone rows and neither blocks M2; when they run is the
  orchestrator's.

---

## 8. Discovered work — described, not numbered

1. **`self_test` plants its faults inside the `try` that judges them**
   (§1.7a), so a mutation that *cannot* be planted is reported as
   `RED as required`. Live today and reachable — `reorder_a_map` raises
   `CheckFailure` on a sidecar with no multi-entry map. **Folded into Q130 as
   R3**, because it is in the function Q130 is already rewriting; recorded here
   because it is a distinct defect with a distinct failure mode.
2. **`vector_index.rs`'s `read_frozen` is an undeclared second parser of
   `FROZEN.sha256`.** It reads `#! pending` and digest lines and skips every
   other `#` line in silence, so a malformed directive is invisible to it while
   the authoritative parser rejects it. Harmless today; it means "the manifest
   is parsed once" is false, and a future directive change must remember it.
   R8 gives it a comment. A row asserting the two readers agree on the digest
   set would be cheap and is not proposed here.
3. **Five kinds' `expect` envelopes are unreachable to the CBOR checker**
   (§1.6). R1 makes the message honest and R7 makes it red for a `cbor=yes`
   kind; making `expect.vectors` kinds genuinely checkable is unowned by any
   row I can find.
4. **`#! kind`'s `since` token is asserted by nothing.**
   `vector_freeze_records_every_registered_kind` compares only the map's keys
   (§1.3). Thirteen task ids are parsed, stored, and checked against no task
   list. `INDEX.json` carries a `task` per *vector* and nothing compares the
   two.
5. **`scripts/local-gate.sh` runs `cross-check.sh --check` and not
   `--self-test`** (`:313`). The 2026-08-09 incident was green under `--check`
   and red only under `--self-test`, so **the local gate structurally could not
   have caught it** — only CI, which runs both as separate steps
   (`ci.yml:382-385`). This is Q125's exact shape ("the gate compiles for
   wasm32 but never runs the wasm32 tests") in a second lane, and the gate's
   `cross-check` line does not say that its half is the half that does not
   select. The self-test costs ~4 s locally.
6. **`crosscheck_cbor.py`'s comments name a function `run_check` that does not
   exist** (`:949`, `:952`; the function is `run`). Swept up by R1's deletion of
   that block; worth noting only because the same wrong name reached
   `TODO.md:560`.

---

## 9. `tasks/Q.md` entry for Q130 — lift verbatim

Q130 has **no** `tasks/Q.md` entry; the file runs Q129 → Q131. That absence is
itself an instance of Q85, and it made `TODO.md:560` the only authoritative
statement of the task — which is how three of its claims went unchallenged for a
wave. The block below is written in the idiom of `### Q129` and `### Q131` and
is the orchestrator's to insert between them.

```markdown
### Q130 — The CBOR cross-check's scope rule is written twice, and checked against nothing
- Milestone: M2
- Size: S
- Deps: after A22; F31 owns the registry flag (D112 R-A); Q54 extends the same directive
- Discovered by: **the wave-10 gate run** (2026-08-09); scoped by **D112** (2026-08-10).
- Problem: `testdata/vectors/v1/crosscheck_cbor.py` decides a vector's scope by sniffing a field name, and A22 proved the rule wrong in both directions. It took "in scope" to mean `"diagnostic" in case`; the `anchor` kind commits no CBOR but names a field `diagnostic` for something else entirely — `AnchorDiagnostic` as a code string or `null` (D101 §3.5), 7 cases, 6 of them `null` — so every anchor case was pulled in and failed for having no `*_bytes` field. **Only the full gate caught it**: A22's lane verified `cross-check.sh`'s *generator* half and never reached this checker, which is `.py` and reads the committed documents rather than the Rust. Narrowed 2026-08-09 to `isinstance(diagnostic, dict)`, the weakest predicate under which `check_case` is defined. **The predicate lived in TWO places and the first repair fixed one, which CI caught within the hour**: `self_test` selects a document *and* a case by the same rule, and once `run` was narrowed the bare form there kept selecting `anchor/anchor.json` — which sorts before `bundle/` — and died on `StopIteration`. **Green `--check`, red `--self-test`, because CI runs them as separate steps and only the second one selects.** **The duplication is still live**: `_in_scope` is a closure *inside* `self_test` (`:958-959`), `run` carries its own inline copy (`:905-909`), and what holds them in step is a comment (`:949`). Two further defects in the same function: `self_test` plants each fault **inside** the `try` that judges it, so a mutation it cannot plant is reported as `RED as required`; and it has no positive non-vacuity assertion — three bare `next(...)` calls whose `StopIteration` is not a `CheckFailure` and never reaches `main`'s handler.
- Do: per **D112 R1–R4, R10**. One module-level `scope_of(path)` — the only expression of scope in the file — called by both `run` and `self_test`; delete `_in_scope` and `run`'s inline comprehension. `self_test` sweeps **every** in-scope document rather than the first (D31 §6 forbids hard-coding a vector or case name, and sweeping removes the sort-order dependence that caused the incident rather than working around it), with the `*_bytes` and ≥2-layer preconditions hoisted **out** of the mutation loop, planting moved out of the `try`, and the summary's fault counts computed instead of hardcoded. Make the out-of-scope message distinguish "no `expect.cases` container" from "cases without a sidecar" — five of thirteen kinds carry `expect.vectors` or named sub-objects and today all print the same false reason. Add `the_cbor_scope_predicate_is_written_exactly_once` to `cbor_crosscheck_contract.rs`, in the idiom that file already uses to ban `cbor2.dumps` prose included. Rewrite `docs/testing/cbor-cross-check.md` §7 bullet 1 and §8.1, routing the registry flag to **F31**.
- Accept:
  - The scope predicate occurs **exactly once** in `crosscheck_cbor.py`, prose included, and a second copy turns a named test red — shown red both ways (deleted, and duplicated).
  - `--self-test` selects the same set `--check` checks, not a sample of it, and raises a diagnosing `CheckFailure` — never `StopIteration` — when that set is empty.
  - A mutation that cannot be planted aborts the self-test; it can no longer be reported as a fault the checker caught.
  - Every count in the self-test's summary is computed from the run.
  - `docs/testing/cbor-cross-check.md` names **F31** as the flag's owner and no longer says "Tracked as Q130".
- Notes: **The registry flag is NOT this row's** — D112 R-A. **F31** has owned it since 2026-07-28 with a fuller `Do` (the `#! kind` home, the must-exist biconditional, `docs/testing/cross-check.md:221-229`'s *"discovery may return a superset, never a subset"*) and a **measured** instance this row lacks: `crypto/manifest-aead.json`'s `manifest_bytes` is CBOR-shaped, **not well-formed** (`5820` declares 32 bytes over a 30-byte literal; `581e` was meant), sidecar-less, frozen, and checked by nothing — so the false **negative** is the live defect and the false positive is the hypothetical, which is the reverse of the ordering `TODO.md:560` gives. **Q54** then forbids building it here: *"two columns on one directive line and one parser, not two mechanisms over the same registry."* **The freeze cost is zero and was the brief's central worry** — `FROZEN.sha256`'s own bytes are pinned by nothing (its `EntryPolicy` admits `.json` only, so it cannot list itself; `wasm-bitmatch/build.rs` and `vector_runner.rs` classify it as an auxiliary), `vector-freeze.sh`'s frozen guard iterates `grep -v '^#'` and cannot see a directive, and the `#! kind` block has been appended to **three times post-freeze** (S4, R12, A22). Also corrected: `TODO.md:560`'s *"only `bundle` ×10 and `manifest` ×6 carry the field"* — 23 cases carry it, 16 dict-valued, the other 7 being `anchor`'s; and its *"Both now share one `_in_scope` helper"*, which is the claim this row exists to make true.
```

---

## Outcome

**RESOLVED, 2026-08-10.** The row is right that a registry-level flag on the
kind is the honest fix, and wrong about whose it is, about what it defends
against, and about what the previous wave landed. **The flag is F31's** — open
since 2026-07-28, with the same home, a stronger `Do`, and a *measured* instance
Q130 does not have — and **Q54 forbids landing it separately** in the sentence
*"two columns on one directive line and one parser, not two mechanisms over the
same registry."* **The freeze cost the brief called load-bearing does not
exist**: `FROZEN.sha256` is pinned by nothing, cannot pin itself, is invisible
to `--update`'s append-only guard, and has been appended to three times since
Q14 froze it. **And the hypothetical is the wrong one**: the false positive is
hypothetical, the false negative is `crypto/manifest-aead.json`, CBOR-shaped and
malformed at `5820`-over-30-bytes, sitting inside the freeze, checked by
nothing. **Q130's own subject is the duplication, and it is still live** — the
row says *"Both now share one `_in_scope` helper"*, and `_in_scope` is a closure
inside `self_test` while `run` carries its own inline copy, held together by a
comment. That closes on one `scope_of` with two callers, a self-test that
sweeps every in-scope document instead of the first (which removes the
sort-order dependence rather than working around it, and honours D31 §6's ban on
hard-coded vector names), and one Rust assertion in the file that already scrapes
this Python source. Three further defects found on the way: the self-test plants
faults **inside** the `try` that judges them, so an unplantable fault reads as a
caught one; it has no positive non-vacuity assertion, so the 2026-08-09 red was
a `StopIteration` traceback rather than a diagnosis; and five of thirteen kinds
carry no `expect.cases` at all, so the checker's neutral out-of-scope line is
false about its reason for a third of the tree. **Zero frozen bytes move.**

---

## Index row (orchestrator applies at merge)

| [D112](D112-cbor-cross-check-scope-rule.md) | Q130 — how the CBOR cross-check decides scope — **the registry flag is the right answer, is built, and is NOT Q130's.** It has an owner with a better specification and a *measured* instance: **F31**, open since 2026-07-28, whose `Do` already names `FROZEN.sha256`'s `#! kind` directives as the home and already specifies the must-exist biconditional; **Q54** then binds them — *"two columns on one directive line and one parser, not two mechanisms over the same registry"* — so a one-column flag here forces the second directive edit Q54 exists to forbid. **The brief's decisive question is answered against its own premise, twice.** There is **no freeze event**: `testdata/vectors/v1/FROZEN.sha256`'s bytes are pinned by nothing (its `EntryPolicy` admits `.json` only, so it cannot list itself; `wasm-bitmatch/build.rs` and `vector_runner.rs` classify it as an auxiliary; `docs/format/FROZEN.sha256`, the tag-bound one under D108 §3, does not list it and carries no `#! kind` lines), `vector-freeze.sh`'s frozen guard iterates `grep -v '^#'` and cannot see a directive line, and the `#! kind` block has been appended to **three times post-freeze** — S4, R12, A22, the last a pure addition. And the threat is **not hypothetical**: the false *positive* is, but the false *negative* is `crypto/manifest-aead.json`, whose `manifest_bytes` is CBOR-shaped and **not well-formed** (`5820` declares 32 bytes over a 30-byte ASCII stand-in; `581e` was meant) — `strict_render` says `truncated: no head byte at offset 36` — sidecar-less, frozen, checked by nothing, and measured by F31 twelve days before Q130 was written. The row has the two directions the wrong way round. **Q130's own subject is the duplication, and it is still live**: the row claims *"Both now share one `_in_scope` helper"*, and `_in_scope` is a **closure inside `self_test`** while `run` carries its own inline copy, held in step by a comment — the exact instrument the brief rules out. It closes on **one `scope_of`, two callers**, a self-test that sweeps **every** in-scope document rather than the first (which dissolves the sort-order dependence that caused the incident, and honours D31 §6's ban on hard-coding a vector or case name), computed fault counts, an explicit non-vacuity `CheckFailure`, and `the_cbor_scope_predicate_is_written_exactly_once` in the file that already bans `cbor2.dumps` *"prose included"*. Three defects found on the way, none in the row: **the self-test plants each fault inside the `try` that judges it**, so `reorder_a_map`'s own abort prints as `RED as required`; there is **no positive non-vacuity assertion** — three bare `next(...)` whose `StopIteration` never reaches `main`'s handler, which is why the 2026-08-09 red was a traceback; and **five of thirteen kinds carry no `expect.cases`** (`commitments`, `hkdf-labels`, `manifest-aead`, `unit-aead` use `expect.vectors`; `signatures` uses named sub-objects), so the neutral out-of-scope line is **false about its reason** for a third of the tree. The flag's design is fixed here for F31 — `key=value` attributes so Q54's column is an append, `cbor=yes\|no` **mandatory with no default** (mandatory dominates both defaults: a silent `yes` is the loud A22 incident, a silent `no` is `manifest-aead` for ever), semantics *"commits format CBOR"* not *"has a sidecar"*, the biconditional asserted **in Rust** so the Python gains no third parser of the directive vocabulary and no coupling to the freeze manifest. Also corrected: the row's census (**23** cases carry `diagnostic`, 16 dict-valued, 7 being `anchor`'s — not *"only bundle ×10 and manifest ×6"*), and `#! kind` is measured to be **the only directive arm that swallows arbitrary trailing content** — `#! kind bundle F13 cbro` parses clean, and `since` is asserted by nothing. **Zero frozen bytes move.** | RESOLVED (Q130 executes; F31 inherits R5–R9) | 2026-08-10 |

---

## Amendments — found by the implementing lane, 2026-08-10

The RULING and R1–R4 survive unchanged, and §9's census was verified true
against the tree as built (`:958-959` / `:905-909` / `:949`; seven `anchor`
cases, six `null`; `bundle` 10/10 dict, `manifest` 6/6 dict, `anchor` 7/7
non-dict, every other kind 0). What follows corrects scope and pointers.

**A1 — R10's scope instruction understates what its own block replaces.** R10
says *"§8.1's title and closing paragraph are replaced by:"*, but the block that
follows is a **full-section rewrite** — title plus four paragraphs, covering the
bullet list and the repair narrative. Applied literally it is impossible. The
block was applied as the section body and the pre-existing final paragraph
**kept**, since R10 offers no counterpart and this document nowhere overturns
it: *"Worth recording *how* this was found, because no lane-local check could
have: A22's lane verified `scripts/cross-check.sh`'s generator half and never
reached this checker…"*. Dropping it would have deleted a measured finding.

**A2 — §5's edit set is incomplete for R4.** R4 makes the self-test summary
computed (8 → 15 planted faults, 1 → 2 controls, 9 → 17 scenarios), and **four
prose sites state the old count**, none of them listed — §5 in fact says
`scripts/cross-check.sh` is *"not touched by either"*: `scripts/cross-check.sh:393`,
`CONTRIBUTING.md:66`, `docs/ci-verification.md:1001`, and
`docs/testing/cross-check.md:163`. All four are outside Q130's file scope and
none is machine-asserted (`cross-check.sh` reads only the exit code), so they
were correctly left alone and are registered as their own row at this wave's
bookkeeping. `scripts/cross-check.sh:393` is the one that misleads a reader of
the lane itself.

**A3 — the `MANIFEST_HEADER` warning is at §4 R8 (`:717-720`), not §3**, and it
is scoped to **F31's R6**, not to Q130. The implementing brief mislocated it;
the error was the orchestrator's, not this document's. Confirmed by execution:
Q130 touches `crates/antseal-core/tests/vector_freeze.rs` not at all,
`MANIFEST_HEADER` remains attribute-less, and `--test vector_freeze` is 19
passed — the same 19 §6.3 recorded. That fixture breaks under R6's mandatory
`cbor=yes|no` parser, which Q130 does not add.

**A4 — R3's comment layout is unreadable as given.** It presents its rationale
as three trailing fragments forming one sentence across `candidate = …`, `try:`
and `check_case(…)`; at the real indentation the fragments do not align. Same
code, rationale moved to a block comment immediately above
`candidate = mutated(fn)`, naming `reorder_a_map` as the live instance.

**A5 — §9's entry text, one missing word before it is pasted into `tasks/Q.md`.**
The `Do` bullet reads *"…in the idiom that file already uses to ban
`cbor2.dumps` prose included."* Read and paste it as *"…to ban `cbor2.dumps`,
prose included."*

**Confirmed by execution, against HEAD.** §1.7b's two live self-test defects
both reproduced at `5fbc48d` and are closed: an unplantable mutation printed
*"RED as required"* and the run announced **`self-test PASSED: 9 scenarios — 8
planted faults caught`, rc 0** — it now aborts with *"no multi-entry map to
reorder"*, rc 1; and an empty selection raised a bare `StopIteration` traceback
past `main`'s handler — it now raises a diagnosing `CheckFailure`. The scope
predicate is asserted exactly once **prose included**, seen red at 0 copies, at
2 in code, and at 2 in a comment.
