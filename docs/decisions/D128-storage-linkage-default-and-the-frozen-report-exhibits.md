# D128 — R20: what `verify_bundle`'s default is, and how the frozen report exhibits survive it

- **Status: RESOLVED — `verify_bundle`'s default RUNS the storage-linkage
  layer, and the committed report exhibits are pinned to an *explicitly
  suppressed* options value through the two executors that already construct
  their own options. Zero frozen bytes move, zero `REPORT_DIGEST_BY_SHAPE`
  rows move, no freeze event of any class occurs, and neither the FIXTURE
  EVENT nor a fourth freeze class is needed.** The enumeration the R20 lane
  supplied treats *the default* and *what the committed exhibits pin* as one
  knob. They are two, and measurement says so: the 21 report cases and the 26
  R30 rows are produced by two executors that **build their own
  `VerifyOptions` value** (`vectors_report.rs:491`, `bundle_fixtures.rs:1991`)
  — they are not observers of an ambient default, and nothing but habit binds
  them to `VerifyOptions::new()`. Pin the exhibits to a stated options tuple
  and the default is free to be what the spec mandates. Arm **(a) FIXTURE
  EVENT** is refused on a measured blast radius of 3 of 14 frozen files, 37 of
  their 47 cases, all 26 R30 rows and a content locator in `verify_fuzz.rs`
  that loses two of its three markers — for a *negative* payoff, since it
  would delete the only committed evidence that a bundle with no valid linkage
  still verifies. Arm **(b) a fourth freeze class** is refused **and is
  mis-aimed**: the class D105 §10 declined to design is *adding a case to a
  frozen report document* (§5.1 Route A, case count 21 → 22), and this change
  adds no case — designing that class would not admit it. Arm **(c) opt-in
  permanently** is refused in its literal form (the layer is not optional) and
  its *mechanism* survives inverted: the switch stays, pointing the other way,
  with a closed two-entry caller list.
- **Date: 2026-08-12** (wave 18, Act 2b; briefed to find the shape the
  enumeration misses before settling for one in it. It exists, it is
  cheaper than every arm enumerated, and it makes the frozen exhibits
  *more* self-describing rather than less.)
- **Owning tasks: R20** (implements §3; its `Do`'s *"report-slot populated"*
  becomes satisfiable), **R21** (must not expose suppression to its callers;
  gains an Accept row), **R22** (same, and it is the reason the default cannot
  be off — its `Do` gives the page no options parameter), **U30**/**R23**
  (consumers), **R27** (the parity gate that would witness a divergence).
  Consumed by **R9**/**R30** (their executors gain the explicit tuple).
- **Amends**: `tasks/R.md` R20 `Do` + `Notes`, R21 and R22 `Accept`
  (quoted in §9; the registrar's to apply), and the `with_storage_linkage`
  rustdoc at `crates/antseal-core/src/verify/pipeline.rs:305-339` (§8 edit 1).
  **Supersedes**: nothing. **Corrects**: that rustdoc's closing sentence —
  *"The two ways out are a FIXTURE EVENT … or a fourth freeze class"* — which
  enumerates two exits where there are three, and takes neither of the two.
  Nothing in a *resolved record* is corrected; D105 §10 is not reopened, it is
  measured as answering a different question (§2.2).

---

## 1. What was measured

### 1.1 R20's three numbers, re-derived statically rather than re-run

The brief forbids flipping the default, so the lane's `moved cases: 21 of 21`
was **not** reproduced. It is re-derived from three readings, and each is
independently sufficient:

**(i) All 21 committed cases carry the same slot value.** Read off the frozen
file, not off a rerun:

```
$ python3 -c '...json.load(...); print(sorted({json.dumps(x["report"]["storage_linkage"]) for x in cases}))'
n cases: 21
storage_linkage values: ['"not-evaluated"']
report_version values: [1]
```

**(ii) The option has exactly one effect.** `options.storage_linkage()` is
read at exactly one site in the whole crate —
`verify/pipeline.rs:1176`, inside `storage_linkage_layer`, whose return value
is bound at `pipeline.rs:582` and reaches nothing else:

```
$ rg -n "options.storage_linkage\(\)|storage_linkage_layer" crates/antseal-core/src/verify/pipeline.rs
582:    let storage_linkage = storage_linkage_layer(bundle, rows.rows(), options);
1171:fn storage_linkage_layer(
1176:    if !options.storage_linkage() {
```

So *"report fields that differ: `['storage_linkage']`"* is a structural fact,
not a measurement that could have come out otherwise. `report_version` is a
`const` nobody touches, and the fixtures are unchanged, so *"report_version
moved: 0"* and *"input digests moved: 0"* are likewise structural.

**(iii) Under the fixtures the exhibits use, the layer's answer is a total
failure.** `StorageAddresses::Placeholder` records `fixture_address(unit_id)` =
`0xAD…` per unit (`bundle_fixtures.rs:741-745`) and a `{0x5E…, 0x5A…, 0x5C…}`
storage record (`:1188-1193`). Neither is BLAKE3 of anything, so every unit
mismatches and the manifest half cannot match either. R20's own bundle-level
test asserts exactly this value and is the reason the arithmetic needs no
rerun (`crates/antseal-core/tests/storage_linkage.rs:180-192`):

```
Evaluated { units_matched: 0, units_mismatched: units, manifest_matched: false }
```

**Therefore**: flipping `VerifyOptions::new()` would rewrite all 21 cases to
say *this bundle links to nothing* — 21 identical, permanent, fixture-only
failures. That is not merely expensive to land; it is **worse content** than
what is there now, because `not-evaluated` "says nothing in either direction"
(`report.rs:371-374`) while the replacement asserts something false about the
product and true only about M0 placeholders.

### 1.2 The freeze refusal, read off the script rather than triggered

`scripts/vector-freeze.sh`'s `verdict_event_ok` runs six checks in order
(`:119-156`). For this change: the path is `report/` (pass), the case count is
21 → 21 (pass), `bundle_len`/`bundle_sha256`/`revealed_unit_ids` are unmoved on
every case (pass — the inputs did not change), `report_version` is unmoved
(pass), `moved` is non-empty (pass), and then `:151-153`:

```python
if len(moved) == len(a):
    fail(f"all {len(a)} cases moved. A format event moves every case at once (R32 "
         "measured exactly that at report_version 0 -> 1); a verdict event does not")
```

The `--update` branch consults `verdict_event_ok` **before** printing its own
refusal (`:336-340`), so the observed output is both messages in that order —
which is what the R20 lane reported. The refusal is on the **last** check,
not the first: every substantive property of a verdict event holds, and only
the cardinality heuristic refuses.

**The tree is byte-clean today**, so the lane's backup-and-restore was
complete. Layer 1, run read-only here:

```
$ cd testdata/vectors/v1 && grep -v '^#' FROZEN.sha256 | sha256sum -c -
anchor/anchor.json: OK          bundle/bundle.json: OK
content-model/content-model.json: OK   crypto/commitments.json: OK
crypto/manifest-aead.json: OK   crypto/signatures.json: OK
crypto/unit-aead.json: OK       fine-tree/fine-tree.json: OK
hkdf/hkdf-labels.json: OK       manifest/manifest.json: OK
report/verification-reports.json: OK   sig-reject/ed25519.json: OK
sig-reject/ml-dsa-65.json: OK   storage/storage-address.json: OK
```

14 of 14. `PIPESTATUS[0]` = 0.

### 1.3 **The finding the enumeration missed: the exhibits construct their own options**

Neither committed report exhibit *observes* a default. Both **build** a
`VerifyOptions` value and hand it to `verify_bundle`:

- `crates/antseal-core/src/test_util/vectors_report.rs:491`, inside
  `build_expect` — the function that produces all 21 cases' `report`,
  `report_json` and `report_len`;
- `crates/antseal-core/src/test_util/bundle_fixtures.rs:1991-1992`, the
  `verify()` helper the 26-row `REPORT_DIGEST_BY_SHAPE` family and its
  `emit_r30_report_digest_table` regenerator both go through.

Two call sites. Changing what they pass changes **no byte of any artifact**,
because the value they currently pass and the value they would pass are the
same value; only its spelling becomes explicit. This is the whole of §3.

### 1.4 The report kind declares no verification input — and a sibling kind does

Measured on the frozen documents themselves:

```
report/verification-reports.json   inputs keys: ['app_version','cases','seal_id','seed','w']
anchor/anchor.json                 inputs keys: ['anchor_digest','cases','verify_at_unix']
```

A22's `anchor` kind declares `verify_at_unix` in `inputs` **because a verify
option determines its pinned bytes** — the `FROZEN.sha256` header says so in
its own words: *"at a fixed `verify_at` against `TsaRootStore::pinned()`"*.
R9's `report` kind declares five **bundle-construction** inputs and **zero**
verification inputs, though its bytes are equally a function of
`verify_at_unix`, `tsa_roots` and (since R20) `storage_linkage`. So the report
vector already pins against an *undeclared* option tuple, and has since R12
populated anchor states. §3 R3 does not create that condition; it names the
tuple for the first time. (The declaration cannot move into the document —
adding an `inputs` key moves the digest, and `verdict_event_ok` refuses it at
`:149-150`, *"no case moved, so the digest changed for some reason this check
cannot see"*. → §10 (i).)

### 1.5 Exactly one production caller of `verify_bundle` exists today

The brief asks for the caller list by measurement, not by guess.

```
$ rg -n "verify_bundle\(|verify_bundle_collecting\(" crates/*/src --glob '!**/test_util/**' \
    | grep -v "^crates/antseal-core/src/verify/pipeline.rs"
crates/antseal-core/src/builder/mod.rs:626:    verify_bundle(&bytes, &VerifyOptions::new())
```

One line. `pipeline.rs`'s own invocations all sit at `:2079` and beyond, i.e.
inside its `#[cfg(test)] mod tests`; `:381`/`:385` are the definition. The
whole population:

| caller | where | what it is | what it needs |
| --- | --- | --- | --- |
| the builder's mandatory self-check (R13/D70 §7.3) | `builder/mod.rs:626` | **the only production caller in the tree** | indifferent — see §3 R7 |
| R9's report-vector executor | `vectors_report.rs:491` (+ regenerator `:683`) | committed exhibit, 21 cases | **suppressed** (§3 R3) |
| R30's digest-table helper | `bundle_fixtures.rs:1991` | committed exhibit, 26 rows | **suppressed** (§3 R3) |
| R11 | — | `antseal-net`; never calls `verify_bundle` and by its own note *"does NOT recompute addresses"* (`tasks/R.md:140` (5)) | unaffected |
| R12 | — | a stage *inside* the pipeline, not a caller | unaffected |
| R16 | `antseal-cli`, no `verify_bundle` call | reaches it only through `builder::build` | unaffected |
| **R21** | does not exist yet | the CLI's library orchestration | **layer ON, not suppressible by its caller** |
| **R22** | does not exist yet | the page binding — `verify(bundle_bytes)`, **no options parameter** (`tasks/R.md:273`) | **layer ON, not suppressible** |
| U30, R23 | do not exist yet | consumers of R21/R22 | inherit |
| R27 | does not exist yet | CLI ↔ page parity | witnesses a divergence |
| everything else | 16 files, 72 `VerifyOptions::new()` occurrences | tamper rows, error-code assertions, property tests, fuzz | invariant to the slot |

**Note the shape of that table.** The one caller that exists is indifferent;
the two that must have the layer ON do not exist yet and cannot express "off"
at all; the two that must have it OFF are committed exhibits. Nobody in the
tree wants the current default.

`with_storage_linkage()` itself has **one** call site in the entire tree —
`crates/antseal-core/tests/storage_linkage.rs:61` — the other six `rg` hits
are rustdoc. As shipped, the layer is reachable only from its own test.

### 1.6 The spec, quoted — and why line 38 is the sentence that decides it

`MVP-SPEC.md` line 116:

> **Two proof layers, rendered distinctly** (the evidence never depends on
> Autonomi):

Line 119:

> 2. **Storage-linkage layer** — the embedded ciphertext must derive the
>    manifest's ciphertext network address (deterministic `self_encryption`
>    address recomputation inside `antseal-core`, fully offline); `--live`
>    re-fetches from Autonomi and byte-compares to prove persistence.

Lines 116/119 are strong but arguable: they describe *what verification is*,
not *which Rust function does it*, and a lane could read "the CLI and the page
render both layers" as compatible with an off-by-default library entry point.
**Line 38 closes that reading**, in a parenthesis that names the page's
storage story by mechanism:

> Optional `--live` (**CLI only** — the page is `antseal-core`-WASM with no
> network layer and there is no backend; **the page's storage story is the
> offline address-recomputation of the storage-linkage layer**) re-fetches
> ciphertexts from Autonomi and byte-compares them against the bundle to
> prove persistence.

And line 156 lists *"storage-linkage layer"* among M3's deliverables beside
the page itself.

So: the page **has** a storage story, it **is** this layer, and the page's
only entry point is R22's `verify(bundle_bytes)` — which by its own `Do` takes
**no options**. A default-off `verify_bundle` therefore gives the page a
`not-evaluated` slot and no storage story at all, unless R22 hardcodes the
opposite of the default. **The layer is non-optional at the product.** What
remains genuinely open — and is what §3 rules — is whether "on" lives in the
default or in two hardcodes.

### 1.7 What the `Evaluated` arm can be produced by today, and what constrains (a)

Both halves of the brief's question 4 are true, and they pull in opposite
directions:

- **The arm is producible from committed fixtures right now.** Any
  `Placeholder` bundle — i.e. every bundle in `testdata/` — yields
  `Evaluated { 0, N, false }` (§1.1 iii). Nothing had to be added to *reach*
  the arm.
- **A *passing* linkage is not producible from any committed artifact, and
  cannot be patched in.** The recorded unit address is written by
  `manifest_entry` into the `UnitEntry` of the **manifest body**
  (`bundle_fixtures.rs:1143-1151`), and `work_id = SHA-256(manifest body)`.
  R20's own test module states the consequence
  (`tests/storage_linkage.rs:31-33`): *"A bent **unit** address lives in the
  signed manifest, so bending it moves `work_id`."* That is why R20 had to
  add `StorageAddresses::{Real, RealExceptUnit, RealExceptManifest}` — a
  linking bundle must be **built** linking, at manifest-construction time.

This is exactly what prices arm (a). Making the exhibits link is not an edit
to a storage record; it is a rebuild of every manifest, hence every `work_id`,
hence every signature, hence every bundle, hence every report.

### 1.8 Arm (a)'s blast radius, measured

Every frozen exhibit that would move, and why:

| frozen file | cases | moves because |
| --- | --- | --- |
| `manifest/manifest.json` | 6 | its six works go through R6's constructor (`vectors_manifest.rs:50`, `:85-86`, `:180`), so `manifest_bytes`, `work_id`, `anchor_digest`, `decoded` and the two-layer `diagnostic` all move |
| `bundle/bundle.json` | 10 | same constructor (`vectors_bundle.rs:76`); `bundle_bytes`, `work_id`, `anchor_digest`, `decoded`, `diagnostic` |
| `report/verification-reports.json` | 21 | `bundle_len`, `bundle_sha256`, `report`, `report_json`, `report_len` — the input moved, so this is a FIXTURE EVENT and `verdict_event_ok` refuses it at `:140-142` before it ever reaches the cardinality check |

3 of 14 frozen files; 37 of those files' 47 cases; and within each case, nearly
every field. Plus, in source: all **26** `REPORT_DIGEST_BY_SHAPE` rows, the
F14 Python cross-check sidecars, and the fuzz seed corpus.

Two further costs the enumeration did not price:

- **It breaks a content locator.**
  `crates/antseal-core/tests/verify_fuzz.rs:230-248`,
  `the_unauthenticated_region_at_m0_is_exactly_the_storage_record`, finds the
  88 unauthenticated bytes by searching for `[(0x5E, 32), (0x5A, 24),
  (0x5C, 32)]` with `find_unique`. Under any real mode the address (`0x5E`)
  and `k_m` (`0x5C`) become BLAKE3/HKDF output; only the nonce survives, and
  `bundle_fixtures.rs:1184-1185` preserves it deliberately *"so a bundle
  remains locatable by content"*. Two of the three markers vanish and the
  test cannot find its own subject.
- **It contradicts the fixture's own ruling.**
  `bundle_fixtures.rs:318-324`: *"The default is `Placeholder` and **must
  stay** the default … a changed default is a FIXTURE EVENT that moves the
  frozen bundle and manifest vectors as well as the report ones (D94 §5)."*

And the payoff is negative: after arm (a), **every** committed bundle links,
so the committed set loses the property R20 went to the trouble of asserting —
*"a bundle with no valid storage linkage at all still verifies"*
(`tests/storage_linkage.rs:173-192`), which the module doc calls *"the
strongest form of the separation claim"*.

### 1.9 D105 §10's declined class is a different hole

D105 §10 bullet 3, in full:

> **The missing fourth freeze class** (§6) — adding a case to a frozen report
> document has no vocabulary and no mechanism. Reported as drift on Q107's
> scope; not designed here, and §5 deliberately routes around it rather than
> forcing it.

Its subject is **adding a case** (§5.1 Route A: *"the case count moved
(21 → 22); a verdict event re-values existing cases and adds none"*). This
change adds no case; it re-values all 21. Designing D105's declined class
would leave this change exactly as refused as it is now. The R20 lane's arm
(b) therefore points at a hole that is real, is documented, and is **not this
one**.

There *is* a second, unnamed hole here — a verdict event that re-values every
case at once has no class — and §2.2 declines to design it too, on measurement
rather than by inheritance.

### 1.10 What the cardinality check is actually a backstop against

The `len(moved) == len(a)` refusal is affirming the consequent: a format event
moves all cases, therefore all-moved means format event. Its warrant is one
observation (R32 at `report_version` 0 → 1). But it is not decorative. A
**disciplined** format event moves `report_version` and is caught two checks
earlier; an **undisciplined** one — a field added to a frozen struct without
the bump D29 rule 1 requires — leaves `report_version` unmoved, moves all 21,
and is caught by *this check and nothing else inside the freeze instrument*.

Source-side instruments would also catch it (`fully_populated_report()` stops
compiling when a struct gains a field; the three `EXPECTED_CANONICAL_JSON*`
literals and R30's 26 rows all move). But those live in the same commit as the
change and can be re-blessed by the same hand. The freeze instrument's value
is that it cannot. Relaxing its last line to admit a whole-population verdict
event trades a permanent guard for a one-off convenience — and §3 shows the
convenience is not needed.

### 1.11 The coverage the layer already has, and keeps

Nothing in §3 creates an R69-shaped gap, because R20 discharged D105's R-VAL
obligation the day the arm landed:

- `EXPECTED_CANONICAL_JSON_WITH_LINKAGE` (`verify/mod.rs:466`, differential
  against the control at `:485-491`) — the **whole canonical report**
  rendering D105 ruling 4 requires, on D29's own fixed-fixture instrument,
  dual-target by A90's `--lib` route (`scripts/wasm-tests.sh:51`,
  `cmd_check`'s `cargo test -p antseal-core --lib --target
  wasm32-unknown-unknown` — D105 §1.5 cites `:48`, which is stale by three
  lines and is recorded here rather than edited into a resolved record);
- `StorageLinkageResult::ALL` + a wildcard-free tag accessor + the sweep
  (`report.rs:471-509`) — Q127's triple, so a third value is a compile error;
- `tests/storage_linkage.rs` — 6 bundle-level tests over four address modes,
  including the byte-identity control pair at `:151-171`;
- `verify/storage_linkage.rs` — 7 unit tests, `--lib`, so wasm32 runs them;
- R18's four frozen wording rows, already in the snapshot
  (`crates/antseal-core/tests/snapshots/verdict-wording.txt:89-92`), including
  the `not evaluated` row — which stays reachable and stays rendered.

And **both** enum values keep a whole-canonical-report pin after §3: the 21
frozen cases pin `NotEvaluated` in composition; `EXPECTED_CANONICAL_JSON_WITH_
LINKAGE` pins `Evaluated` in composition.

### 1.12 The cost of running the layer, priced

Per verification: one BLAKE3-256 over each **embedded** ciphertext (bytes the
evidence layer has already decrypted and hashed), plus one
XChaCha20-Poly1305 pass and one BLAKE3 over the plaintext manifest. Bounded by
`MAX_MANIFEST_BYTES` = 16 777 216 (`codec/caps.rs:118`). Allocation is one
`BTreeMap` and one `Vec` sized by the embedded-reveal count
(`pipeline.rs:1180-1203`), both bounded by `MAX_COVERED_REVEAL_COUNT`.

The at-scale perf guard is unaffected in kind: `verify_scan_shape.rs` builds
**no-reveal** bundles, so only the manifest half runs, against a 15-second
absolute bound (`:215`) and a scaling-ratio guard that a constant-factor
addition cannot move.

One adjacency checked rather than assumed: a manifest whose blob exceeds
`MAX_CHUNK_SIZE` (4 194 304, `storage.rs:66`) has no v1 address at all (D32),
which would make `manifest_matched` permanently `false`. It is **unreachable
from the seal path** — `crates/antseal-cli/src/pipeline/seal.rs:333` caps the
encrypted-manifest blob at seal time with `over_cap("the encrypted manifest")`
— so the layer's over-cap arm is defensive only, exactly as its doc says.

---

## 2. The enumerated arms, refused on measurement

### 2.1 (a) FIXTURE EVENT — refused

Refused on §1.8's blast radius (3 frozen files, 37 cases, 26 R30 rows, a
broken content locator, a contradicted fixture ruling) against a **negative**
payoff (§1.8's last paragraph). Two additional measurements finish it:

- **It is the class the freeze policy prices highest, and it prices it in
  decisions, not in bytes.** `testdata/vectors/README.md`'s three-cause table:
  *"FIXTURE EVENT | the **input bundle** changed, so `bundle_sha256` moves |
  any bundle digest moved | the largest — it moves frozen `bundle`/`manifest`
  vectors too, and over a frozen `v1` vector it needs its own decision"*. So a
  FIXTURE EVENT is **not** an unruled class — it has vocabulary, a
  recognizer, and a stated price. This decision *could* pay it. It refuses to,
  because the thing bought is worth less than the thing spent.
- **A re-emit that moves everything is a re-emit nobody can review.** The
  reviewer's only differential — which cases moved, and why those — is empty
  when the answer is "all of them, in every field". D94's own re-emit
  procedure exists because R12 moved **1 of 21**.

### 2.2 (b) The fourth freeze class — refused, and mis-aimed

Mis-aimed per §1.9: D105 §10's declined class admits *added cases*, and this
change adds none.

The class this change would actually need — *a verdict event that re-values
every case* — is refused on §1.10: the cardinality check is the freeze
instrument's only defence against an undisciplined format event, and the
instrument's whole value is that it is not editable in the same commit as the
change it guards. Designing a class whose sole member is a change that has a
free alternative (§3) is the "designing a class to admit one change is how
freeze discipline dies" case in its purest form.

**Stated so it cannot be mistaken for evasion**: this record declines to
design that class *and says the hole is real*. It is reported in §10 (ii) so
Q107's owner inherits a second short row rather than a silence. What makes
declining honest here — and would not make it honest if §3 did not exist — is
that no change in the tree needs the class, this one included.

### 2.3 (c) Permanently opt-in — refused in its literal form; its mechanism survives inverted

The literal arm — *the layer is optional; the default stays off; R21/R22 turn
it on* — is refused, on three measurements:

1. **It makes the spec-mandated configuration the one you have to remember.**
   Under (c), the storage layer appears only because two future rows each
   hardcode the opposite of the default. If both forget, the product ships
   with no storage story, the 21 vectors agree, R30 agrees, R18's
   `not evaluated` row renders a perfectly grammatical sentence, and **nothing
   goes red.** R27's parity gate compares CLI against page and cannot see an
   omission both share. That is a silent spec divergence with no red arm — the
   failure class this project spends whole records closing.
2. **Its failure modes are inverted relative to §3's.** Under §3, the way to
   get it wrong is to forget to *suppress* an exhibit, which reddens instantly
   and loudly (`vector-freeze.sh` refuses; R30's 26-row assertion fires with a
   message that already names the three event classes). Loud-on-error beats
   silent-on-error when the cost of the two arms is otherwise comparable, and
   here §3 is also the cheaper one.
3. **"Optional" is not a property line 38 leaves available.** §1.6.

What survives from (c) is its *mechanism*: a switch on `VerifyOptions`, and
the two exhibit generators as its only users. §3 keeps the switch and points
it the other way.

### 2.4 The arm nobody supplied — a new vector kind — refused *for now*, and recorded

A new `storage-linkage` vector kind is unambiguously legal post-freeze: it is
the sanctioned append path, executed twice already (`storage-address`, S4,
2026-08-01; `anchor`, A22, 2026-08-09), and `testdata/vectors/README.md`'s
"Add a kind" row says a new kind *"is an **append** … no existing digest moves
and no existing vector is touched"*. D105 §5.4 Route D reached the same
conclusion and refused it for R69 on cost and on an A22 coupling that no
longer exists.

Refused here too, for a different reason: **nothing requires it.** R20's
`Accept` asks for no vector; D105's R-VAL is discharged (§1.11); spec line
167's native↔wasm32 bit-match obligation is met for this layer by A90's
`--lib` route, which D105 §5.2 property 4 accepted for exactly this class of
value. D105 §5.5 left *"whether every report value must eventually live in a
**retained** `testdata/` artifact"* open and said that if it is ever ruled yes,
the snapshot is a floor and not a ceiling. That remains open, and this record
does not pre-empt it — it records the route in §10 (iii) as the answer if it
is ever asked.

### 2.5 The arm that was taken, stated as its own claim

> The exhibits pin an **options tuple**, not a **default**. Name the tuple at
> the two sites that already build it, and the default is free.

It is the shape the enumeration missed because the enumeration inherited a
premise — *the vectors are what a default run produces* — that is true today
only by coincidence of spelling, and that the sibling `anchor` kind already
does not share (§1.4).

---

## 3. The ruling

Eight rules. "The layer" = the offline storage-linkage stage
(`verify::storage_linkage`); "the exhibits" = the 21 R9 report cases and the
26 `REPORT_DIGEST_BY_SHAPE` rows.

**R1 — `verify_bundle`'s default runs the layer.** `VerifyOptions::new()`
evaluates storage linkage. The report's `storage_linkage` slot therefore
carries `Evaluated{…}` in every report a caller gets without asking otherwise.
Warrant: spec line 38's *"the page's storage story is the offline
address-recomputation of the storage-linkage layer"*, read against R22's
options-free `verify(bundle_bytes)` — the page cannot opt in, so the default
must already be in. Lines 116 and 156 agree; §2.3 measures what "off by
default" costs.

`REPORT_VERSION` stays `1`. This rule adds no variant, no field and no
spelling — R20 already landed those as a D105 §2.4 value addition. It changes
only **which existing value a default run emits**.

**R2 — the suppression switch, renamed, with a closed caller list.**

- `VerifyOptions::with_storage_linkage()` is **deleted**. Its meaning after R1
  is "turn on the thing that is on", and leaving it in the API is an invitation
  to read the layer as opt-in. There is no release (Q34 unstarted, D105 §4.1
  ground 4), and the method is uncommitted work of this same wave, so removal
  costs no caller.
- `VerifyOptions::without_storage_linkage()` replaces it: `#[must_use] const
  fn`, same builder shape as `with_verify_at_unix`/`with_tsa_roots`. The
  accessor `storage_linkage()` is unchanged.
- **Its caller list is closed at two entries**, both committed-exhibit
  generators (§3 R3), and that closure is asserted, not merely documented: a
  literal scan (D123's pattern) requires `without_storage_linkage` to appear
  in exactly those two files plus its own definition and rustdoc. A third
  appearance is a red arm, because the third caller is either a product
  surface that must not suppress (R5) or an exhibit nobody ruled.
  — **Contradicted by §3.2 row 3 of this same ruling; see "Correction — §8
  edit 3's second target, and the §3 R2 / §3.2 contradiction about the scan's
  file count, 2026-08-12" below** (D117 §2.3 (c): pointer only — neither
  sentence is rewritten).

**R3 — the exhibits pin a stated options tuple, not a default.** Both
generators pass `VerifyOptions::new().without_storage_linkage()`:

- `crates/antseal-core/src/test_util/vectors_report.rs:491` (`build_expect`)
  and its regenerator at `:683`;
- `crates/antseal-core/src/test_util/bundle_fixtures.rs:1991-1992` (the
  `verify()` helper behind `REPORT_DIGEST_BY_SHAPE` and
  `emit_r30_report_digest_table`).

Each site carries a one-paragraph rustdoc stating **why**, in these terms: the
exhibits' bundles are M0 `Placeholder` fixtures, so running the layer over them
would pin 21 identical fixture-only failures rather than any product fact
(§1.1 iii); the layer's coverage lives at the instruments in §1.11; and the
tuple is explicit precisely so that a future change to `new()` cannot move a
frozen digest by accident.

**This moves nothing.** The value passed is the value passed today; only its
spelling changes. `scripts/vector-freeze.sh` must report `v1: unchanged`, and
all 26 R30 rows must be byte-identical. If either moves, §7 kill criterion 1
has fired. *(→ see the Correction of 2026-08-12 after `## Outcome`: `v1:
unchanged` is unobtainable from a flagless run — the string exists only in the
`--update` branch. The gate this sentence intends is `GREEN` + `v1: N frozen
vector(s) OK`. The ruling is unaffected; only the expected string is wrong.)*

**R4 — no freeze event of any class occurs, and these numbers must be zero.**
This decision authorises **no** `--update`, **no** `--verdict-event`, **no**
FIXTURE EVENT and **no** new freeze class. The implementing commit must state,
checkably: **0 frozen vector digests moved · 0 `REPORT_DIGEST_BY_SHAPE` rows
moved · 0 files under `testdata/` touched · `REPORT_VERSION` unchanged at 1.**
Because there is no event, **no row executes one** — the brief's question 5 is
answered by there being nothing to own.

**R5 — the two product entry points may not expose suppression.** R21's
orchestration and R22's binding construct their own `VerifyOptions` and do not
accept one from their callers for this bit. Neither may call
`without_storage_linkage`. Consequences: U30 has no `--no-storage-linkage`
flag and R23's page has no toggle; a third party dropping a `.sealproof` on
the page **always** sees the storage-linkage section, which is what line 38
promises. If a user-facing suppression is ever wanted, it is a new decision
and a new CLI surface, not a default.

**R6 — what the downstream rows owe, as red-capable rows and not as prose.**

- **R21** — Accept gains: *for a well-formed bundle, the offline report R21
  exposes carries `StorageLinkageResult::Evaluated`, and
  `wording::storage_linkage_not_evaluated_line()` appears nowhere in its
  rendered output.* The negative half is the one that catches a regression,
  because the positive half can be satisfied by a renderer that prints the
  section header and nothing under it. R21's `Do` already puts `--live`'s
  per-blob results *"in the storage layer's section"*; the offline linkage rows
  render in that section **whether or not `--live` was asked for** — line 119
  is one layer with two questions, not two layers.
- **R22** — Accept gains the same assertion through the JS boundary, on a
  bundle verified via the binding. R22's existing row *"R9 golden vectors
  verified through the JS boundary produce reports byte-identical to native"*
  **needs an amendment**: after R3 the vectors are pinned to a suppressed
  tuple and the binding runs the default, so the binding's report for a vector
  bundle is *not* the vector's pinned report. The row's real content is
  native ≡ wasm32 for the same input, and it must say so: *"…byte-identical to
  the report native `verify_bundle` produces for the same bundle under the
  same options."* Left as written it is a row that must fail. → §9.3.
- **U30 / R23** — inherit; no flag, no toggle (R5).
- **R27** — its CLI↔page parity comparison now covers the storage section on
  both sides; that is the arm that would witness one surface diverging.

**R7 — the builder's self-check keeps the default, and that is a decision, not
an omission.** `builder/mod.rs:626` runs with `VerifyOptions::new()`, so after
R1 it evaluates the layer. Three grounds: its own comment already licenses any
option (*"no option could change the accept/reject bit this gate reads"*,
`:621-625`) and the layer cannot fail, so the gate is unchanged; the marginal
cost is a BLAKE3 over bytes the builder has already AEAD-processed (§1.12);
and suppressing it would be the third entry on a list R2 closes at two. The
builder currently **discards** the finding — see §10 (iv), which is the one
place this ruling leaves value on the table on purpose.

**R8 — what does not change.** No struct gains, loses or reorders a field, so
D105 §2.4's test is satisfied trivially and `REPORT_VERSION` stays `1`. No
registry key, no error code, no HKDF label, no domain tag, no wording row
(R18 froze all four in wave 17 and the `not evaluated` row stays reachable
through `without_storage_linkage` and through any caller who suppresses).
D29's three fixed-fixture literals are hand-built and pipeline-independent, so
none moves. D64's report-byte equality for R21 is untouched — both an
`--online` and an offline run have the layer on, so the bytes stay identical.
D65's tiering is untouched: `storage_linkage` is a tier-A enum-valued key
already documented as open (D65 §"the one hole"), and this rule adds no
spelling to it.

### 3.1 The implementation detail that will silently ship wrong if unstated

`VerifyOptions` derives `Default` (`pipeline.rs:264`). A derived `Default`
gives `storage_linkage: false` and would **disagree with `new()`** the moment
R1 lands. Replace the derive with an explicit
`impl Default { fn default() -> Self { Self::new() } }`.

The red arm already exists and needs no minting:
`pipeline.rs:2576` `default_options_are_the_conservative_ones` opens with
`assert_eq!(VerifyOptions::default(), VerifyOptions::new())`. Its **title and
doc must be updated** in the same edit — "the conservative ones" was accurate
when every default meant *do less*, and after R1 one default means *do the
thing the spec names*. The other two clauses (no caller-supplied clock, the
pinned root store) keep their meaning and their R12 warrant verbatim.

### 3.2 The three source assertions that change meaning, enumerated

Measured by sweeping every pin of the slot; the list is complete.

| site | today | after R1 | why it is a strengthening, not a re-bless |
| --- | --- | --- | --- |
| `pipeline.rs:2100` (`a_valid_bundle_verifies_end_to_end`) | `assert_eq!(report.storage_linkage, NotEvaluated)` | asserts the `Evaluated{0, N, false}` value | it stops asserting "the stage did not run" and starts asserting what the stage found on an M0 fixture — a value with content |
| `pipeline.rs:2897` (`the_partial_with_mirror_report_bytes_are_pinned`) | the literal fragment `"storage_linkage":"not-evaluated",` | the evaluated object | one whole-report literal, in-diff and reviewable; it is the D29-style literal-against-literal pin, not a digest |
| `tests/storage_linkage.rs:198` (`the_layer_is_silent_unless_it_is_asked_for`) | three modes under `VerifyOptions::new()` assert `NotEvaluated` | the same three modes under `without_storage_linkage()` | the test's subject inverts to *the layer is silent only when it is suppressed*, which is the property R2's closed caller list depends on — **and this is the third file R2's own sentence does not admit; see the Correction of 2026-08-12 below** |

Unaffected and verified so: the three `EXPECTED_CANONICAL_JSON*` literals and
`overlay/tests.rs:724` (hand-built, never pipeline-produced — D105 §5.2
property 1); `report.rs:990` (standalone slot serialization);
`crates/antseal-cli/tests/redaction_view.rs:429` (substring checks on
redaction fields only); `crates/antseal-cli/tests/snapshots/json-envelopes.txt`
(zero occurrences of `storage_linkage`). `testdata/` contains exactly **one**
file mentioning the slot — `report/verification-reports.json` — and R3 keeps
it byte-identical.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| FIXTURE EVENT: give R6's fixtures real S4 addresses | 3 frozen files / 37 cases / 26 R30 rows move (§1.8); breaks `verify_fuzz.rs:230`'s content locator (two of three markers vanish); contradicts `bundle_fixtures.rs:318-324`; deletes the committed evidence that an unlinked bundle still verifies; and the payoff is a set of exhibits that can no longer show a mismatch |
| flip the default and re-emit the 21 under placeholders | refused by the instrument (§1.2) **and** on content — it would pin 21 permanent fixture-only failures, which is a worse statement than `not-evaluated`, a value whose own doc says it claims nothing (§1.1) |
| design D105 §10's fourth class | mis-aimed: that class admits an *added case*; this change adds none (§1.9) |
| design a *fifth* class for a whole-population verdict event | removes the freeze instrument's only defence against an undisciplined format event (§1.10), to buy something §3 supplies free |
| permanently opt-in, R21/R22 hardcode "on" | makes the spec's configuration the one you must remember; both surfaces forgetting is silent and self-consistent, and R27 cannot see an omission it shares (§2.3) |
| keep both `with_` and `without_storage_linkage` | two switches for one bit; the surviving `with_` reads as evidence the layer is opt-in, which after R1 it is not (§3 R2) |
| a user-facing `--no-storage-linkage` on `verify` | mints CLI surface no row owns, to let a user turn off a layer the spec says the verdict renders; and the layer gates nothing, so there is no verdict to escape (§3 R5) |
| declare the options tuple in the vector document's `inputs` | moves a frozen digest with no case moved, which `verdict_event_ok` refuses at `:149-150`; the declaration lives in the executor instead (§1.4, §10 i) |
| a new `storage-linkage` vector kind now | legal and cheap-ish, but nothing requires it: R20's Accept asks for none, D105's R-VAL is discharged, and wasm32 parity comes by A90's `--lib` route (§2.4). Recorded as the answer if D105 §5.5's open question is ever ruled yes |
| suppress the layer in the builder's self-check | would make R2's caller list three, for a cost §1.12 bounds and a finding §10 (iv) argues the builder should eventually *use* (§3 R7) |

---

## 5. The edges with D105, D94, D64 and D65, drawn explicitly

**D105 owns whether a *value* may enter frozen report v1.** It ruled R20's arm
legal and stated the test (§2.4). **D128 owns nothing about the value space**:
it adds no variant, no field and no spelling. It rules only *which existing
value a default `verify_bundle` run emits*, which D105 §10 bullet 1 explicitly
left open (*"R20's design … whether R20 renders anything at all"*). D105 is
not amended, corrected or reopened.

**D94 owns the three-class vocabulary for a moved pin.** D128 moves no pin, so
no class applies. Its one contribution to that vocabulary is negative and is
reported, not ruled: the recogniser's `all cases moved ⇒ FORMAT EVENT` step is
a sufficient-condition heuristic standing in for a necessary one (§1.10), and
it is left standing deliberately.

**D64 is the near-miss worth naming.** D64 §6 ruled the `--online` overlay a
**sibling document** so that *"the canonical report bytes of a `--online` run
are byte-identical to the offline run's"*, and made `--live`'s
`LiveCheckReport` a third sibling. The obvious inference — *so run modes must
never move report bytes* — does not reach here, because `storage_linkage` is a
report v1 **field**, frozen at Q14, and cannot be moved out of the report
without the FORMAT EVENT D64 itself refused to pay. The genuine distinction:
`verify_at_unix` and `tsa_roots` are *evidence inputs* whose values legitimately
change the report; `storage_linkage` is the first *execution switch* that does.
R1 is what shrinks that anomaly to its minimum — after it, the switch is off
only in two committed exhibits, and every product surface produces the same
bytes for the same bundle.

**D65 is untouched and already priced this.** `storage_linkage` is named in
D65's tier-A hole as an enum-valued key that *"may gain a spelling with no
version moving anywhere"*, with the standing consumer rule to *"always write
the default arm"*. D128 adds no spelling; it changes which arm a default run
takes, which no released consumer can observe because none exists (Q34
unstarted).

---

## 6. Consumed rows and inputs

- **R20** (`tasks/R.md:243-253`) — the `Do`'s *"Add the offline storage-linkage
  stage to `verify_bundle` (report-slot populated)"* becomes satisfiable; the
  D105 §9 edit-6 paragraph appended to it stays true and untouched.
- **R9** (`:109-118`) and **R30** (`:369-378`) — their executors gain the
  explicit tuple (§3 R3); neither row's Accept changes meaning.
- **R21** (`:254-266`), **R22** (`:268-278`), **U30**, **R23**, **R27** — §3 R6.
- **MVP-SPEC.md** lines 38, 116, 118, 119, 156 (and 98 for the storage record,
  167 for the bit-match obligation), quoted where load-bearing.
- **D105** (value addition; R-VAL; §5.5's open retention question; §10's
  declined class), **D94 §5** + `testdata/vectors/README.md`'s three-cause
  table (the FIXTURE EVENT class and its price), **D29** rules 1/4 and its
  fixed-fixture instrument, **D64 §6**, **D65** tier A, **D32/D35** (one blob =
  one chunk; BLAKE3-256), **D70 §7.3** (the builder's beyond-self-check
  assertions), **D123** (the literal-scan pattern R2 borrows), **Q6/Q14**
  (`testdata/vectors/v1/FROZEN.sha256`'s authority, cited by directive and not
  by line), **A90** (the `--lib` wasm32 route), **Q127** (the enum triple).

---

## 7. Kill criteria

This record is wrong, and must be re-opened, if any of these is observed:

1. **Landing §3 moves any frozen vector digest, or any
   `REPORT_DIGEST_BY_SHAPE` row.** R3 changes a spelling, not a value; a moved
   pin means the edit reached further than §3 describes. **Stop and find out
   why — do not re-pin, and do not reach for `--verdict-event`.**
2. **R22's binding turns out to need a `VerifyOptions` parameter after all**
   (e.g. the page must supply `verify_at_unix` from the browser clock). Then
   the page *can* express options, §1.6's decisive step weakens to lines
   116/119 alone, and §2.3's arm (c) deserves a second reading — though R5's
   prohibition on caller-supplied suppression would still stand.
3. **A third `without_storage_linkage` call site is proposed.** R2's closure is
   the load-bearing half; a third caller means either a product surface is
   suppressing (forbidden by R5) or a new exhibit exists that nobody ruled.
4. **`Deserialize` is derived on any report type** (D105 §8 criterion 1). A v1
   reader meeting `{"evaluated":{…}}` where it expected `"not-evaluated"` is a
   compatibility event, and *which value a default run emits* stops being an
   internal question.
5. **A release ships** (Q34). Then the default's change becomes observable to
   deployed consumers and D65's tier-A rule stops being free advice.
6. **D105 §5.5's open question is ruled yes** — every report v1 value must live
   in a *retained* `testdata/` artifact. Then §2.4's refusal expires and the
   `storage-linkage` kind in §10 (iii) is the route.
7. **Someone measures the layer costing more than §1.12 bounds** — in
   particular if `verify_scan_shape.rs`'s ratio guard (`< 3.0`) moves at all.
   The layer is O(embedded bytes + manifest bytes) and must not scale with
   files × units; if it does, R54's scan-shape defect has a new instance.

---

## 8. Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction for the
registrar and the implementing lane.

| # | File | Edit | Why |
| --- | --- | --- | --- |
| 1 | `crates/antseal-core/src/verify/pipeline.rs:305-339` | Replace `with_storage_linkage` with `without_storage_linkage` per §3 R2; the rustdoc's *"The two ways out are a FIXTURE EVENT … or a fourth freeze class"* is **corrected** — there are three, D105 §10's class is a different hole (§1.9), and the exit taken is §3 R3. Keep the measured paragraph about the 21 vectors: it is true and it is why the switch exists | Ruling R1/R2; the live prose enumerates two exits and takes neither |
| 2 | `crates/antseal-core/src/verify/pipeline.rs:264` + `:2576` | Replace the `Default` derive with `impl Default { fn default() -> Self { Self::new() } }`; retitle `default_options_are_the_conservative_ones` and update its doc's first sentence | §3.1 — the derive would silently disagree with `new()` |
| 3 | `crates/antseal-core/src/test_util/vectors_report.rs:491`, ~~`:683`~~ — **Corrected 2026-08-12 → `regenerate_expect`**; see the Correction below | Pass `VerifyOptions::new().without_storage_linkage()`; add the rustdoc paragraph §3 R3 specifies | Ruling R3 — the 21 cases |
| 4 | `crates/antseal-core/src/test_util/bundle_fixtures.rs:1991-1992` | Same, in the `verify()` helper | Ruling R3 — the 26 R30 rows |
| 5 | `crates/antseal-core/src/verify/pipeline.rs:2100`, `:2897`; `crates/antseal-core/tests/storage_linkage.rs:198-213` | The three assertions of §3.2, re-expressed (not re-blessed) | Ruling R1's only source-side consequences |
| 5b | `crates/antseal-core/tests/storage_linkage.rs:61` | `linked()`'s helper drops `.with_storage_linkage()` and uses the plain default; the module doc's *"Verify with the layer switched on — R20's mode"* becomes *"the default"* | Mechanical follow-on of R2's deletion; the test's four fixtures and every assertion are unchanged |
| 6 | a new `--lib` test beside R2's definition | The literal scan closing `without_storage_linkage`'s caller list at two | Ruling R2's red arm |
| 7 | `tasks/R.md` R20 | `Do`: append §9.1's note. `Notes`: append §9.1's second paragraph | The `Do`'s unconditional clause now has its condition ruled |
| 8 | `tasks/R.md` R21 | Append §9.2's Accept row | Ruling R6 |
| 9 | `tasks/R.md` R22 | Append §9.3's Accept row **and amend the existing golden-vector row** — as written it must fail after R3 | Ruling R6; a row that cannot pass is worse than a missing one |
| 10 | `TODO.md` | The D128 register row (Due M3 block) and the R20 row's `→ D128` pointer resolved | Bookkeeping |
| 11 | `docs/decisions/README.md` | One index row for this record, in id order, status/date from this record's own lines (D119 conventions) | Bookkeeping |
| 12 | — | **No edits** to `MVP-SPEC.md`, `testdata/` (any file), `docs/format/registry-v1.md`, `testdata/vectors/README.md`, `scripts/vector-freeze.sh`, or any resolved decision record | Ruling R4 |

**Gate, in this order** (two implementation lanes are building; none of these is
`--workspace`): `cargo test -p antseal-core --lib`; then
`cargo test -p antseal-core --test storage_linkage --test vector_freeze --test
report_vectors --test verify_fuzz`; then `scripts/wasm-tests.sh --check`; then
`./scripts/vector-freeze.sh` (flagless — it must print `GREEN`; note D105's own
recorded slip that `unchanged` appears only in the `--update` branch); then
`cargo fmt` and `cargo clippy`.

**The commit message must state, checkably against the diff**: *no freeze event
— 0 frozen vector digests moved, 0 `REPORT_DIGEST_BY_SHAPE` rows moved, 0 files
under `testdata/` touched, `REPORT_VERSION` unchanged at 1; the default now runs
the layer (D128 R1) and the two committed-exhibit generators suppress it
explicitly (D128 R3).*

---

## 9. Quoted entry notes (registrar's to apply)

### 9.1 `tasks/R.md` R20 — append to `Do`, then to `Notes`

> **Added 2026-08-12 (D128 §3):** the `Do`'s *"report-slot populated"* is
> unconditional and now satisfiable — `VerifyOptions::new()` **runs** the
> layer (spec line 38: *"the page's storage story is the offline
> address-recomputation of the storage-linkage layer"*, read against R22's
> options-free `verify(bundle_bytes)`). The 21 R9 report cases and the 26
> `REPORT_DIGEST_BY_SHAPE` rows are pinned to
> `VerifyOptions::new().without_storage_linkage()` at the two executors that
> already build their own options, so **zero frozen bytes move and no freeze
> event of any class occurs**. `with_storage_linkage` is deleted;
> `without_storage_linkage`'s caller list is closed at those two sites by a
> literal scan.

> - Notes: **[D128, 2026-08-12]** The default was ruled, not deferred. Arm (a)
>   (a FIXTURE EVENT giving R6's fixtures real S4 addresses) is **refused** on a
>   measured blast radius — 3 of 14 frozen files, 37 of their 47 cases, all 26
>   R30 rows, and `verify_fuzz.rs:230`'s content locator loses two of its three
>   markers — for a negative payoff, since every committed bundle would then
>   link and the tree would lose its only evidence that an unlinked bundle still
>   verifies. Arm (b) is refused **and mis-aimed**: D105 §10's declined class
>   admits an *added case* (21 → 22) and this change adds none. Arm (c)
>   (permanently opt-in) is refused because it makes the spec's configuration
>   the one two future rows must remember, and both forgetting is silent —
>   R27's parity gate cannot see an omission it shares. The exit taken is the
>   one the enumeration missed: **the exhibits pin an options tuple, not a
>   default**, and the sibling `anchor` kind already declares its own
>   `verify_at_unix` for exactly that reason.

### 9.2 `tasks/R.md` R21 — append an `Accept` row

> - **[D128, 2026-08-12]** For a well-formed bundle, the offline report this
>   row exposes carries `StorageLinkageResult::Evaluated`, and
>   `wording::storage_linkage_not_evaluated_line()` appears **nowhere** in its
>   rendered output — the negative half is the red-capable one, because a
>   renderer that emits the section header and nothing under it satisfies the
>   positive half. R21 constructs its own `VerifyOptions` and never calls
>   `without_storage_linkage` (D128 §3 R5), so U30 has no flag to suppress the
>   layer with. The offline linkage rows render in the storage layer's section
>   **whether or not `--live` was requested** — spec line 119 is one layer with
>   two questions.

### 9.3 `tasks/R.md` R22 — amend one `Accept` row and append another

Amend the existing row — as written it must fail once D128 R3 lands, because
the vectors are pinned to a suppressed tuple while the binding runs the default:

> - Binding-level test: R9 golden vectors verified through the JS boundary
>   produce reports byte-identical to the report **native `verify_bundle`
>   produces for the same bundle under the same options** (**[D128,
>   2026-08-12]** — the vectors' pinned bytes are the *suppressed* tuple's, and
>   the property this row exists for is native ≡ wasm32 for one input, not
>   binding ≡ vector file)

Append:

> - **[D128, 2026-08-12]** The binding runs the storage-linkage layer: a bundle
>   verified through `verify(bundle_bytes)` returns a report whose
>   `storage_linkage` is `evaluated`. This row is why the layer cannot be
>   default-off — the export takes no options, so the page has nothing to opt in
>   with, and spec line 38 names this layer as the page's entire storage story.
>   R22 never calls `without_storage_linkage` (D128 §3 R5).

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) The `report` kind's `inputs` block declares no verification input, and
cannot be made to.** `anchor/anchor.json` declares `verify_at_unix`;
`report/verification-reports.json` declares `app_version`, `cases`, `seal_id`,
`seed`, `w` — all bundle-construction inputs — while its `expect` is a function
of `verify_at_unix`, `tsa_roots` and `storage_linkage` as well. Adding a key to
`inputs` moves the digest with no case moved, which `verdict_event_ok` refuses
at `:149-150`. So a second implementation could not reproduce these vectors from
the document alone. §3 R3 makes the tuple explicit **in the executor**, which is
the strongest form available under the freeze. Instrument material, and it
predates this decision by two milestones.

**(ii) `verdict_event_ok`'s `all cases moved ⇒ FORMAT EVENT` step is a
sufficient-condition heuristic doing a necessary condition's job.** A verdict
event that re-values every case is refused by a check whose stated warrant is a
single observation (R32). It is left standing deliberately (§1.10) — it is the
freeze instrument's only defence against an undisciplined format event — but it
is a known, now-witnessed limit. Q107 owns the freeze vocabulary table and, per
D105 §6, is already short one class; this is a second. Instrument material.

**(iii) The retained-artifact question D105 §5.5 left open now has a second
instance.** `StorageLinkageResult::Evaluated` joins
`SupportingEvidenceResult::ArbitrumReceipt` as a report v1 value pinned only in
source, never in a retained `testdata/` artifact. If the project ever rules that
every report v1 value must live in a retained artifact, the route for both is a
new `storage-linkage` vector kind through the sanctioned append path (S4
2026-08-01, A22 2026-08-09) — no existing digest moves. Not proposed here.

**(iv) The builder discards a self-check finding it now computes for free.**
After §3 R7 the builder's mandatory `verify_bundle` evaluates the layer and
then throws the report away. A mismatch there means the builder embedded a
ciphertext that does not address to the address the signed manifest records —
i.e. it is about to ship a bundle whose recipient's linkage check will fail,
for a reason internal to the builder. `assert_beyond_self_check`
(`builder/mod.rs:631`, D70 §7.3) is the natural home. This changes what a
user's `reveal` does, so it is **row** material, not ledger material.

**(v) R18 froze one storage-linkage failure row, so two distinct report values
render one sentence.** A bent unit address and a bent manifest address are
different values in the report and the byte-identical CLI line, because the
frozen row takes `(mismatch_count, checked_count)`. R20 reported it and
asserted the equality rather than leaving it to be discovered
(`tests/storage_linkage.rs:244`). D128 does not resolve it: it is a wording-set
question, it is now more visible because the layer renders on every run, and
the distinction survives where it matters — in the report, hence in `--json`
and on R23's page.

**(vi) D105 §1.5 and §5.2 cite `scripts/wasm-tests.sh:48` for the wasm32
`--lib` route; the live line is `:51` (`cmd_check`).** Records are immutable, so
this is reported rather than edited — the same disposition D105 §7 gave the
three stale citations it found. Instrument material.

---

## Outcome

The R20 lane measured the obstacle correctly and enumerated the exits from
inside a premise: that the frozen report vectors are *what a default run
produces*, so moving the default must move them. They are not. They are what
two executors produce with a `VerifyOptions` value they build themselves, and
the sibling `anchor` kind has been declaring its own verify option in its
`inputs` since A22 — the tree already knew that a verification option is an
input to a vector, in one kind out of two.

Naming that input at the two sites that pass it costs one renamed builder
method, three re-expressed assertions and a hand-written `Default`. It buys
the configuration the spec actually mandates: a third party who drops a
`.sealproof` on the page sees both proof layers, because the layer is on before
anyone remembers to turn it on. The FIXTURE EVENT is not paid, the fourth
freeze class is not designed, and the frozen set — 14 files, 14 `OK` lines —
does not move a byte.

---

## Correction — §8 edit 3's second target, the §3 R2 / §3.2 contradiction about the scan's file count, and §3 R3's unobtainable `v1: unchanged`, 2026-08-12

**Three defects, all found by executing §3.** None is a change of decision:
§3 R1–R8 stand exactly as written and this section adds no ruling
(D117 §2.2). The first two run in the direction that *strengthens* the ruling;
the third leaves it exactly where it stood and corrects only a string. Stated
at (4) below.

### (1) §8 edit 3's second target is a test, not a regenerator

**The wrong text, quoted verbatim.** §8's edit-set table, row 3, File column:

> `crates/antseal-core/src/test_util/vectors_report.rs:491`, `:683`

§3 R3 spells the same pair in words —

> `crates/antseal-core/src/test_util/vectors_report.rs:491` (`build_expect`)
> and its regenerator at `:683`

— and §1.5's caller table carries it a third time, as *"`vectors_report.rs:491`
(+ regenerator `:683`)"*.

**What is there.** Measured on the tree after §3 landed. Line numbers are
today's and are a handle only (D117 §2.6); the symbols are the citation:

```
$ grep -n 'fn build_expect\|pub fn regenerate_expect\|fn the_leak_scan_fires_on_a_planted_salt' \
    crates/antseal-core/src/test_util/vectors_report.rs
511:fn build_expect(inputs: &Inputs) -> Result<(serde_json::Value, Vec<CaseArtifacts>), VectorError> {
580:pub fn regenerate_expect(document: &serde_json::Value) -> Result<serde_json::Value, VectorError> {
713:    fn the_leak_scan_fires_on_a_planted_salt() {
$ grep -n 'build_expect(&parsed)' crates/antseal-core/src/test_util/vectors_report.rs
592:    build_expect(&parsed).map(|(value, _)| value)
```

The real regenerator is **`regenerate_expect`**, and its last statement is a
**delegation**: it checks the document's `kind`, parses its `inputs`, and
returns `build_expect(&parsed)`. Pinning `build_expect` therefore pins both,
which is why R3 landed with **one** added call in this file rather than two,
and why §3 R4's four figures came out zero.

`:683` is inside the file's `#[cfg(test)] mod tests`, on
**`the_leak_scan_fires_on_a_planted_salt`** — a leak-scan control that verifies
a bundle under `VerifyOptions::new()` deliberately. **Applying the edit as
written would have added a third suppressing call to the tree** — the exact
condition §3 R2 closes and §7 kill criterion 3 names — and would have
suppressed the layer inside the test that proves the report carries no derived
salt. The instrument reddens on it either way: the scan pins the call **count
per file** at 1, so a second suppressed call inside `vectors_report.rs` fails
on its own without any file-level list changing.

**Disposition.** The locator is struck at §8 edit 3 with the corrected **name**
inline — an edit-set row is a sentence a lane executes (D117 §2.3 (a)) and the
corrected value is a single name (§2.3 (c)). §3 R3's and §1.5's copies carry no
separate marker: this section is the single home of the fact (D117 §2.2) and
names all three sites, so a reader arriving at any of them lands in one place.

### (2) §3 R2 and §3.2 contradict each other about how many files may name the switch

**The two sentences, quoted verbatim.** §3 R2, third bullet:

> **Its caller list is closed at two entries**, both committed-exhibit
> generators (§3 R3), and that closure is asserted, not merely documented: a
> literal scan (D123's pattern) requires `without_storage_linkage` to appear
> in exactly those two files plus its own definition and rustdoc.

§3.2, row 3, in the same ruling:

> `tests/storage_linkage.rs:198` (`the_layer_is_silent_unless_it_is_asked_for`)
> … the same three modes under `without_storage_linkage()` … the test's subject
> inverts to *the layer is silent only when it is suppressed*, **which is the
> property R2's closed caller list depends on**

**The contradiction, flatly.** §3.2 **mandates** a call to
`without_storage_linkage` in a third file — `crates/antseal-core/tests/storage_linkage.rs`,
which is not an exhibit generator, not the switch's definition and not its
rustdoc — and calls the property that call establishes the one *"R2's closed
caller list depends on"*. A scan built to R2's sentence reddens on the file
R2's own warrant rests on.

**§3.2 wins by construction, and this section does not rule it so.** R2's clause
is a **count of appearances**; §3.2's row is a **mandated act** with a named
subject. A record that requires an act and forbids its trace is falsified by its
own mandate — so this section states which of its two sentences the tree obeys
and rewrites neither (D117 §2.1 (a), §2.2).

**How the implementation resolved it without moving either number.**
`without_storage_linkage_has_exactly_two_callers`
(`crates/antseal-core/src/verify/pipeline.rs`) is a **three-entry table**, each
row `(path, calls, why it may suppress)` carrying its own warrant:

```rust
const CALLERS: [(&str, usize, &str); 3] = [
    ("crates/antseal-core/src/test_util/vectors_report.rs", 1,
     "R9's report-vector executor: the 21 frozen cases (D128 §3 R3)"),
    ("crates/antseal-core/src/test_util/bundle_fixtures.rs", 1,
     "R30's digest-table helper: the 26 REPORT_DIGEST_BY_SHAPE rows (D128 §3 R3)"),
    ("crates/antseal-core/tests/storage_linkage.rs", 1,
     "the switch's own test — the layer is silent only when suppressed (D128 §3.2)"),
];
```

and **R2's number is asserted separately and exactly**, over the partition that
makes it true — the switch's own test is outside every `src/` by construction:

```rust
let in_src = CALLERS.iter().filter(|(path, _, _)| path.contains("/src/")).count();
assert_eq!(in_src, 2, "D128 §3 R2's caller list is closed at two library-side suppressors");
```

The reasoning is written into the test's rustdoc, so the third row cannot be
read later as an unexplained relaxation, and the per-file call count closes the
hole a file-level list leaves open.

### (3) §3 R3 expects a string a flagless run cannot print

**The wrong text, quoted verbatim.** §3 R3's closing paragraph:

> **This moves nothing.** The value passed is the value passed today; only its
> spelling changes. `scripts/vector-freeze.sh` must report `v1: unchanged`, and
> all 26 R30 rows must be byte-identical.

**What the script prints.** Measured on the committed script; line numbers are
today's and are a handle only (D117 §2.6), the branch is the citation:

```
$ grep -n 'unchanged\|frozen vector(s) OK\|vector-freeze: GREEN' scripts/vector-freeze.sh
207:      echo "  ${version}: ${count} frozen vector(s) OK (independent ${SUM[*]} check)"
241:  echo "vector-freeze: GREEN"
358:      echo "  ${version}: unchanged"
$ grep -n 'update)' scripts/vector-freeze.sh
 92:  --update)     MODE="update" ;;
316:update)
```

`:358` is inside the `update)` arm opened at `:316` — it is the idempotence
report, printed when the regenerated digest block `cmp`s equal to the committed
one. **`unchanged` exists only in the `--update` branch.** A *flagless* run —
which is what §8's own gate list tells the lane to perform — takes the lane
arm and prints `:207` and `:241`: `vector-freeze: GREEN` plus
`v1: N frozen vector(s) OK (independent sha256sum check)`. The word
`unchanged` cannot appear in it, so as written R3 asks the lane for evidence
the run it is told to make is incapable of producing.

**The ruling is unaffected, and this is the load-bearing half.** The gate R3
intends is *the frozen set did not move*, and that is exactly the gate the
implementation ran and passed: `vector-freeze: GREEN` with
`v1: 14 frozen vector(s) OK`, plus `sha256sum -c FROZEN.sha256` at 14/14 `OK`
with `PIPESTATUS[0]=0`. Only the expected **string** is wrong. Note that the
two are not interchangeable even though both are green here: `unchanged` is a
statement about a *regeneration* that produced no diff, and `OK` is a statement
about *digests matching what is committed* — R3 wants the second and named the
first.

**This is the third site of one slip, and the origin is not this record.** The
sentence descends from D105's own gate list —
*"**`scripts/vector-freeze.sh` must report `unchanged`** — if it does not, kill
criterion 4 has fired"* (`docs/decisions/D105-post-freeze-report-value-additions.md:662-663`)
— which D128 §8 already names as D105's recorded slip while telling the lane to
run flagless and expect `GREEN`. It has since propagated twice more: into §3 R3
above, five sections earlier in the record that warns about it, and into the
wave-18 lane prompt that quoted R3. R20's `TODO.md` result line carried it too
until the implementing act rewrote it. **The one correct use in the tree names
its branch**: `docs/ci-verification.md:755` records `v1: unchanged` in a row
whose command column is `./scripts/vector-freeze.sh --update` — which is why it
is right and the others are not.

**Disposition.** An inline pointer is placed at §3 R3's sentence directing the
reader here, and the sentence itself stands verbatim (D117 §2.2: this section
is the single home of the fact; §2.3 (c): the corrected value is a single
string, `GREEN` + `v1: N frozen vector(s) OK`). D105's sentence is **not**
edited from here — a record does not correct another record's prose — and the
ledger entry of 2026-08-12 carries it as the origin so a future D105 reader
lands on the measurement.

### (4) Authority, separability, and which rulings stand

**Authority.** All three defects were found by the **D128-implementation lane**
(2026-08-12) while executing §3 — the lane that was executing the record, so
D117 §2.3 (e) is satisfied — and applied by the wave-18 registrar, who re-ran
the two `grep` measurements at (1) and the two at (3) before applying them.

**Separability (D117 §2.1 (c)).** This correction lands in a commit distinct
from the one that committed this record's body: D128 and its register row landed
in wave 18's Act 2b, and §3's implementation and this section come after.

**Which rulings still stand: all of them.** (1) and (2) move them in the
strengthening direction; (3) does not move R3 at all.

- (1) **strengthens R3.** The edit set over-specified its target; the correct
  target is a strict subset of what it named, because the regenerator delegates.
  The zero-byte result R4 demands is what proves the subset was sufficient.
- (2) **falsifies R2's arithmetic and confirms R2's purpose.** The third file is
  the switch's own instrument, so what R2 exists to hold — *no product surface
  suppresses* — is asserted more tightly than R2's sentence describes: `in_src
  == 2` over a `/src/` partition, plus a per-file call count R2 never asked for.
- (3) **leaves R3 where it stood.** It corrects the string a lane is told to
  observe, not the property R3 asserts. The exhibits still pin a stated options
  tuple, the frozen set still does not move, and **§7 kill criterion 1 — named
  in R3's own sentence — has not fired**: it is evaluated against the digest
  evidence (14/14 `OK`, 0 `REPORT_DIGEST_BY_SHAPE` rows moved), which is what
  R3 always wanted, reported under the name the flagless lane actually prints.
- **§7's kill criteria are untouched.** In particular criterion 3 — *"A third
  `without_storage_linkage` call site is proposed"* — has **not** fired: it names
  a product surface that must not suppress, or an exhibit nobody ruled, and
  `tests/storage_linkage.rs` is neither. Recorded explicitly so no later reader
  meets the three-entry table and concludes the record must be re-opened.
