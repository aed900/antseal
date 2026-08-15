# D133 — How the corpus gains a bundle that verifies OFFLINE to `attested`, so R27's four online cases can be written

- **Status: RESOLVED — and the row's own problem statement is OVERTURNED at its
  root. R84 says the four online cases "cannot be written at all, on either
  surface". Measured, ALL FOUR ARE ALREADY WRITTEN AND GREEN**, twice: in
  `crates/antseal-core/src/verify/orchestration/tests.rs` under a section header
  that literally reads `// Accept row 2 — the mock-endpoint outcomes` (native
  **and** `wasm32-unknown-unknown`, because that lane runs this crate's `--lib`
  tests), and again in `crates/antseal-cli/tests/verify_command.rs`, whose
  disagreement row drives **two real loopback `StubServer`s** through the
  production collector `probe_online`. 22 CLI rows pass in 1.67 s. What is
  missing is not a case and not a surface — it is **the browser venue's
  fixture**, because `scripts/verifier-page-browser.mjs` receives bundles as
  **file paths** (`DOM.setFileInputFiles`), and no file on disk verifies to
  `attested`.
  **The fixture is MATERIALISED into `target/`, never committed** — the
  precedent is already in the tree and already argued, in
  `scripts/verifier-page-browser.sh`'s own header: *"a second binary copy of the
  same bundle committed under another name would be a second source of truth
  that agrees on the day it is written."*
  **Its material is real, and it is already committed and already frozen.**
  A25's calendar campaign stamped `3448b9f2…` and `083f87df…` — and
  `083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df` **is the
  `anchor_digest` of the F13 case `empty-anchor-unanchored`**, so the real
  merged-and-upgraded `.ots` already committed inside the **frozen** anchor
  vector (`ots-upgraded-offline`, 3 808 B, expected state `attested`) binds to
  that bundle's manifest **by construction and not by coincidence**. Measured,
  end to end: the rebuilt 4 846-byte bundle verifies to
  `anchor[0] state = Attested`, `plan.blocks = [960767]`, `unanchored = true`,
  `headline_eligible_count = 0`. The mocked endpoint responses are likewise
  **real captured bytes** — `testdata/anchors/A25-upgrade-headers/` holds
  blockstream's and mempool's answers for height 960767, and both are
  **byte-identical to the embedded header**.
  **ONE fixture serves all four cases**; they differ only in what the mock
  returns. **No freeze event of any class is incurred: nothing under
  `testdata/vectors/` is read-write, only read.** The `_at_m2` test is
  **untouched**, and §2 (b) shows why its suffix does not oblige a change.
  **The lean — arm (a), build around the A25-bootstrap upgraded `.ots` — is
  REFUSED on a mechanism**: that artifact stamps
  `6fd9c1c4f096b77e…`, the digest of a **third-party project's `LARGE_TEST`
  file**, and `anchor_digest` is SHA-256 over the bundle's own manifest
  envelope, so **no bundle can be built that it binds to**. The ruling is
  arm **(e)** for the venue and arm **(b)** for the material, which is a
  combination the brief's list did not contain.**
- **Date: 2026-08-14** (wave 20 planning round, D133 lane; briefed to overturn
  the lean rather than confirm it. The lean did not survive, and neither did
  the register's statement of the problem. Every claim below was executed —
  four cargo runs, a purpose-built probe crate outside the repository, and
  three subagent measurement lanes whose findings are quoted with their
  file:line.)
- **Owning task: R84.** Blocking **Q237** (the M3 gate). Consumers: **R27**
  (`Do` clause (d), Accept row 3), **R24** (Accept row 2), **R85** (the receipt
  twin's target, deferred here with reasons).
  Builds on **D127** (the real round-trip that produced the wave-17 material),
  **D128** (the freeze classes and the refused FIXTURE EVENT), **D105** (format
  events, and the fourth class it declined to design), **D94** (the verdict-event
  re-emit, and §5c's refusal of exactly the swap arm (d) proposes), **D96** (the
  precedent for synthesizing a fixture rather than committing one), **D92**
  (proven OTS anchor identity), **D101** (frozen vectors depending on unfrozen
  anchor material), **D132** (the probe plan), **A16/A18** (the must-agree core),
  **D56** rules O3–O9, **D64**, **D66**, **D79**.
  **Boundary: this record does not touch `testdata/vectors/` and does not
  reopen R85.**

---

## 1. What was measured

### (a) The four cases are already written, green, and on both targets

The premise of R84 — *"R27's `Do` clause (d) and its Accept row 3 … and R24's
Accept row 2 … cannot be written against committed data, on either surface"* —
is **false as stated**. Two independent suites already contain all four,
against an in-test constructor.

`crates/antseal-core/src/verify/orchestration/tests.rs`, under the section
header at `:269-271`:

```
// ─────────────────────────────────────────────────────────────────────
// Accept row 2 — the mock-endpoint outcomes
// ─────────────────────────────────────────────────────────────────────
```

| R24 Accept row 2 case | test | line |
| --- | --- | --- |
| agreement / promotion | `agreement_promotes_and_the_overlay_supplies_the_headline` | `:276` |
| disagreement | `disagreement_is_advisory_and_leaves_the_offline_verdict_untouched` | `:331` |
| one-endpoint-down | `endpoint_failures_never_promote_on_the_survivor` | `:381` |
| mismatch → invalid | `a_header_mismatch_refutes_and_climbs_the_rung` | `:440` |

All four call the *same* `attested_bundle()` at `:61`. That module's own doc
(`:1-8`) records the venue: *"the `wasm32-core-tests` lane runs this crate's
`--lib` tests on `wasm32-unknown-unknown`, so every row here runs natively **and**
in wasm32"* — and `scripts/wasm-tests.sh:52` is the command that does it,
`cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked`.

`crates/antseal-cli/tests/verify_command.rs` has the same four at the CLI
surface, and its disagreement row is stronger than a fixture host: it spawns
**two loopback `StubServer`s** answering `block-height/{H}` and
`block/{hash}/header` with different blocks, and drives
`antseal_cli::verify_host::probe_online` — *"the production collector … rather
than a fixture host, so the mapping from A16's `Agreement` onto D64's probe
classes is measured and not assumed"* (`:875-878`). Measured this session:

```
$ cargo test -p antseal-cli --test verify_command
test agreement_promotes_the_rung_from_unanchored_to_clean ... ok
test an_agreed_header_mismatch_climbs_to_anchor_refuted ... ok
test disagreeing_endpoints_render_the_advisory_and_move_nothing ... ok
test probe_failure_moves_neither_the_exit_code_nor_the_report_bytes ... ok
test result: ok. 22 passed; 0 failed; ... finished in 1.67s
```

**What is genuinely missing** is the venue R24 Accept row 2 names in its
parenthesis — *"(R27 playwright routes)"* — i.e. the **browser**. And the
browser needs a **file**: `scripts/verifier-page-browser.mjs:6` takes
`<page.html> [bundle.sealproof …]`, and `dropBundle` at `:139-150` calls
`DOM.setFileInputFiles({ files: [resolve(bundlePath)], nodeId })`. There is no
playwright anywhere in this repository — the driver is raw CDP over a
dependency-free WebSocket, by D129's ruling.

### (b) The `_at_m2` suffix — the brief's most important question, settled from git

`crates/antseal-core/tests/anchor_aggregate.rs:102`,
`vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2`.

The suffix is **deliberate, and it is a maintained convention** — it has
already been moved once. `git log -S` on the file returns exactly one commit,
`5f758de` (*"R12: the anchor stage is wired…"*), and its diff is a **rename**:

```
-fn vector_every_anchor_kind_bundle_is_all_absent_and_unanchored_at_m1() {
+fn vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2() {
```

with the old doc comment reading *"…bogus times cannot leak in; **A18 populates
real states at M2**"*. So the suffix names the milestone at which the assertion
was last re-measured, and a milestone-scoped claim in this tree gets renamed
when it moves. The sibling convention is
`the_unauthenticated_region_at_m0_is_exactly_the_storage_record`
(`tests/verify_fuzz.rs:230`).

**But the suffix does not oblige a change at M3, and the reason is in the
test's own doc comment.** The four anchors render `Invalid` because *"each a
schema-opaque placeholder the anchor stage cannot parse"* — a property of
**those committed bytes**, not of the milestone. The vector's own committed
`NON_SECRET` string says the same
(`crates/antseal-core/tests/bundle_vectors.rs:41-47`): *"All anchor artifact
bytes … are self-labelling SCHEMA-OPAQUE PLACEHOLDERS, not recorded
attestations; A swaps in real recorded fixtures at M2 with no schema change."*
That swap **did not happen**, and D94 §5c is the record of it being
**deliberately refused**. So the property is permanent for as long as the bytes
are placeholders, which is for as long as the freeze holds them.

There is a second, stronger reason to leave it alone. Its value is
**differential**: *"the bundle records four **different** sealer-claimed
statuses — `attested`, `pending`, `proven` and
`valid-at-stamping-cert-since-expired` … and the report renders one answer for
all four. A stage that believed the bundle's own `status` field would produce
four different states here and would be caught by this row alone."* Making one
of those four genuinely verify would put claim and state **in agreement** on
the very slot whose disagreement is the instrument. Arm (d) does not merely
cost frozen bytes — it **blunts the test it edits**.

**Ruling input: the `_at_m2` suffix is a dated re-measurement marker, not an
expiry. Nothing in this record renames or edits that test.**

### (c) The material for a real attested bundle is already committed, already frozen, and binds by construction

This is the finding that decides the record, and it was not in the brief.

`testdata/anchors/A25-bootstrap/OTS-BOOTSTRAP.md:26-29` records what A25's
consented campaign stamped:

| tag | digest | source vector |
| --- | --- | --- |
| A | `083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df` | `testdata/vectors/v1/manifest/manifest.json` |
| B | `3448b9f22d6d4de5b68e0c1ba28d56e8466aa5a01892835411f7c467b52e5e9c` | `testdata/vectors/v1/bundle/bundle.json` |

and describes them as *"Two `anchor_digest` values, both already committed
public golden-vector material"*. Measured against the F13 document, they are
exactly that:

```
empty-anchor-unanchored          -> anchor_digest 083f87df…69df   <- digest A
noncovered-unit-reveal           -> anchor_digest 3448b9f2…5e9c   <- digest B
every-anchor-kind-with-receipt   -> anchor_digest 3448b9f2…5e9c   <- digest B
every-anchor-kind-no-receipt     -> anchor_digest 3448b9f2…5e9c   <- digest B
nothing-revealed                 -> anchor_digest 3448b9f2…5e9c   <- digest B
```

(Four cases share digest B because `anchor_digest` covers **only the manifest**
— `anchor_digest(proof.anchor_digest_preimage())`,
`crates/antseal-core/src/verify/pipeline.rs:1124-1133` — and those four are
reveal-selections over one work.)

**The consequence is decisive: substituting a bundle's anchor section does not
move its `anchor_digest`.** So a real `.ots` stamped over digest A remains
bound to any bundle built from that manifest, however its anchors are rewritten.

And the real artifact exists, **inside a frozen vector**.
`testdata/vectors/v1/anchor/anchor.json` carries seven cases; case 3 is:

```
name        = ots-upgraded-offline
kind        = ots
provenance  = derived (not a file): testdata/anchors/A25-bootstrap/merged-A.ots
              spliced with upgraded/A-alice.upgrade, upgraded/A-bob.upgrade,
              upgraded/A-catallaxy.upgrade in that order by
              testdata/vectors/v1/anchor/gen_vectors.py; header from
              testdata/anchors/A25-upgrade-headers/esplora-blockstream-header-960767…
artifact    = 3 808 B, sha256 c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68
upgrade     = { block_height: 960767, block_header_hex: <160 hex>, fetch_date_unix: 1786098992 }
expect      = state "attested",  report_slot.state "attested"
```

and case 4, `ots-upgraded-online-proven`, is the **same artifact** promoted to
`proven` by the real header at 960767. `inputs.anchor_digest` for the whole
document is `083f87df…69df` — digest A.

Provenance chain, all committed, all offline-reachable:
`merged-A.ots` (664 B, 3 pending attestations)
→ spliced with `A25-bootstrap/upgraded/A-{alice,bob,catallaxy}.upgrade`
  (real Bitcoin attestations at heights **960767 / 960768 / 960771**, confirmed
  by scanning for the tag `05 88 96 0d 73 d7 19 01`: 1 each, 0 pendings)
→ the 3 808-byte upgraded artifact, via the **shipped** `merge_upgrade`
  (`crates/antseal-anchor/src/ots/upgrade.rs:358`).

Two further campaigns (`A25-wave16-cycle/`, `A25-wave17-cycle/`) hold six more
real Bitcoin-attested upgrade bodies each, over the same two digests. D127's
material is therefore **surplus**, not required — a point §2 (d) turns into a
refusal of arm (b)-as-stated.

### (d) The assembly, executed

Built in a throwaway crate outside the repository
(`scratchpad/attest-probe`, path-dependency on `antseal-core`, **default
features only** — no `test-vectors`, no `test-util`), from nothing but the two
committed vector documents:

```rust
let base   = hex(EMPTY_ANCHOR_UNANCHORED_BUNDLE_BYTES);   // F13, 936 B
let anchor = OtsAnchor::new(
    AnchorStatus::Attested,
    OpaqueBytes::from_vec(hex(OTS_UPGRADED_OFFLINE_ARTIFACT_HEX)),   // anchor vector, 3 808 B
    Some(OtsUpgrade::new(960_767, real_header_80, 1_786_098_992)),
)?;
let mut parts = BundleV1::decode(&base)?.into_parts();
parts.ots_anchors = vec![anchor];
let bytes = encode_bundle(&BundleV1::new(parts)?)?;
verify_bundle(&bytes, &VerifyOptions::new())?
```

Output:

```
bundle anchor_digest        = 083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df
rebuilt bundle bytes        = 4846
anchor[0] state             = Attested
unanchored                  = true
headline_eligible_count     = 0
plan.blocks                 = [960767]
```

Every clause of R84's Accept is satisfied by that one object: an anchor in
state `attested` **asserted by state, not by the bundle's claimed `status`**;
a non-empty `plan.blocks`; and — because `ProbePlan::from_bundle` is the wide
set — a fixture on which the wide and narrow sets can now be made to **differ**
by adding a second, non-attested upgraded anchor.

Note also what did **not** happen: `parts.ots_anchors` was replaced wholesale
and the manifest was never touched, so `anchor_digest` is the same 32 bytes
before and after. That is the mechanism, not a coincidence of this fixture.

### (e) The mocked endpoint responses are real captured bytes, and they agree

`testdata/anchors/A25-upgrade-headers/` (README: twelve requests, all `200`,
consented 2026-08-07, reads only). Measured:

```
blockstream  header == embedded header : True   (160 hex)   hash 64 hex
mempool      header == embedded header : True   (160 hex)   hash 64 hex
block hash (both) = 00000000000000000000553c93eb174557abe089e9c59a7e8f3eb7d116eb803e
```

Both endpoints answer **byte-identically**, and their answer **is** the header
embedded in the D79 upgrade group. The capture README already records the
offline verification: *"`double-SHA256(header)`, byte-reversed, equals the block
hash the height lookup returned"* and *"Both endpoints agree byte-for-byte."*

So the agreement/promotion route interception replays recorded reality:

```
GET **/block-height/960767                  -> 00000000…803e            (64 B)
GET **/block/00000000…803e/header           -> 00806d21…04cb38dd        (160 B)
```

### (f) One fixture, four cases — proved from the code, not assumed

`classify_probed_anchor` (`crates/antseal-core/src/verify/overlay.rs:686-749`)
takes the **online-augmented `AnchorOutcome`**, the height, and the probe-log
entry. Everything the bundle contributes is identical across the four; the
delta is entirely in what the endpoints return:

| case | both endpoints return | core sees | class |
| --- | --- | --- | --- |
| agreement / promotion | the embedded header | `Agreed(Some(h))` → O3 → `Proven` | `Promoted{time,height,source}` |
| mismatch → invalid | the **same wrong** header | `Agreed` → O6 → `Invalid` | `Refuted{code}` |
| disagreement | **different** headers | `Disagreed` → no evidence | `NotPromoted{Disagreed}` |
| one-endpoint-down | one fails | `Unavailable{failures}` → no evidence | `NotPromoted{EndpointFailures}` |

Confirmed by the four core tests all calling one `attested_bundle()`, and by
`must_agree` (`crates/antseal-anchor/src/agree.rs:217-234`), whose
`(Err, Ok)` arm is `Unavailable` — *"One endpoint's answer is not evidence."*

**Four preconditions the fixture must meet, and the measured fixture meets all
four** (`crates/antseal-core/src/anchor/verdicts.rs`):

1. `parse_ots` succeeds and **step 5** binds the start digest to the bundle's
   `anchor_digest` (`anchor/ots/mod.rs:156-172`).
2. A D79 upgrade group is present — without it `ots_refutation` returns at
   `let upgrade = view.upgrade()?;` (`verdicts.rs:943`) and the mismatch case
   is unreachable.
3. `committed == true`: the Bitcoin attestation's height equals
   `upgrade.block_height()` and its ops-derived root equals header bytes
   `36..68` (`anchor/ots/header.rs:136-146`). An **uncommitted** artifact is
   already `Invalid` offline via O8, so the mismatch case would pass with the
   online gate never having run — the exact trap `tamper_rows.rs:272-277` names.
4. **No evaluable pending sibling**: O5 out-ranks every refutation
   (`verdicts.rs:877-887`), so a pending branch renders `pending` and
   `NotPromoted{RefutationSuppressed}` instead. The measured artifact came back
   `Attested`, so it has none.

And the overlay gate itself (`overlay.rs:615-620`) skips any slot whose
**offline** state is not `Attested`. That single line is why R84 is a gate
blocker and why no synthetic-status bundle can substitute.

### (g) Ageing: the offline verdict path reads no clock

Exhaustive grep across `crates/`: **zero** `SystemTime::now` / `Utc::now` /
`Date.now` / `js_sys::Date` in `antseal-core/src/` or `antseal-wasm/src/`.
`antseal-wasm` does not even depend on `js-sys`/`web-sys`.

`evaluate_ots_artifact(view, anchor_digest, blocks)`
(`verdicts.rs:675-679`) **takes no verification time at all** — there is no
expression in the OTS path in which today's date can appear. No confirmation
depth, no maturity rule, no max-age. The block time is read out
(`verdicts.rs:811`) and never compared.

The one clock-sensitive path is TSA cert validity, and it is decided against
the token's own `genTime` (`anchor/chain.rs:849-874`), with `verify_at_unix` a
**parameter** that is *"one-sided, deliberately… **No path from `verify_at` to
`Invalid` exists**"*. The only production caller passing a clock is
`antseal-cli/src/commands.rs:604`; `VerifyOptions::new()` — which the page uses
(`antseal-wasm/src/api.rs:80-82`) and every `verify_bundle` test uses — leaves
it `None` → `0`.

**Verdict: a fixture built from a real 2026 OTS attestation and a real Bitcoin
header cannot rot.** It carries no TSA token, and the OTS evaluator is
time-independent by signature.

### (h) The freeze regime, and what it costs to touch it

Measured, and the numbers are unambiguous.

`testdata/vectors/v1/FROZEN.sha256` is a `sha256sum -c`-compatible list of
**14 whole-file digests**, status **`#! status frozen`** (Q14), pending set
empty. `scripts/vector-freeze.sh` covers `testdata/vectors` only;
`scripts/format-freeze.sh` covers `docs/format` and never touches `testdata/`.

Adding one case to a frozen document moves its digest, unconditionally
(computed in memory, no file written):

| file | frozen digest | with +1 case |
| --- | --- | --- |
| `bundle/bundle.json` | `5144eb89…abfde6` | `6e175c56…3005b5` — moved |
| `report/verification-reports.json` | `a6269eb6…d61cd4` | `43c03d23…a3575f` — moved |

The three event classes are `testdata/vectors/README.md:468-470` — FORMAT,
VERDICT, FIXTURE — and the one post-freeze escape, `--verdict-event <Dnn>`, is
**path-scoped**: `vector-freeze.sh:119-122` fails if the path is not under
`/report/`. So for `bundle/bundle.json` the escape is not merely refused, it is
**unreachable**. D105 §5.1 named this exactly: *"It is not a FORMAT EVENT … and
not a FIXTURE EVENT … **There is no class for it.** This is not cost — it is a
red gate with no key."*

And the D128 "fourth freeze class" the brief asks about is **not** FIXTURE
EVENT. FIXTURE EVENT is the *third* class and is fully specified. D128 §2.1
declined to *pay* it, measuring the blast radius at **3 of 14 frozen files, 37
of their 47 cases, all 26 R30 rows**, the F14 Python sidecars, the fuzz seed
corpus, and a content locator in `verify_fuzz.rs`. The genuinely undesigned
fourth class is *adding a case to a frozen report document*, which D105 §10
declined and D128 §2.2 declined again: *"Designing a class whose sole member is
a change that has a free alternative is the 'designing a class to admit one
change is how freeze discipline dies' case in its purest form."*

**Whether this record is a FIXTURE EVENT: it is not, because it moves no frozen
byte.** It reads two frozen documents and writes to `target/`.

### (i) The page's fixture policy is already ruled, in the script that needs it

`scripts/verifier-page-browser.sh:12-19`, verbatim:

```
# ── The fixture is MATERIALISED, not committed ─────────────────────────────
#
# `testdata/vectors/v1/bundle/bundle.json` already carries canonical bundle
# bytes as hex (F13's golden vectors), so a second binary copy of the same
# bundle committed under another name would be a second source of truth that
# agrees on the day it is written. The bundle this drives is decoded from that
# vector into `target/`, which also means the browser arm is exercising the
# same bytes the native and wasm boundary arms do.
```

`materialise()` (`:51-64`) loops over **every** case in the F13 document and
writes `target/verifier-web-fixtures/<name>.sealproof`; the driver is handed
all of them. That is the venue, the naming, and the argument — already
committed, already green, and directly on point.

---

## 2. The lean, dismantled

The brief's lean was arm **(a)**: build the fixture around the existing
A25-bootstrap upgraded `.ots`. It fails on a mechanism, and the three
alternatives it was offered against fail or half-fail for reasons the brief did
not have.

**(a) is impossible, not merely unattractive.** The A25-bootstrap upgraded
`.ots` the brief means — the one artifact the register says *"does reach
`Attested`"* — is
`testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots`,
driven there by `row_5_attested_not_headline`
(`anchor/testing/tamper_rows.rs:309-336`). It stamps
`DIGEST_UPGRADED_LARGE_TEST = 6fd9c1c4f096b77e6d4457bac1c7f51010d318db483f2868d3795843f098d378`
(`anchor/testing/ots_writer.rs:60-63`) — the digest of the `LARGE_TEST` constant
from the third-party `opentimestamps-0.2.0` crate. A bundle's `anchor_digest` is
SHA-256 over **its own manifest envelope**; it cannot be chosen. So there is no
bundle this artifact binds to, `parse_ots` step 5 returns
`anchor-ots-digest-mismatch`, and the slot renders `Invalid` — the wrong state
*and* the wrong code, with no overlay row at all. **Arm (a) cannot be built.**
Its upgrade group is also *"synthesized around the artifact's real derived
root… the surrounding 48 bytes are filler, because no fetched mainnet header
for these heights is in the tree"* (`ots_writer.rs:221-226`) — so even if the
digest bound, its header could never be replayed from a recorded endpoint
response.

The register's note that *"the material for one already exists in the tree"* is
right; it just points at the wrong artifact. The material is the **A25-bootstrap
`merged-A.ots` + `A-*.upgrade`** chain, and it is already assembled and
committed inside the anchor vector.

**(b) is right about the material and wrong about the artifacts.** The brief
nominates D127's six wave-17 `.upgrade` files. Measured, those are **not `.ots`
containers**: they begin `08f120…` (ops), not the 31-byte OTS magic — the
`OTS-BOOTSTRAP.md` says so of the whole class, *"they are the calendar's
serialized timestamp ops, not complete `.ots` files"*. Using them means running
`merge_upgrade` against a pending container, which is exactly what
`testdata/vectors/v1/anchor/gen_vectors.py` **already did**, whose output is
**already committed and frozen**, and whose expected state is **already pinned
at `attested`**. Re-deriving from D127's wave-17 set would produce a *second*
upgraded artifact where a frozen one exists — the "second source of truth"
`verifier-page-browser.sh` refuses. So: **adopt (b)'s material, take it from the
frozen vector, and leave D127's captures as the redundancy they were meant to
be.** The brief's two worries about (b) both dissolve on measurement — the
timestamps cannot age (§1 g), and the block header does not have to be
*matched* by a mocked endpoint because the real endpoint responses are
themselves committed (§1 e).

**(c) is refused as the page fixture's material, and must NOT be applied
backwards.** Deterministic synthesis is available — `ots_writer::container`,
`bitcoin`, `header_with` — and it is what the four existing green cases use.
That is correct where it is: those are unit tests over the machine, they run on
wasm32, and a synthetic zero-op container is the *only* way to get shapes no
capture contains (`ots_writer.rs:1-14`, task A82). But for the fixture a
**browser** drops through a file picker to demonstrate the product's online
mode, synthesis buys nothing that real material does not already give free, and
it gives up the one thing this fixture can uniquely provide: an end-to-end path
in which *every* byte — artifact, header, block hash — was recorded from
mainnet. `ots_writer.rs:258-260` also warns that a zero-op container means
*"forging one costs no mining at all"*, which is a fine property for a unit test
and a poor one for the artifact that demonstrates the claim. **Nothing in this
record rewrites the existing synthetic constructors.**

**(d) is refused three times over.** It moves `bundle_bytes` in
`bundle/bundle.json` → FIXTURE EVENT, whose blast radius D128 §1.8 measured at
3 files / 37 cases / 26 R30 rows; **D94 §5c already refused precisely this
swap** (*"swap the report fixture's synthetic anchor bytes for real A25
material… for zero gain"*); and, uniquely among the arms, it **damages the test
it edits**, because that test's power is the disagreement between claimed
status and rendered state (§1 b). The brief asks whether this is *"what the
`_at_m2` suffix anticipates"* — it is not: the suffix marks a re-measurement,
and the vector's own `NON_SECRET` line predicted a swap that D94 then declined,
on the record, with reasons that have not changed.

**(e) is right, and the brief under-sold it.** The brief asks what would be
*lost* — in particular whether R27's parity assertion needs the fixture to be
one the CLI and native side verify *from the same committed bytes*. Measured:
**no.** Parity needs **one file**, not one *committed* file. The existing
browser lane already materialises into `target/verifier-web-fixtures/` and
already says why. R27's CLI arm reads the same path; the bytes are identical
because there is one emitter. What is genuinely given up by not committing is
D105 §5.5's honest list — *"no retention guarantee, no freeze manifest line,
and no `wasm-bitmatch` transcript entry"* — and none of the three is what this
fixture is for. Format stability over time is R9/F13/R28's job, discharged by
21 report vectors and 10 bundle vectors that this fixture does not replace.

**The shape the brief's list did not contain, and which wins:** the venue of
(e) with the material of (b), sourced from **frozen** vectors so the emitter has
no independent bytes of its own. It incurs no freeze event, ages not at all,
requires no network and no consent, and is stronger evidence than any of the
four arms as posed — because the artifact, the header and the block hash were
all recorded from mainnet and are all already under CI.

---

## 3. The ruling

**R1 — R84's problem statement is corrected on the record.** The four cases are
written and green on both library surfaces and on both targets (§1 a). R84's
scope is **the browser venue's fixture**, and its title should be read as *"no
bundle **file** verifies to `attested`, so R27's browser cases cannot be
written"*. The registrar's entry note in §9 carries the correction.

**R2 — The attested fixture is MATERIALISED into `target/`, never committed.**
It is written to `target/verifier-web-fixtures/`, beside the ten cases
`scripts/verifier-page-browser.sh::materialise()` already writes there. No file
is added under `testdata/`. `.gitignore` is not edited — `/target` at
`.gitignore:8` already covers it, exactly as D131 §3 ruled for the built page.

**R3 — Its material is the two frozen vectors, and nothing else.** The emitter
reads:

- **base bundle** — `testdata/vectors/v1/bundle/bundle.json`, case
  **`empty-anchor-unanchored`**, field `bundle_bytes` (936 B). Chosen because
  its `anchor_digest` is **digest A**, `083f87df…69df`, and because its anchor
  sections are empty so the substitution is a fill and not an overwrite.
- **OTS artifact** — `testdata/vectors/v1/anchor/anchor.json`,
  `inputs.cases[]` where `name == "ots-upgraded-offline"`, field
  `artifact_hex` (3 808 B, sha256 `c2bf8b2c…0c68`).
- **upgrade group** — the same case's `upgrade` object:
  `block_height = 960767`, `block_header_hex` (160 hex → 80 B),
  `fetch_date_unix = 1786098992`.

Both files are read-only inputs. **Neither is modified. `FROZEN.sha256` does not
move. `INDEX.json` does not move. No `--update`, no `--verdict-event`, no D87
budget line.**

**R4 — The assembly is exactly this, and it is public API only.**

```rust
let mut parts = BundleV1::decode(&base_bundle_bytes)?.into_parts();
parts.ots_anchors = vec![OtsAnchor::new(
    AnchorStatus::Attested,
    OpaqueBytes::from_vec(artifact_bytes),
    Some(OtsUpgrade::new(960_767, header_80, 1_786_098_992)),
)?];
let bytes = encode_bundle(&BundleV1::new(parts)?)?;   // 4 846 B
```

`tsa_anchors` stays empty and `receipt` stays `None`. The manifest is **not
touched**, which is what keeps `anchor_digest` at `083f87df…69df` and the
artifact bound. Re-encoding through `encode_bundle` re-runs the tier-`[X]`
layer-1 rules, as `orchestration/tests.rs:10-13` requires of every fixture.

**R5 — One fixture, one name.** The file is
`target/verifier-web-fixtures/attested-ots-960767.sealproof`. **One fixture
serves all four cases** (§1 f); four fixtures are refused. The name states the
state and the height, so a route interception and the file it belongs to cannot
drift silently.

**R6 — The emitter is an env-gated `vector_`-marked test in `antseal-core`, in
the house pattern.** The precedent is `ANTSEAL_BLESS_VECTORS=1` in
`crates/antseal-core/tests/bundle_vectors.rs` and
`tests/content_model_vectors.rs` — *"the only sanctioned way to regenerate"*.

- Home: `crates/antseal-core/tests/page_fixtures.rs`, new file.
- Without the variable it **only asserts**: build the bundle, assert
  `report.anchors[0].state == AnchorState::Attested`, assert
  `ProbePlan::from_bundle(...).blocks == vec![960767]`. This runs in every
  `cargo test` and is the row that goes red if the format moves under the
  fixture.
- With `ANTSEAL_EMIT_PAGE_FIXTURES=<dir>` it additionally writes the
  `.sealproof`. It is `#![cfg(not(target_arch = "wasm32"))]` because it reads
  files from disk, matching `tests/anchor_aggregate.rs:12`.
- The test name carries the reserved `vector_` marker so the three `cross-os-*`
  lanes run it (CONTRIBUTING.md).

**R7 — `scripts/verifier-page-browser.sh::materialise()` gains one step, before
its existing Python block.** It runs the emitter with
`ANTSEAL_EMIT_PAGE_FIXTURES="$FIXTURES"`, then decodes the ten F13 cases as it
does today. ~~The `ls "$FIXTURES"/*.sealproof` glob at `:71` then picks the new
file up with **no further change**.~~ The glob picks the new files up, and **an
explicit per-fixture existence check is required beside it** — the glob cannot
fail, so a fixture that never arrived leaves `ls` returning the others and the
lane green over less than it claims. The script's `# ── The fixture is
MATERIALISED, not committed ──` header gains one sentence naming the eleventh
**and twelfth** fixtures and their two frozen sources, so the next reader finds
the reasoning at the site. — **Corrected 2026-08-15 by the R84 lane** (two
fixtures, per this record's own **R11**, and a glob that cannot fail); see
"Correction — R7's fixture count and its glob, and R11's inertness assertion,
2026-08-15" below.

**R8 — The mocked endpoint responses are the committed real captures, replayed
verbatim.** From `testdata/anchors/A25-upgrade-headers/`, for height 960767:

| route | body | source file |
| --- | --- | --- |
| `**/block-height/960767` | `00000000000000000000553c93eb174557abe089e9c59a7e8f3eb7d116eb803e` | `esplora-{blockstream,mempool}-height-960767.txt` |
| `**/block/00000000…803e/header` | the 160-hex header | `esplora-{blockstream,mempool}-header-960767.txt` |

Both endpoints' files are byte-identical (measured), so the *agreement* case
serves both routes the same body. The other three cases perturb the **response
only**, never the fixture:

| case | perturbation |
| --- | --- |
| agreement → promotion | both endpoints replay the captures above |
| mismatch → invalid | **both** endpoints return the header for **960768** (also captured, also real) — an agreed header that is not the embedded one |
| disagreement | endpoint 1 replays 960767's header, endpoint 2 returns 960768's |
| one-endpoint-down | endpoint 1 replays the captures; endpoint 2 fails the request |

Using a **real** header from a **different real block** for the mismatch case is
deliberate: it exercises O6 with bytes an attacker could actually produce,
rather than a `0xEE`-filled synthetic, and it needs no new capture.

**R9 — The receipt-bearing twin is DEFERRED, and this is a scope reduction of
R84's Accept.** R84 asks for *"a receipt-bearing twin"* and to decide *"what the
receipt twin's transaction hash points at, given R85"*. That question is
**R85's**, and it is open: R85 measured that the page pins chain id 42161, that
no document it can see carries a network datum, and that an off-mainnet receipt
is therefore **affirmatively refuted** rather than left unconfirmed. Minting a
fixture whose `tx_hash` points at nothing would commit a demonstration of that
defect and would need re-doing the moment R85 rules. **None of R27's four block
cases needs a receipt** (§1 f). The twin is therefore not built here; it is
built by whichever row implements R85's ruling, from the same emitter, by adding
a `receipt` to `parts`. R84's Accept is amended accordingly in §9.

**R10 — Nothing in `testdata/vectors/` is edited, and no existing test changes
its assertions.** Specifically and by name:

- `crates/antseal-core/tests/anchor_aggregate.rs:102`,
  `vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2` —
  **unchanged, not renamed** (§1 b, §2 d).
- `crates/antseal-core/src/verify/orchestration/tests.rs` — the four
  `attested_bundle()` cases stay synthetic and stay where they are (§2 c).
- `crates/antseal-cli/tests/verify_command.rs` — unchanged.
- `crates/antseal-core/src/verify/plan.rs`,
  `an_upgraded_ots_anchor_puts_its_height_in_the_plan_whatever_its_verdict` —
  unchanged; it is the *wide-set* row over an offline-**invalid** anchor and
  keeps its meaning.

The only additions are `tests/page_fixtures.rs` and the `materialise()` step.

**R11 — The wide-versus-narrow witness R84 asks for gets a second fixture, and
it is one line.** R84's Accept row 2 wants *"a case where the two differ, so
D132 §1 (c)'s inertness has a witness in committed data and not only in
argument"*. Emit a **second** file,
`attested-plus-invalid-ots.sealproof`, identical to the first plus a **second**
`OtsAnchor` carrying the F13 placeholder `.ots` bytes and an upgrade group at
height **960768**. Measured consequence: `plan.blocks == [960767, 960768]`
(wide) while the overlay produces **one** row (narrow, because the second
anchor's offline state is not `Attested`, per `overlay.rs:615-620`). That is the
difference, exhibited. ~~The assertion that it is **inert** is the byte-equality
of report, overlay and verdict-class across the two fixtures.~~ — **Corrected
2026-08-15 by the R84 lane: byte-equality across the two fixtures is
impossible**, because the second carries an extra anchor and its report
therefore carries two anchor slots against one. What is asserted instead, and
is true: the **narrow** set is one row on **both** fixtures while the **wide**
set names one height against two — which is what makes the second fixture a
witness to the *difference* rather than to a second anchor. See "Correction —
R7's fixture count and its glob, and R11's inertness assertion, 2026-08-15"
below.

**R12 — The classification of this record, stated so it is not rediscovered:
NOT a format event, NOT a verdict event, NOT a fixture event.** It moves zero
frozen digests. `./scripts/vector-freeze.sh` must be **green without
`--update`** after the change, and that is the check that proves the
classification. Anyone who finds themselves reaching for `--update` has left
this ruling.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| **(a)** Build the fixture around `A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` | **Impossible, not costly.** It stamps `6fd9c1c4…d378`, the digest of a third-party crate's `LARGE_TEST` file. `anchor_digest` is SHA-256 over the bundle's own manifest envelope and cannot be chosen, so no bundle binds to it: `parse_ots` step 5 → `anchor-ots-digest-mismatch` → `Invalid` → no overlay row. Its upgrade group's 48 non-root header bytes are filler (`ots_writer.rs:221-226`), so it could never be replayed from a recorded endpoint response either |
| **(b)** as stated — derive a new upgraded artifact from D127's six wave-17 `.upgrade` files | The `.upgrade` files are **ops bodies, not `.ots` containers** (measured: they begin `08f120…`, not the 31-byte magic). Merging them reproduces work `testdata/vectors/v1/anchor/gen_vectors.py` has already done and whose output is already **frozen** with `state: attested`. A second upgraded artifact beside a frozen one is the "second source of truth" `verifier-page-browser.sh:12-19` refuses. **Its material is adopted; its re-derivation is not** |
| **(c)** Synthesize the attested OTS deterministically for the page fixture | Buys nothing real material does not give free, and gives up an end-to-end mainnet-recorded path. `ots_writer.rs:258-260` notes a zero-op container is forgeable with no mining — acceptable in a unit test, poor in the artifact that demonstrates the product claim. **Not applied backwards**: the existing synthetic constructors are correct where they are and stay |
| **(d)** Edit `every-anchor-kind-*` so one anchor verifies `attested` | Three refusals. It is a **FIXTURE EVENT** (D128 §1.8: 3 of 14 files, 37 of 47 cases, 26 R30 rows, F14 sidecars, fuzz corpus); **D94 §5c already refused this exact swap**; and it **blunts the instrument** — the test's power is claim-vs-state disagreement, and this puts them in agreement on the graded slot |
| Add a **new case** to `testdata/vectors/v1/bundle/bundle.json` | D105 §5.1's *"a red gate with no key"*. The digest moves (measured `5144eb89…` → `6e175c56…`); `--update` refuses under `status frozen`; `--verdict-event` is **unreachable by path** (`vector-freeze.sh:119-122` scopes it to `/report/`). No class exists |
| Add a **new bundle-kind vector file** carrying only the attested case | `require_shape_coverage` is **per-file** (`vectors_bundle.rs:36-42`): *"a second file would have to satisfy the whole F13 coverage list on its own, and each half would then silently under-claim"* |
| Mint a **new vector kind** for it | Legal as an append, and refused on cost for the same reason D105 declined Route D: `#! kind` line, digest lines, executor arm, `KNOWN_KINDS`, README row, `INDEX.json`, `wasm-bitmatch` budget — full vector ceremony for an artifact whose purpose is a browser parity gate, not format stability |
| **Commit** the emitted `.sealproof` under `testdata/` | `scripts/verifier-page-browser.sh:12-19`, already ruled and already argued: a second binary copy *"agrees on the day it is written"*. D131 §3's committed-artifact hazard, one level out |
| Four separate fixtures, one per case | The four differ only in mocked responses (§1 f); `classify_probed_anchor` reads the online-augmented outcome and the probe log, never a second bundle. Four fixtures would let three of them drift |
| Ship the **receipt twin** in this record | Its `tx_hash` target is exactly what **R85** leaves open, and no block case needs it (**R9**) |
| Rename or re-scope `..._at_m2` | The suffix is a dated re-measurement marker, not an expiry; the all-`invalid` property belongs to the placeholder bytes, not the milestone (§1 b) |
| Run a **new calendar campaign** to stamp a fixture's digest | Unnecessary — A25 already stamped `083f87df…69df` and `3448b9f2…5e9c`, both of which **are** committed bundle `anchor_digest`s — and it would need in-the-moment maintainer consent plus a multi-hour Bitcoin wait for material the tree already holds three times over |

---

## 5. What R84 / R27 / R24 / Q237 must implement

### 5.1 R84 — the row, reduced to four concrete acts

1. **`crates/antseal-core/tests/page_fixtures.rs`** (new). Reads the two frozen
   vector documents; builds the bundle per **R4**; asserts
   `state == AnchorState::Attested` **by state, not by `status`**, and
   `plan.blocks == vec![960_767]`. `#![cfg(not(target_arch = "wasm32"))]`.
   Test names carry the `vector_` marker.
2. **The negative control R84's Accept demands — and it is already measured.**
   Assert that the *unmodified* `empty-anchor-unanchored` bundle yields
   `report.anchors.is_empty()`, and that substituting the **`ots-wrong-seal`**
   artifact from the same anchor vector (`inputs.cases[6]`, stamped over digest
   **B**, expected `invalid`) yields `AnchorState::Invalid`. Executed this
   session, same assembly, only the artifact swapped:

   ```
   anchor[0] state             = Invalid
   plan.blocks                 = [960767]
   ```

   That is a real negative control from committed material — the assertion goes
   red for the right reason (`anchor-ots-digest-mismatch`), not by absence. It
   also **exhibits D132's wide set for free**: the plan still names 960767 with
   the anchor offline-`Invalid`, which is
   `an_upgraded_ots_anchor_puts_its_height_in_the_plan_whatever_its_verdict`
   holding on real material rather than on placeholders.
3. **The emitter arm**, gated on `ANTSEAL_EMIT_PAGE_FIXTURES=<dir>`, writing
   `attested-ots-960767.sealproof` and `attested-plus-invalid-ots.sealproof`
   (**R11**).
4. **`scripts/verifier-page-browser.sh`** — one emitter call at the head of
   `materialise()`, plus the header sentence (**R7**).

**Do not**: touch `testdata/vectors/`, run `vector-freeze.sh --update`, edit
`FROZEN.sha256` or `INDEX.json`, or add a file under `testdata/`.

**Green condition**: `./scripts/vector-freeze.sh` passes with **no** `--update`,
and `git status` shows no change under `testdata/`.

### 5.2 R27 — what it can now write, and the one thing it must build

The four browser cases become writable the moment the fixture materialises.
`scripts/verifier-page-browser.mjs` already runs `Network.enable`; route
interception is `Fetch.enable` + `Fetch.requestPaused` + `Fetch.fulfillRequest`
/ `Fetch.failRequest` over the **same** CDP session — no new dependency, no
playwright, consistent with D129's dependency-free driver.

Per **D132**, route off `verify_rendered(b).plan`, never off a hard-coded
height, so fixture and intercepts cannot drift. For this fixture
`plan.blocks == [960767]`.

| case | intercept | assert |
| --- | --- | --- |
| agreement → promotion | both endpoints fulfilled from the 960767 captures | overlay row `Promoted`; headline attribution line carries `wording::ONLINE_ATTRIBUTION_MARKER`; **offline block byte-identical** to the pre-activation render (D64 §2) |
| mismatch → invalid | both fulfilled with 960768's header | overlay row `Refuted` with code `anchor-ots-online-header-mismatch`; report bytes unmoved |
| disagreement | endpoint 1 → 960767's header, endpoint 2 → 960768's | overlay row `NotPromoted{Disagreed}`; verdict and report bytes equal the offline run's |
| one-endpoint-down | endpoint 1 fulfilled, endpoint 2 `Fetch.failRequest` | overlay row `NotPromoted{EndpointFailures}`; **never** a promotion on the survivor (D66) |

Two riders that already exist and now bite:

- **D132's parity warning stands and is not discharged by any of this.** Both
  surfaces derive the probe set from one function, so a defect in
  `ProbePlan::from_bundle` is invisible to a rendering-comparison gate. The
  core equality row is the only instrument that can see it and must be
  red-capable.
- **D130 §7.3 (i)**: the parity comparison over this fixture is safe —
  it is not a hostile-path fixture, so `redaction.files[].header_line` needs no
  exclusion.

**The zero-fetch row D132 asked for is unchanged and still cheap**: an online
confirmation over any of the ten existing R9 fixtures makes zero fetches and
still renders the overlay. Keep it — it is the proof the plan-driven path
invents no work, and it now has a non-empty counterpart.

### 5.3 R24 — Accept row 2

Row 2 reads *"Mocked-endpoint tests (R27 playwright routes): agreement/promotion,
disagreement, mismatch→invalid, one-endpoint-down"*. It is satisfied when R27's
four browser cases above are green. The library halves are **already** green and
should be cited on the row rather than rebuilt — the registrar's note in §9
says so, because a lane that reads *"unwritable on either surface"* will
otherwise write them a third time.

### 5.4 Q237 — the M3 gate

The gate's clause list names the endpoint-disagreement case **on both surfaces**.
After R84 and R27's clause (d):

- **CLI surface**: `disagreeing_endpoints_render_the_advisory_and_move_nothing`
  (already green, real `StubServer` pair).
- **Page surface**: R27's disagreement case above.

The blocker clears when `scripts/verifier-page-browser.sh --check` is green with
the four intercept cases in it. Note the venue caveat D131's registrar note
already records: that script is **not** in `scripts/local-gate.sh` — it runs
from `.github/workflows/verifier-page.yml`, and Q19 is `workflow_dispatch` only
and not a required context. **Q237 must state which machine ran the browser
arm**, or the gate will be satisfied by a lane nobody executed. That is R82's
shape (heavy-features local-only) recurring on a second lane, and it should not
be discovered a third time.

---

## 6. Spec conformance

- **MVP-SPEC.md line 174** (Verification — the M3 bullet) — the end-to-end suite
  gains the anchor-state class it could not previously reach. D129 §10 (iii)
  recorded that the R9 corpus exercises exactly one class and that the richer
  states arrive at R27; this record supplies them without disturbing the corpus
  that pins the format.
- **Line 108** (`--online` semantics) — promotion is defined off the `attested`
  state and requires two agreeing endpoints; the fixture is the first committed
  material on which the page can demonstrate it. Nothing here changes the
  semantics.
- **Line 137** (verifier web page, online mode, *"two public Arbitrum RPCs"*) —
  untouched. The receipt half is deferred to R85 (**R9**), and R24 already
  discloses four endpoints regardless of whether a receipt is probed
  (D132 §5 R5).
- **Line 156** (M3 milestone) — R84 stops being a gate blocker.
- **Line 167** (vectors retained forever) — **strengthened by omission**: the
  frozen corpus is read, never written, so every retention guarantee stands
  exactly as Q14 froze it.
- **Project rule 3** (*every timestamp comes from independent anchors; Autonomi
  is never trusted for time*) — the fixture's time comes from a Bitcoin block
  header agreed by two independent esplora endpoints, and `attested` is
  **not headline-eligible** offline (measured: `headline_eligible_count = 0`),
  which is D56 rule O4 holding at the bundle surface.
- **Project rule 4** (`.sealproof` bundles verify offline) — the fixture
  verifies with `VerifyOptions::new()` and no host; the emitter needs no
  network; the browser case that proves zero fetches is unchanged.
- **Project rule 6** (no secret material in fixtures) — inherited. Both source
  documents carry the `non_secret` declaration, the digests are *"already
  committed public golden-vector material"*, and the block header is public
  consensus data. The emitted file is a re-encoding of bytes already committed.

---

## 7. Residual risk

1. **Ageing: none, and this is measured rather than hoped.** The OTS evaluator
   takes no verification time as a parameter (§1 g), so no expression exists in
   which today's date could appear. The fixture carries **no TSA token**, which
   is the only artifact class in this tree with any date sensitivity at all —
   and even there the effect is a cosmetic relabel to
   `valid-at-stamping-cert-since-expired`, never `Invalid`
   (`anchor/chain.rs:91-93`). **Do not add a TSA anchor to this fixture**
   without re-reading that; a real TSA token asserted through the *binary* (as
   opposed to `verify_bundle`) is the one construction in this project that
   could rot, and it does not exist today.
2. **The fixture is not retained and not frozen.** By construction (**R2**), it
   has no `FROZEN.sha256` line and no retention guarantee — D105 §5.5's honest
   price. Mitigation: the emitter's assertion arm runs in every `cargo test`, so
   a format change that broke the fixture goes red immediately rather than at
   the next browser run. What is genuinely unprotected is *historical* format
   compatibility for this shape, and that is R28's job over the frozen corpus,
   not this fixture's.
3. **A silent dependency on two frozen documents' internal structure.** The
   emitter reads `expect.cases[name=…].bundle_bytes` and
   `inputs.cases[name=…].{artifact_hex,upgrade}`. A re-emit that renamed a case
   would break it. Mitigation: the emitter must fail with a message naming the
   missing case and the file, in the style of
   `anchor_aggregate.rs:44` (*"case `{case_name}` present in the committed
   document"*), never `unwrap()`.
4. **Block 960767 is a real block and its header is now load-bearing in a
   test.** It cannot change — it is 45 000 blocks deep — but a reader may
   mistake a recorded response for a live one. Mitigation: the intercepts must
   carry a comment naming
   `testdata/anchors/A25-upgrade-headers/README.md` as the source, and the R27
   browser row must keep the zero-network assertion so a fixture that
   accidentally reached the network is caught by the instrument that already
   exists.
5. **The mismatch case uses a real header from block 960768.** If a later lane
   adds a *second* attested anchor at 960768 (R11 adds an **invalid** one), the
   mismatch case's "wrong" header becomes that anchor's "right" one. Mitigation:
   R11's second anchor is deliberately the placeholder artifact — offline
   `Invalid` — so no promotion can occur at 960768; and the emitter should
   assert that no *attested* anchor in either fixture carries height 960768.
6. **Q237's venue, restated because it is the live one.** The browser lane is
   not in `local-gate.sh` and Q19 is not a required context. A green local gate
   is **not** evidence for R27's clause (d). This is the same class as R82 and
   R83, and the gate row must say which machine ran it.
7. **`ProbePlan::from_bundle`'s wide set now has a witness, not a proof.** R11
   exhibits the difference and asserts the inertness on **one** fixture pair.
   D132 §1 (c)'s general claim remains a construction argument. That is an
   improvement over "argument only" and should not be over-claimed as
   "measured in general".

---

## 8. Discovered work — described, not registered

*(No ids minted. Descriptions only, for the registrar.)*

1. **The freeze's addition check is one-directional, and layer 1 is blind to
   it.** `scripts/vector-freeze.sh`'s `check_digests()` pipes the manifest's
   lines through `sha256sum -c` and **never enumerates the directory** — a
   `*.json` dropped under `testdata/vectors/v1/` that is not in
   `FROZEN.sha256` leaves layer 1 **green** over 14 of 33 files.
   `scripts/format-freeze.sh:126-137` has exactly the reverse-direction check
   that `vector-freeze.sh` lacks. Three `cargo test` rows do catch it
   (`vector_freeze.rs:255-266`, `vector_index.rs:258-269`, the runner's
   unclassifiable-file rule), so the hole is covered — but the script that
   *names itself* the freeze cannot see an unfrozen addition, and its
   `--self-test` has no arm for one because it picks its victim from the
   manifest rather than from a walk. Worth either a reverse check or a comment
   at the site saying which layer owns it.
2. **D128 §1.9's "fourth freeze class" is still undesigned, and this record
   walked right up to it.** D133 avoids it by not adding a case. The next
   attested-fixture-shaped need may not have a frozen source to read from, and
   will meet D105 §5.1's *"red gate with no key"* head-on. Worth recording that
   two decisions have now declined to design it and a third has routed around
   it.
3. **`ots-upgraded-online-proven` proves promotion at the artifact layer, and
   nothing proves it at the bundle layer from committed material.** After D133
   the bundle-layer path exists but is exercised only in the browser lane. A
   cheap native row — the emitted fixture plus the two captured headers through
   `verify_with_host` — would put a real-material promotion under `cargo test`
   where `local-gate.sh` can see it. This is the single highest-value follow-on
   and it costs one test.
4. **`row_5_attested_not_headline` is the only thing reading
   `rust-opentimestamps-LARGE_TEST.ots`, and its upgrade group's 48 non-root
   header bytes are filler.** Now that real mainnet headers for this project's
   *own* attestations are committed
   (`A25-upgrade-headers/`), that row could be re-pointed at
   `merged-A.ots`-derived material and stop depending on a third-party crate's
   test constant. Not urgent; the row is honest about what it is.
5. **The `_at_m2` suffix convention is undocumented.** Two tests carry a
   milestone suffix, one has already been renamed once, and nothing in
   `CONTRIBUTING.md` says what the suffix means or when a lane is obliged to
   move it. This brief spent its first measurement establishing it from `git
   log -S`. One sentence in CONTRIBUTING.md would retire that cost permanently.
6. **`verifier-page-browser.mjs` asserts only `RESULT`/`FAILURE`/`TIMEOUT` per
   bundle.** It does not yet compare rendered strings against the CLI, which is
   R27's parity gate. Noted so nobody reads the current green as parity.
7. **The wave-16 and wave-17 upgrade campaigns are, on this evidence, surplus
   to any committed test.** Twelve real Bitcoin-attested bodies over the two
   digests exist beyond the bootstrap set that the frozen anchor vector
   consumes. That is fine — D127's purpose was the round-trip, and
   `testdata/anchors/README.md` calls captures append-only — but a reader may
   look for their consumer and find none. Worth a line in
   `testdata/anchors/README.md` saying they are corroboration, not inputs.

---

## 9. Quoted entry notes (registrar's to apply)

**On R84** (`tasks/R.md` and the `TODO.md` row) —

> **[D133, 2026-08-14]** Ruled, and **the row's problem statement is overturned
> at its root**. *"R27's four online cases and R24's Accept row 2 cannot be
> written at all, on either surface"* is **false as measured**: all four are
> already written and green in
> `crates/antseal-core/src/verify/orchestration/tests.rs`, under a section
> header reading `// Accept row 2 — the mock-endpoint outcomes`, on native
> **and** `wasm32-unknown-unknown`; and again in
> `crates/antseal-cli/tests/verify_command.rs`, whose disagreement row drives
> **two real loopback `StubServer`s** through the production collector
> `probe_online` (22 rows, green, 1.67 s). What is missing is the **browser
> venue's fixture** — `scripts/verifier-page-browser.mjs` takes bundles as
> **file paths** via `DOM.setFileInputFiles`, and no file on disk verifies to
> `attested`. Read the row's title as *"no bundle **file** verifies to
> `attested`"*.
> **The fixture is MATERIALISED into `target/verifier-web-fixtures/`, never
> committed**, on `scripts/verifier-page-browser.sh:12-19`'s own already-argued
> precedent — *"a second binary copy of the same bundle committed under another
> name would be a second source of truth that agrees on the day it is
> written."*
> **Its material is real and already frozen, and it binds by construction.**
> A25 stamped `083f87df…69df`, which **is** the `anchor_digest` of the F13 case
> `empty-anchor-unanchored`; the real merged-and-upgraded `.ots` over that
> digest is already committed inside the frozen `anchor` vector as
> `ots-upgraded-offline` (3 808 B, expected state `attested`, upgrade group at
> real block **960767** with the real captured header). Measured end to end
> from those two documents alone: rebuilt bundle **4 846 B**,
> `anchor[0] state = Attested`, `plan.blocks = [960767]`,
> `headline_eligible_count = 0`. Both endpoints' captured responses for 960767
> (`testdata/anchors/A25-upgrade-headers/`) are **byte-identical to the embedded
> header**, so the intercepts replay recorded mainnet rather than inventing
> bytes.
> **The lean is REFUSED on a mechanism.** The A25-bootstrap upgraded `.ots`
> this row nominates stamps `6fd9c1c4…d378`, the digest of a **third-party
> crate's `LARGE_TEST` file**; `anchor_digest` is SHA-256 over the bundle's own
> manifest and cannot be chosen, so **no bundle can be built that it binds
> to** — `parse_ots` step 5 gives `anchor-ots-digest-mismatch` and the slot
> renders `Invalid`. The row's note *"the material for one already exists in
> the tree"* is right and points at the wrong artifact.
> **ONE fixture serves all four cases** — they differ only in mocked responses
> (`classify_probed_anchor` reads the online-augmented outcome and the probe
> log, never a second bundle). A second fixture is emitted for **one** reason:
> the wide-vs-narrow witness this row's Accept asks for (`plan.blocks` two
> entries, overlay one row).
> **No freeze event of any class**: `testdata/vectors/` is read, never written.
> `./scripts/vector-freeze.sh` must be green **without** `--update`, and that
> is the check that proves the classification. Adding a case to
> `bundle/bundle.json` is refused as D105 §5.1's *"red gate with no key"* — the
> digest moves (`5144eb89…` → `6e175c56…`, measured) and `--verdict-event` is
> **unreachable by path**, being scoped to `/report/`. Editing
> `every-anchor-kind-*` is refused three times: FIXTURE EVENT (D128 §1.8),
> **already refused by D94 §5c**, and it would **blunt the instrument** it
> edits.
> **`..._at_m2` is UNCHANGED and NOT renamed.** The suffix is a dated
> re-measurement marker, not an expiry — `git log -S` shows the test was
> renamed from `..._all_absent_and_unanchored_at_m1` at R12 — and the
> all-`invalid` property belongs to the vector's **placeholder bytes**, not to
> the milestone.
> **Accept is amended: the receipt-bearing twin is DEFERRED to R85.** Its
> `tx_hash` target is precisely what R85 leaves open, and none of the four block
> cases needs a receipt. Building it now would commit a demonstration of R85's
> defect.
> **Ageing: nil, measured.** `evaluate_ots_artifact` takes no verification time
> as a parameter — there is no expression in the OTS path in which today's date
> can appear — and the fixture carries no TSA token, which is the only
> date-sensitive artifact class in this tree.

**On R27** —

> **[D133, 2026-08-14]** Unblocked. The fixture arrives as
> `target/verifier-web-fixtures/attested-ots-960767.sealproof`, materialised by
> `scripts/verifier-page-browser.sh` and asserted by
> `crates/antseal-core/tests/page_fixtures.rs`. **Route off
> `verify_rendered(b).plan`** (D132), which for this fixture is
> `{"blocks":[960767],"receipt":null}`. Interception is **`Fetch.enable` +
> `Fetch.requestPaused` + `Fetch.fulfillRequest`/`failRequest`** over the
> existing CDP session — **there is no playwright in this repository** and none
> is to be added; D129 ruled the driver dependency-free. The four cases differ
> **only** in the mocked response: both endpoints replay the 960767 captures
> (promotion); both return 960768's real header (mismatch → `Refuted`,
> `anchor-ots-online-header-mismatch`); the two return different real headers
> (disagreement); one is failed (`NotPromoted{EndpointFailures}`, never a
> promotion on the survivor, D66). Keep the zero-fetch row over the existing R9
> fixtures — it is the proof the plan-driven path invents no work and it now has
> a non-empty counterpart. **D132's parity warning is not discharged by any of
> this**: both surfaces derive the probe set from one function, so a defect in
> `ProbePlan::from_bundle` is invisible to a rendering-comparison gate and the
> core equality row is the only instrument that can see it.

**On R24** —

> **[D133, 2026-08-14]** Accept row 2's four cases are **already green at the
> library layer on both surfaces and both targets** — see
> `orchestration/tests.rs`'s `// Accept row 2 — the mock-endpoint outcomes`
> section and `verify_command.rs`'s `StubServer` disagreement row. What the row
> still owes is the **browser** venue named in its own parenthesis, which R27
> writes against D133's materialised fixture. Cite the existing rows rather than
> rebuilding them; the previous note's *"cannot be written at all"* was measured
> false and is corrected here so the cases are not written a third time.

**On Q237** —

> **[D133, 2026-08-14]** R84 is no longer a fixture hole. The gate's
> endpoint-disagreement clause is satisfiable on both surfaces: CLI by
> `disagreeing_endpoints_render_the_advisory_and_move_nothing` (green today,
> real loopback endpoints), page by R27's browser case over D133's fixture.
> **The gate must state which machine ran the browser arm**:
> `scripts/verifier-page-browser.sh` is **not** in `scripts/local-gate.sh` and
> Q19 is `workflow_dispatch` only and not a required context, so a green local
> gate is not evidence for R27's clause (d). Same class as R82 and R83; do not
> let it be discovered a third time.

**On R85** —

> **[D133, 2026-08-14]** The receipt-bearing twin R84 was to carry is
> **deferred to this row**, because the twin's `tx_hash` target is exactly the
> question this row leaves open — a fixture pointing at nothing would commit a
> demonstration of the false-refutation defect and need re-doing the moment this
> row rules. The emitter D133 specifies
> (`crates/antseal-core/tests/page_fixtures.rs`,
> `ANTSEAL_EMIT_PAGE_FIXTURES=<dir>`) builds the twin by adding a `receipt` to
> `parts`; nothing else changes.

---

## Outcome

R84 loses its premise and keeps its purpose. The four cases were never
unwritable — they were written twice, on both targets, and what was missing was
a **file** the browser could be handed. That file is now assembled, in this
session, from two documents already frozen in the tree, and it verifies to
`Attested` at 4 846 bytes with `plan.blocks = [960767]`.

The lean died on a mechanism rather than on cost: a digest that cannot be
chosen. The freeze was never the obstacle it appeared to be, because the ruling
does not touch it. And the arm that wins is one the brief's list did not
contain — the venue of (e) with the material of (b), sourced from frozen bytes
so that the emitter owns no bytes of its own, and every value in the fixture
was either computed from a committed manifest or recorded from mainnet.

---

## Correction — R7's fixture count and its glob, and R11's inertness assertion, 2026-08-15

Two of this record's own rulings are wrong in the direction of under-counting
what the record itself ordered. Both were found by the lane implementing R84,
not by a reader.

**(1) R7 says "the eleventh fixture" where this record orders twelve.**

> *"The `ls "$FIXTURES"/*.sealproof` glob at `:71` then picks the new file up
> with **no further change**. The script's `# ── The fixture is MATERIALISED,
> not committed ──` header gains one sentence naming the eleventh fixture and
> its two frozen sources"* — §3 **R7**.

R2 counts ten cases already materialised by
`scripts/verifier-page-browser.sh::materialise()`, and **R11** orders a
**second** emitted fixture. Ten plus two is twelve, so R7's singular is wrong
against R11 on the same page, and its *"no further change"* is wrong against
the glob's own failure mode. Measured, with the emitter pointed at a scratch
directory:

```
$ ANTSEAL_EMIT_PAGE_FIXTURES=<abs dir> cargo test -p antseal-core --test page_fixtures
test result: ok. 5 passed; 0 failed
$ ls -l <abs dir>
4846  attested-ots-960767.sealproof
4978  attested-plus-invalid-ots.sealproof
```

The implementing lane additionally measured the glob's silence: `ls` returns
the other files when a fixture does not arrive, so the browser lane runs green
having tested less than it claims — which is what happened during R84, when a
**relative** emit path wrote both fixtures somewhere else (cargo runs an
integration test from the package root) and the lane passed regardless. The
script therefore asserts each required fixture by name and the test refuses a
relative directory. Both are enforcement of R7's own intent, not a new rule.

**(2) R11's closing sentence names an assertion that cannot exist.**

> *"The assertion that it is **inert** is the byte-equality of report, overlay
> and verdict-class across the two fixtures."* — §3 **R11**.

The second fixture carries a **second anchor** by R11's own construction, so
its report carries **two** anchor slots against the first's one. Byte-equality
of the reports is therefore impossible, and a lane obeying the sentence
literally would either fail or weaken the fixture until it passed. Measured, in
`crates/antseal-core/tests/page_fixtures.rs`
(`vector_page_fixture_wide_plan_exceeds_the_narrow_overlay_set`, green):

| quantity | `attested-ots-960767` | `attested-plus-invalid-ots` |
| --- | --- | --- |
| offline anchor states | `[Attested]` | `[Attested, Invalid]` |
| **wide** set — `ProbePlan::from_bundle(...).blocks` | `[960767]` | `[960767, 960768]` |
| **narrow** set — overlay rows admitted | **1** | **1** |
| bundle bytes | 4 846 | 4 978 |

The true assertion — and the one the lane wrote — is that the **narrow set is
the same single row on both fixtures while the wide set names one height
against two**. That is D132 §1 (c)'s inertness exhibited in artifacts rather
than argued: the extra planned fetch changes what is fetched and nothing that
is rendered.

**Authority.** R84's implementing lane, 2026-08-15, executing §5.1's four acts;
recorded by the registrar in the same act that closes R84, so this correction
and its subject ship in one commit (§2.1 (c) of D117 permits either; they are
not separable here, because the corrected text is what the shipped code
contradicts).

**A third correction was proposed and is REFUSED, because the record does not
make the claim.** The proposal was that *"§8 item 3's native `verify_with_host`
promotion row was not built"* be recorded as an error. §8's own preamble reads
*"Discovered work — described, not registered … No ids minted. Descriptions
only, for the registrar"*, and item 3 says the row *"would put a real-material
promotion under `cargo test`"* and *"costs one test"* — a description of work
not yet done. Nothing in §5.1's four acts orders it. It is therefore an
**open follow-on**, correctly described where it stands, and it is recorded as
such on R84's entry rather than as a defect here. Recording it as a correction
would put a true sentence under a heading that says it is false.

**Which rulings still stand.** All of them. Both errors run in the direction of
**under-stating** what this record ordered — one fixture where it ordered two,
and an assertion narrower than the one its own construction supports — so R2,
R5, R9, R10 and R12 are untouched, R7's substance (one emitter step at the head
of `materialise()`, the header sentence at the site) stands with its count and
its glob corrected, and R11's ruling — emit a second fixture whose wide and
narrow sets differ — is exactly what shipped. The classification in **R12**
(not a format, verdict or fixture event) is unaffected: `git status --
testdata/` is empty after the change and `./scripts/vector-freeze.sh` is green
without `--update`.
