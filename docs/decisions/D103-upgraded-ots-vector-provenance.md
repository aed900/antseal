# D103 — A22's upgraded-`.ots` cases: whether they can be provenanced, and what the `anchor` vector set actually is

- **Status: RESOLVED — the lean is OVERTURNED ON ITS PREMISE, not on its
  merits. "Ship 1–3, append 4/5 later" answers the question "is deferral
  legal?" when the live question is "is deferral necessary?", and it is not:
  cases 4 and 5 are buildable **today, from committed bytes, with no network
  and no `antseal-anchor` call**, and I built the artifact and measured it in
  this round. The crate-graph objection dissolves because there is nothing to
  call: `merge_upgrade`'s only byte effect is
  `file[..offset] ‖ 0xff ‖ body ‖ file[offset..]`
  (`container.rs:252-268`) — no hash, no key, no crypto, no `antseal-anchor`
  logic. Splicing the three committed `A-*.upgrade` bodies into `merged-A.ots`
  in document order yields **3 808 B, 244 ops, depth 85, 6 attestations,
  sha256 `c2bf8b2c…`**, and the **decisive measurement, which nothing in the
  tree had made: the ops of all three Bitcoin branches derive merkle roots
  that byte-match `header[36..68]` of the three committed mainnet headers**
  for 960767 / 960768 / 960771, each of which I re-verified offline by
  `double-SHA256(header) == claimed hash`. So `check_embedded_header` returns
  `Committed`, and **O4 precedes O5** (`verdicts.rs`) — the surviving pending
  branches do **not** demote it, which is the inverse of the trap
  `tasks/A.md:265` records for the *forged* row and is the thing a reader is
  most likely to get backwards. **K5 therefore never fires**, on either
  reading — and I rule the reading anyway (§3), because D101's text reads it
  narrowly and the narrow reading is **already false of the tree**: five
  committed frozen kinds have no generator at all. Three further things the
  brief did not ask for and that fall out of the measurement. (1) **D101 §9.2's
  partial-landing fallback was CONDITIONAL — *"if the headers do not land"* —
  and its condition expired on 2026-08-07 when `A25-upgrade-headers/` was
  committed.** The lean revives a fallback whose trigger is gone. (2) **D101
  §3.2 rules `suppressed` into the `expect` on the strength of a witness its
  own case set does not contain** — `ots_refutation` returns `None` for every
  one of D101 §9's five cases, so all five carry `[]` and the "one that
  carries a code" does not exist. One extra case over the **same artifact
  bytes** — agreed `no-such-block` at 960767 — delivers it at zero artifact
  cost, and is simultaneously the first committed witness for D56 §4's
  anti-downgrade rule. (3) **D101 §3.5's coverage assertion 6 is vacuous**:
  `absent` is a kind-level answer on `AnchorVerdicts::absent_verdict`
  (`verdicts.rs:472-478`) and every case is one artifact, so the iff has no
  reachable counterexample — D94's "instrument nobody exercises" defect, in a
  document whose §4.3 invokes it. **A107 is ruled here and closed** (§9): §7.4
  is guidance, not a ruling (D101's markers jump 6c → 7), and its number is
  wrong about its own two artifacts — measured, both frozen tokens are **128 s**,
  not 129. The case set is **seven**, the frozen OTS artifact is the **full**
  three-way splice, and A22's Accept becomes **four explicitly numbered rows**
  so the D53/Q109 miscount cannot recur by counting.**
- **Date: 2026-08-09** (M2 wave 10 planning round; unblocks **A22**, resolves
  **A107**)
- **Owning tasks: A22** (executes; §5's case set, §8's tier rule, §7's Accept
  rows), **A107** (resolved by §9), **A25** (`upgraded/PROVENANCE.md` gains the
  derivation record, §4.4), **A14** (owns the cross-check test, §3.3).
  Register entry: the D103 row this record creates under `TODO.md` "Due M2".
- **Amends**: **D101 §9** — row 4/5's artifact naming is factually wrong and is
  replaced (§2.1); **D101 §9.2** — the fallback's condition has expired and the
  paragraph is struck (§2.4); **D101 §3.5** structural assertion 6 (§6.2);
  **D101 §7.4** — superseded by §9, and its "~129 s" corrected to a measured
  per-token figure; **D101 §8 K3**'s budget estimate (§11); **D101 §2.3**'s
  Accept rows gain explicit numbering (§7). **Supersedes**: nothing.
  **Binds against**: D101 (throughout), D56 §4/§5/§9, D79, D93 §5, D92 §5.1,
  D53 §4a, D87, D94 §2a, A32, A104.

---

## The problem, in one sentence

D101 §9 fixes A22's wave unit at five cases and names cases 4/5's artifact as
`upgraded/A-*.upgrade`; those files are bare calendar response bodies with no
`.ots` magic and no header, so **no upgraded `.ots` over antseal's own digest
exists on disk**, and the function that would make one lives in a crate the
vector executor cannot reach.

---

## 1. What was measured

Everything below was measured in this round against the working tree at
`4672843`, independently of the recon lanes that reported it. Where a
committed document disagrees with the bytes, the bytes are recorded as the
fact.

### 1.1 D101 §9 rows 4/5 name an artifact that does not exist — confirmed

A whole-tree scan for the 31-byte OpenTimestamps magic
(`\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94`) finds
exactly **three** containers:

| file | bytes | shape |
| --- | --- | --- |
| `A25-bootstrap/merged-A.ots` | 664 | pending, digest A |
| `A25-bootstrap/merged-B.ots` | 629 | pending, digest B |
| `A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` | 1 768 | third-party, foreign digest, blocks 449397/449399 |

`upgraded/A-alice.upgrade` begins `08 f1 20 f8 c2 78 …` — an op stream, no
magic, no header, no digest. The sizes D101 §9 quotes (1 000 / 1 036 / 1 105)
are the `bytes=` fields of `UPGRADE-CAPTURE.log:3-5`, which are HTTP
response-body lengths. `replay.rs:130-135` already says so in its own comment:
*"each is a timestamp body rooted at that pending attestation's commitment,
**NOT a `.ots` file**."*

### 1.2 The merge is a byte splice, and it is reproducible outside Rust

`splice_sibling_before` (`crates/antseal-anchor/src/ots/container.rs:252-268`)
is, in its entirety:

```text
out = file[..offset] ‖ 0xff ‖ sibling ‖ file[offset..]
```

`offset` comes from `locate_pending` (`:211-237`), a byte search for
`0x00 ‖ OTS_PENDING_TAG ‖ varuint(len) ‖ varuint(|uri|) ‖ uri` whose result
count must equal the parser's count. `merge_upgrade` (`upgrade.rs:358`) wraps
that with three validations — re-parse, `retains_all`, `added_bitcoin` — none
of which changes a byte.

I re-implemented the container walk in Python and **validated it against the
tree's own committed shape measurements before using it for anything**
(`ots/tests.rs:243-269`): `merged-A.ots` → ops **34**, depth **12**,
attestations **3**; `LARGE_TEST.ots` → ops **100**, depth **67**,
attestations **4**. Exact agreement on both.

Splicing the three committed digest-A upgrade bodies in document order
(alice → bob → catallaxy — `pending_refs` order, `upgrade.rs:289-315`), each
step re-locating in the *current* bytes exactly as `merge_upgrade` does:

| step | bytes | ops | depth | attestations | occurrences found |
| --- | --- | --- | --- | --- | --- |
| `merged-A.ots` | 664 | 34 | 12 | 3 | — |
| `+ A-alice.upgrade` | 1 665 | 101 | 79 | 4 | 1 |
| `+ A-bob.upgrade` | 2 702 | 171 | 80 | 5 | 1 |
| `+ A-catallaxy.upgrade` | **3 808** | **244** | **85** | **6** | 1 |

`sha256 = c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68`

The digest-B walk is the same shape: **3 773 B**, 242 ops, depth 83,
`sha256 = 759adb377136d97099695cd6f727c9c85b8578b97e8c3f31ee61072ec1d156f8`.

### 1.3 The decisive measurement — the ops commit the real headers

This is the fact on which cases 4 and 5 live or die, and nothing in the tree
had measured it. Executing the op stream (`0x08` SHA-256, `0xf0` append,
`0xf1` prepend — the only ops the artifact uses, so every branch value is
determinate) down each Bitcoin branch of the spliced digest-A artifact:

| height | calendar | ops-derived root | `header[36..68]` | match | `nTime` |
| --- | --- | --- | --- | --- | --- |
| 960767 | alice | `74ce7464…ab53233a` | `74ce7464…ab53233a` | **yes** | 1 785 701 746 |
| 960768 | bob | `a921c752…14798ae5` | `a921c752…14798ae5` | **yes** | 1 785 702 431 |
| 960771 | catallaxy | `d303b654…92b537a7` | `d303b654…92b537a7` | **yes** | 1 785 704 384 |

No byte reversal, matching A12's rule. Each header re-verified offline:
`double-SHA256(header)`, reversed, equals the committed
`esplora-*-height-<h>.txt` value, for all three, from both endpoints.

So `header_commits` (`ots/header.rs:124-134`) is satisfied for any of the
three heights, and `check_embedded_header` — existential over branches —
returns `Committed`.

### 1.4 The spliced artifact clears every F4 limit with three orders of margin

| measure | value | limit | headroom |
| --- | --- | --- | --- |
| bytes | 3 808 | `MAX_OTS_BYTES` 1 048 576 | 275× |
| ops | 244 | `MAX_OTS_OPS` 4 096 | 16.8× |
| depth | 85 | `MAX_OTS_DEPTH` 1 024 | 12× |
| attestations | 6 | `MAX_OTS_ATTESTATIONS` 256 | 42× |
| branch width | 4 | `MAX_OTS_BRANCH_WIDTH` 64 | 16× |
| max operand | 89 | `MAX_OTS_OPERAND_BYTES` 16 384 | 184× |
| max attestation payload | 46 | `MAX_OTS_ATTESTATION_PAYLOAD_BYTES` 8 192 | 178× |

Under D102's rule 6 the artifact's structural cost is
`next_pow2(min(3808, 1024)) × 40 + next_pow2(min(3808, 256)) × 48` — nowhere
near clause (c). This artifact is not a stress case and must not be described
as one.

### 1.5 The rule order — O4 precedes O5, and the recorded trap is about the *other* row

`tasks/A.md:265` records, for A21's **forged-header** row: *"the sibling
pending branches survive, D56's rule O5 fires first and the row renders
`pending`"*. Read carelessly that says any merged artifact with surviving
pendings renders `pending`. It does not. Reading `evaluate_ots_artifact`:

- **O3** fires on `upgrade && committed && agreed == Header(embedded)` →
  `proven`, `AnchorIdentity::BitcoinChain`, time = the **agreed** header's
  `nTime`.
- **O4** fires on `upgrade && committed && !refuted_online` → `attested`,
  identity passed and then dropped by `AnchorOutcome::new`'s eligibility
  filter → `identity_kind: null`.
- **O5** (`has_evaluable_pending`) is reached **only after both**.

The forged row renders `pending` because forging breaks `committed`, so O3 and
O4 fall through. The honest artifact keeps `committed == true` and never
reaches O5. **This is what makes case 4/5 work, and it is also why the full
splice is the right artifact to freeze** (§4).

### 1.6 The feature-tier trap — confirmed at the line

`crates/antseal-core/src/anchor/mod.rs:77` is
`#[cfg(any(test, feature = "test-util"))] pub mod testing;`.
`crates/wasm-bitmatch/Cargo.toml:44` takes `antseal-core` with
`features = ["test-vectors"]` through a **normal** edge, and
`test-util = ["test-vectors", "dep:proptest"]` is the *larger* feature. So
every constant in `anchor::testing` — `MERGED_A`, `DIGEST_A`,
`UPGRADED_LARGE_TEST`, `committing_upgrade()`, all of `ots_writer`, all of
`tamper_rows` — is invisible to the parity build, and an executor naming one
**fails to build `wasm-bitmatch`**, the single crate A22 exists to satisfy.
This is D101 §1.4's `from_static` finding one module over, and D101 did not
name it.

### 1.7 The clock, measured per token rather than quoted

`openssl ts -reply -text` against the two tokens A22 freezes, differenced
against their own `D60-CAPTURE.log` rows:

| token | log `utc=` | unix | `genTime` | unix | skew |
| --- | --- | --- | --- | --- | --- |
| `D60-tsa-freetsa-resp.tsr` | 2026-08-02T19:20:19Z | 1 785 698 419 | 2026-08-02T19:22:27Z | 1 785 698 547 | **128 s** |
| `D60-tsa-digicert-resp.tsr` | 2026-08-02T19:20:26Z | 1 785 698 426 | 2026-08-02T19:22:34Z | 1 785 698 554 | **128 s** |

`D60-CAPTURE.log:17-23` headlines *"129 s slow"* over three probe offsets of
**+129 / +128 / +129**. 129 is the mode of three probes, not a constant, and
it is **wrong about both artifacts A22 freezes**.

`A25-upgrade-headers/CAPTURE.log` records `utc_start=2026-08-07T10:36:32Z`
(= 1 786 098 992) and **no clock offset at all** — verified by reading the
whole header block.

---

## 2. Ruling 1 — cases 4 and 5 land this wave

**RULING 1. The lean is overturned. A22 builds the upgraded-`.ots` cases now.
They require no network, no consent event, no `antseal-anchor` dependency
edge, and no new capture.**

### 2.1 D101 §9's rows 4 and 5 are replaced

Row 4/5's `artifact` cell becomes: *"the three-way merged+upgraded `.ots` over
digest A, derived by `gen_vectors.py` from `merged-A.ots` plus the three
committed `upgraded/A-*.upgrade` bodies — **3 808 B**, sha256 `c2bf8b2c…`.
Not an archive file: `upgraded/A-*.upgrade` are calendar response bodies, not
containers (D103 §1.1)."*

### 2.2 Why the crate-graph objection dissolves rather than being worked around

It is not that the executor gets a new way to reach `merge_upgrade`. It is
that **there is nothing in `merge_upgrade` to reach.** Its byte output is a
concatenation at an offset found by a literal byte search. `antseal-anchor`
owns the *validation* around that splice; the splice itself is not the sort
of thing a crate can own. A generator that performs it is not reimplementing
antseal — it is doing the one thing the function does.

Contrast with the case D101 §7.3 correctly refuses: a Python reimplementation
of RFC 3161 chain validation, which *would* be a second implementation of a
judgement, and would pin the same bug twice. A byte splice has no judgement
in it. The distinction is not "how hard is it" — it is **does the procedure
decide anything the verdict depends on**, and here it does not: every verdict
in cases 4/5/6 is computed by the Rust evaluator from the frozen bytes.

### 2.3 The strongest form of the lean, and why it still fails

The lean's best version is not "4/5 are impossible" — that premise is dead.
It is: *"even so, the artifact is a reconstruction no live run ever emitted;
freezing a synthesised artifact forever is worse than deferring."*

That objection is real and it is answered by the measurement, not waved away:

1. **The reconstruction is exact, not approximate.** Every byte in the frozen
   artifact comes from a committed capture. The splice adds precisely three
   `0xff` bytes. There is no synthesis in it — 3 805 of 3 808 bytes are
   verbatim archive, and the three that are not are the fork marker the format
   requires.
2. **The chain does not care that a client did not write the file.** The three
   Bitcoin branches derive roots that match three real mainnet headers whose
   proof-of-work I re-verified. Bitcoin attested this project's digest on
   2026-08-02; that is a fact about the chain, and the file is the ordinary
   encoding of it.
3. **The alternative freezes something worse.** Shipping 1–3 declares the M2
   exit criterion met over a set in which the upgrade path, `identity_kind:
   "bitcoin-chain"`, the online/offline distinction, and every `nTime`
   extraction are unexercised — and D101 §3.5's assertion 4 cannot be
   satisfied, so the executor D101 specifies **does not compile against a 1–3
   vector**. The lean is not merely weak; as specified it is internally
   impossible.

### 2.4 D101 §9.2's fallback has expired and must be struck

§9.2 reads *"**If the headers do not land** — ship cases 1–4"*, resting on
§1.6's *"It is **untracked**"*. `git ls-files` now returns fourteen files under
`testdata/anchors/A25-upgrade-headers/`; they landed in `6f69e1a`. **The
condition on which the fallback rested is gone.** Leaving the paragraph
standing is the D94 §3 shape — a prediction that ages into a lie — and it is
exactly what the lean cites as if it were a standing option.

Note also that §9.2 offered *"cases 1–4"*, not 1–3. Even on its own terms it
never sanctioned the lean, because case 4 is offline and needed no header.

---

## 3. Ruling 2 — what K5 is about

**RULING 2. K5 is about a committed, re-runnable, network-free procedure over
committed inputs. It is not about a language. D101's text reads it narrowly;
the narrow reading is wrong and is already false of the tree; and for A22 the
question does not bind, because Python does the job.**

### 3.1 The two readings, and the evidence

| reading | what it demands |
| --- | --- |
| **narrow** | the committed `gen_vectors.py` must emit the frozen bytes |
| **broad** | *some* committed, re-runnable, network-free procedure over committed archive bytes must emit the frozen bytes |

D101 read it narrowly: RULING 6a names `gen_vectors.py` and quotes
`testdata/vectors/README.md:211-213` (*"commit the generator as `*.py` beside
the vectors"*), and K5's definite article — *"**the** generator"* — refers
back to it.

The narrow reading is refuted by the tree it governs. **Five committed, frozen
kinds have no generator at all**: `report`, `bundle`, `manifest`,
`content-model`, `sig-reject`. Under the narrow reading each is unprovenanced
and none may be frozen. They are frozen. So the narrow reading is not the rule
the project runs on, and K5 cannot be it either.

The freeze manifest states the property directly: *"the `*.py` reference
generators are deliberately NOT frozen: the generators are **re-runnable
cross-checks**, and the JSON they produced is what the format actually commits
to"* (`FROZEN.sha256:13-16`). Re-runnability is the named property. And
README:211-213's own clause is conditional — *"generate `expect` values with
an independent reference implementation **where one exists**"* — which is
precisely the clause D101 §7.3 invokes to rule that `anchor` has none.

### 3.2 What "provenanced" means for the `anchor` kind, specifically

Because this is where a future reader will go wrong: for `crypto`,
`fine-tree`, `hkdf` and `storage-address`, the generator is a **cross-check** —
an independently written implementation whose agreement with Rust is the
evidence. For `anchor` there is no such implementation and D101 §7.3 is right
to refuse to fake one.

For `anchor`, `gen_vectors.py` is a **derivation record**: the committed,
executable statement of how the frozen `inputs` were obtained from
`testdata/anchors/`. It emits `inputs` only; `expect` comes from the Rust
executor's `build_expect`. A22's `anchor/README.md` must say this in those
words, or a reader will look for a cross-check nobody intended and conclude
one was skipped.

### 3.3 …and the cross-check that *is* available, which nobody proposed

The derivation half is one thing. Separately, the tree can prove the Python
splice agrees with the shipped code, and it costs one test:

> **RULING 2a.** `antseal-anchor` gains a native test that runs the real
> `merge_upgrade` three times over `fixtures::MERGED_A` and
> `fixtures::UPGRADE_A_{ALICE,BOB,CATALLAXY}` — all four already
> `include_bytes!`-wired in `testing/replay.rs` — and asserts the result's
> SHA-256 equals `c2bf8b2c…`, the same literal the vector's
> `expect.cases[].artifact_sha256` carries. Two independently written pieces
> of code, one committed number.

This is A13's own precedent, in its own words: *"assembling from the three
real replies reproduces the committed `merged-A.ots` — two independent pieces
of code from the same inputs."* It is **A14's** to own, not A22's, because it
is a statement about the merge engine.

**It is not the standing archive-equality test D101 RULING 6b refuses**, and
the difference is not cosmetic. 6b's test asserts *the archive has not moved*;
its red is only ever fixable on the unfrozen side, and the archive has no
retention rule. This test asserts *the code and the generator agree*; it names
no vector file, reads no frozen path, and compares two computations against
one literal. If `merge_upgrade`'s splice rule ever legitimately changes, this
test is **code** and is edited — D101 §3.1's own argument for why
`root_store_version` belongs in `chain.rs` rather than in a frozen file. Its
inputs are already build-critical via `replay.rs`, so 6b's objection 2 does
not reach it either.

---

## 4. Ruling 3 — which artifact is frozen

**RULING 3. The frozen OTS upgrade artifact is the FULL three-way splice —
all three calendars, in `pending_refs` document order alice → bob →
catallaxy — 3 808 B, sha256 `c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68`.
Not the one-calendar splice.**

### 4.1 Why the full splice, on four grounds

1. **It is the real terminal state.** The engine polls every pending ref and
   merges every `200`; all six of the 2026-08-03 responses were `200`
   (`UPGRADE-CAPTURE.log:3-8`). The one-calendar splice is a state the protocol
   passes through, not one it stops at.
2. **One artifact, three committed headers.** Three Bitcoin branches at three
   heights, every header committed and independently verified (§1.3), so a
   single frozen artifact expresses three distinct `upgrade` groups. The
   one-calendar splice buys exactly one.
3. **It makes `check_embedded_header`'s permutation-invariance non-vacuous.**
   D56 §5 requires the answer to be invariant under branch order; over one
   Bitcoin branch that requirement has nothing to quantify over.
4. **The surviving pending branches are what make §5's case 6 expressible at
   all.** A committed artifact that agreed evidence refutes, still rendering
   `pending`, with the refutation carried as an A39 anomaly — D56 §4's
   anti-downgrade rule — needs both a committed Bitcoin branch and a live
   pending branch in one artifact. Only the merged shape has both, and no
   committed artifact witnesses it today.

Cost: 2 143 bytes over the one-calendar splice. Against D87's 1 461 590 B of
headroom that is 0.15 %.

### 4.2 The order is part of the ruling

Different orders produce different bytes. The order is `pending_refs`'
document order over the *current* stored artifact at each step, re-located
each time — which is `merge_upgrade`'s own iteration and what §1.2 measured.
`gen_vectors.py` must state the order in a comment and RULING 2a's test must
apply it in the same sequence, or the two agree by luck.

### 4.3 The bytes are not committed to `testdata/anchors/`

**RULING 3a.** The spliced artifact does **not** land as a file under
`testdata/anchors/`. It is derived, and D101 RULING 6 already settles the
authority question: the vector copy is authoritative and the archive is
provenance. A third, unfrozen copy of derived bytes is a copy with no rule
attached to it.

### 4.4 What the archive gains instead

**RULING 3b.** `testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md` gains a
derivation paragraph: the splice rule, the order, the four intermediate byte
counts of §1.2, the final sha256, the three attested heights, and the pointer
to `testdata/vectors/v1/anchor/`. That is A25's file and this is A25's
provenance; A22 writes the paragraph and A25 owns it.

**And the capture logs are not edited.** §1.7's per-token measurement corrects
a headline in `D60-CAPTURE.log`, and a capture log is a record of what was
observed at capture time. The correction goes in the vector's `description`
and in `anchor/README.md`, never into the log.

---

## 5. Ruling 4 — the case set is seven

**RULING 4.** One vector file, `testdata/vectors/v1/anchor/anchor.json`, one
top-level `anchor_digest` (digest A) and one top-level
`verify_at_unix = 1 786 100 000`, over **seven** cases and **four** distinct
artifacts.

| # | name | artifact | inputs beyond the artifact | `expect.state` | `[H]` | `identity_kind` | `suppressed` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `tsa-freetsa-p384` | `D60-tsa-freetsa-resp.tsr` (4 643 B) | `fetch_date_unix` 1 785 698 419 | `proven` | yes | `tsa-signer` | `[]` |
| 2 | `tsa-digicert-rsa` | `D60-tsa-digicert-resp.tsr` (6 007 B) | `fetch_date_unix` 1 785 698 426 | `proven` | yes | `tsa-signer` | `[]` |
| 3 | `ots-pending` | `merged-A.ots` (664 B) | no upgrade, no online | `pending` | no | `null` | `[]` |
| 4 | `ots-upgraded-offline` | spliced (3 808 B) | `upgrade{960767, header, 1 786 098 992}`, no online | `attested` | no | `null` | `[]` |
| 5 | `ots-upgraded-online-proven` | spliced (same bytes) | same `upgrade` + `online[{960767, header}]` | `proven` | yes | `bitcoin-chain` | `[]` |
| 6 | `ots-upgraded-online-block-absent` | spliced (same bytes) | same `upgrade` + `online[{960767, no-such-block}]` | `pending` | no | `null` | `["anchor-ots-online-block-absent"]` |
| 7 | `ots-wrong-seal` | `merged-B.ots` (629 B) | no upgrade, no online | `invalid` | no | `null` | `[]` |

Case 5's `verified_time_unix` is **1 785 701 746** — block 960767's `nTime`,
read from the **agreed** header per D56 §5.

### 5.1 Cases 1–5 are D101 §9's set with row 4/5's artifact corrected

No change of intent. §2.1 supplies the corrected artifact.

### 5.2 Case 6 completes D101 §3.2's own promise, at zero artifact cost

D101 §3.2 rules `suppressed` **IN** on the strength of *"an `anchor` vector
whose every case carries `"suppressed": []` **except the one that carries a
code**"*. Measured against `ots_refutation` (`verdicts.rs:937-983`), **no such
case exists in D101's set**:

- `ots_refutation` opens with `let upgrade = view.upgrade()?;` → cases 1, 2, 3
  and 7 return `None`.
- Case 4: `committed` true, `agreed` `None` → falls to `_ => None`.
- Case 5: O3's guard has already established `fetched == embedded`, so O6 is
  false, O7 is false, O8 needs `!committed` → `None`.

Five cases, five empty lists. `suppressed` would be frozen as a field that has
never been non-empty — the exact "empty vs absent" ambiguity A39 exists to
prevent, re-created inside the artifact meant to settle it.

Case 6 fixes it for **one extra `expect` case and about forty characters of
`inputs`**, because it reuses case 4's artifact hex verbatim. Its route is
worth stating so the implementer does not misread it as a tamper row: agreed
`NoSuchBlock` at 960767 makes `refuted_online` true (O7), which disqualifies
O4; O5 then fires because the merged artifact still carries three pending
attestations, and the O7 refutation is carried as the A39 anomaly. That is
**D56 §4's anti-downgrade rule, in the words `verdicts.rs` already uses for
it** — *"a committed artifact that agreed evidence refutes still renders
`pending` when it has a pending branch, and the refutation is carried as an
A39 anomaly"* — and it has no committed witness today.

It also gives case 3 a proper twin: same state, differing in `fetch_date`
(`null` vs a value, because case 3 has no upgrade group) and in `suppressed`.

**Note for the `description`, and it is not optional.** Case 6's input is
*hypothetical* online evidence about a block that exists. `OnlineEvidence` is
data a host supplies, and the case pins what the rule does with an agreed
absence — it does not claim block 960767 is absent. A frozen file that reads
otherwise is a frozen file that lies.

### 5.3 Case 7 — ruled IN, the one discretionary addition

`merged-B.ots` evaluated under the document's top-level `anchor_digest` (A)
fails `parse_ots`'s step-5 digest comparison → O1 → `invalid`,
`anchor-ots-digest-mismatch`.

This is the closest thing the OTS half has to a headline defect — D56 §9's
*"an `.ots` for someone else's seal carrying a genuine online-confirmable
Bitcoin attestation would render `proven`"*. A21 row 1 already covers it, and
D101 §6.3 records why that is not the same thing: the tamper matrix's wasm32
half is **same-verdict**, while a vector is **byte-identical across targets**.
Case 7 promotes the single most consequential OTS rule from the weaker tier to
the stronger one, using bytes committed since 2026-08-02, for 1 258 hex
characters.

It also earns its place structurally: without it every case in the set has an
artifact that matches the document's digest, and the top-level `anchor_digest`
field would be pinned by nothing.

### 5.4 The shared artifact is duplicated, not referenced

**RULING 4a.** Cases 4, 5 and 6 each carry the full `artifact_hex`. No
by-reference mechanism.

22 848 hex characters for one artifact is 1.1 % of D87's ceiling. A reference
key would be a second way to spell an input in a document whose reviewability
already rests entirely on `description` and `provenance` (D101 §7.1), and it
would add a resolution failure mode to an executor that currently has none.
The duplication is self-checking: `expect.cases[].artifact_sha256` must be
identical across the three, and a diverging copy fails the value compare on
the same run that would have produced a wrong verdict.

### 5.5 `verify_at_unix = 1 786 100 000`

**RULING 4b.** 2026-08-07T11:33:20Z. Four constraints, all checked:

- after every `genTime` (latest 1 785 698 554) ✓
- after every attesting `nTime` (latest 1 785 704 384) ✓
- after every `fetch_date` (latest 1 786 098 992, the header campaign's start) ✓
- before every signer certificate's `notAfter` — FreeTSA 2040-02-02, DigiCert
  responder 2036-09-03 — so cases 1 and 2 are `proven` and not
  `valid-at-stamping-cert-since-expired` ✓ (measured with
  `openssl pkcs7 -print_certs`)

A second vector file under `anchor/` is the extension path for a different
`verify_at`; the field is top-level and one document has one.

---

## 6. Ruling 5 — the structural coverage assertions

### 6.1 Assertion 4 survives, and case 5 is what makes it satisfiable

D101 §3.5 assertion 4 — *"some OTS case carries `identity_kind:
"bitcoin-chain"` and some OTS case carries `null`"* — is satisfied by case 5
(`bitcoin-chain`, via O3) against cases 3, 4, 6 and 7 (`null`). Case 4's
`null` is the interesting one: `AnchorOutcome::new` is *handed*
`Some(AnchorIdentity::BitcoinChain)` and drops it because `attested` is not
headline-eligible (`verdicts.rs:400`) — which is A40's filter with an OTS-side
witness, D92's stated gap, closed.

**And the brief's suspicion is confirmed: a 1–3 vector cannot satisfy it.**
With only case 3 there is no `bitcoin-chain` case, the assertion fails, and
the executor D101 specifies does not compile against its own vector.

### 6.2 Assertion 6 is vacuous and is replaced

**RULING 5.** D101 §3.5 assertion 6 — *"`report_slot == null` iff `state ==
"absent"`"* — can never fire and is replaced.

`absent` is produced only by `AnchorVerdicts::absent_verdict`
(`verdicts.rs:472-478`), which returns `Some` only when `!present` for a
whole kind. Every vector case is one artifact, so `present` is true by
construction and **no case can ever be `absent`**. Both sides of the iff are
uniformly false; the assertion is a tautology over an empty domain, which is
D94 §4's "instrument nobody exercises" in a document whose §4.3 cites it.

Replaced by an assertion that can go red:

> **6′.** Every case has a non-null `report_slot`, **and** no case's `state` is
> `"absent"` — with a comment recording that `absent` is a kind-level answer
> (D53 §4a) and is unreachable in this kind by construction, so a case that
> ever produced one would mean `absent_verdict`'s domain had moved.

D53 §4a's own rule keeps its home in code. The vector stops pretending to
cover it.

### 6.3 One assertion to add

**RULING 5a.** Add: *every case's `fetch_date` is non-null exactly when its
`inputs` supply a `fetch_date_unix` (TSA) or an `upgrade` group (OTS)*. Cases
3 and 7 are the `null` side, 1/2/4/5/6 the non-null side. This is the
pass-through property R72 pins in code, stated over the frozen document, and
it is what makes §9's ruling checkable rather than merely written down.

---

## 7. Ruling 6 — three rows or four

**RULING 6. Four rows, and they are explicitly numbered, because the defect
class is *counting* and the fix is to make counting unnecessary.**

D101 §2.2 rules the honest statement is *"three of three"* and amends three
documents to say **three**; D101 §2.3 then rewrites A22's Accept as **four**.
Once §2.3 lands, three committed documents assert a count that A22 contradicts
on its face, and the next recon re-enters the D53/Q109 loop those corrections
exist to close. Neither half is wrong on its own; the pair is.

Resolved by taking D101 §2.2's own fallback — *"or delete the count — a count
that has been wrong in three places at once is not load-bearing enough to
keep"* — and going one step further: number the rows so nobody ever counts
them again.

### 7.1 A22's Accept, exact final text

```
- Accept:
  - **1.** Vectors committed as the **`anchor` kind** under
    `testdata/vectors/v1/anchor/`, registered in `INDEX.json` and in
    `KNOWN_KINDS`. Not `testdata/anchors/`, which is A25's capture area and
    carries no freeze, no retention rule and no wasm parity lane (D101 §2).
  - **2.** Frozen and retained: a `#! kind anchor A22` directive and one
    digest line per file appended to `testdata/vectors/v1/FROZEN.sha256`,
    retained forever per Q6's per-version retention policy.
  - **3.** Native and wasm runs produce byte-identical `recomputed_digest`
    for every vector — which, for this kind, is the whole `expect` object of
    D101 §3.5 as amended by D103 §6.
  - **4.** The M2 exit checklist references the `golden-vectors`,
    `vector-freeze` and `wasm-bitmatch` lanes' passing runs **and** A21's
    in-module wasm32 rows (D101 §6.3 — two mechanisms of different strength,
    one criterion); any wasm-incompatible dependency (A-OD6) resolved first.
```

### 7.2 The three citing documents

**RULING 6a.** `tasks/Q.md:1373`, `docs/decisions/D94-anchor-verdict-vector-re-emit.md:555`
and `TODO.md:540` (Q109's row — **note the line has drifted from D101 §10's
`:529`**) drop the count and cite by number. `tasks/Q.md:1373` becomes
*"A22 Accept rows 1 and 2 depend on the distinction"*; the D94 sentence
becomes *"which are A22 Accept rows 1 and 2"*. Per the house rule, each
correction quotes its own former wording — §2.2's defect class is what happens
when it does not.

Q109's row already carries its self-correction and needs only the numbers
appended; do not rewrite its history.

---

## 8. Ruling 7 — the feature tier the executor must obey

**RULING 7. `test_util/vectors_anchor.rs` may name only public, ungated
`antseal-core` API. It may not name `anchor::testing` in any form. Verified
from source, both directions.**

### 8.1 Reachable under `test-vectors` alone — confirmed ungated

`evaluate_ots_artifact`, `evaluate_tsa_artifact` (`verdicts.rs:610-616`,
`:675-679`); `OtsArtifactView::from_parts`, `TsaArtifactView::from_parts`
(`model.rs:129-145`, `:184-207`); `OtsUpgrade::new` and its three accessors
(`bundle/schema.rs:463-499`); `OnlineEvidence::{new, with_block}` and
`BlockEvidence` (`model.rs:480-600`); `OnlineBlockResult`;
`TsaRootStore::pinned`; `AnchorVerdict`'s accessors,
`is_headline_eligible` (`model.rs:900`), `to_anchor_result` (`model.rs:948`);
`AnchorOutcome`'s `verdict`/`suppressed`/`identity`. None carries a `cfg`.

### 8.2 Forbidden, and the failure mode

Everything under `crates/antseal-core/src/anchor/testing/` —
`ots_writer::{MERGED_A, DIGEST_A, UPGRADED_LARGE_TEST, FETCH_DATE,
committing_upgrade, committed_single_branch, container, …}` and all of
`tamper_rows` — plus `TsaRootStore::from_static` (D101 §1.4).

The failure is not a red test. `cargo test -p antseal-core` turns `cfg(test)`
on, so the executor compiles locally and passes; `wasm-bitmatch` takes
`test-vectors` through a normal edge and **fails to build**. A22 would discover
this at the end, in the one lane it exists to satisfy.

### 8.3 The order of work

**RULING 7a.** A22's first action, before the executor exists, is to add the
`anchor` arm to `KNOWN_KINDS` plus a stub payload type and **build
`wasm-bitmatch`**. D101 K1 says *"verify by building `wasm-bitmatch` first,
before any vector exists"*; §1.6 is the reason that instruction is not
ceremonial. Every byte the executor needs arrives as hex from the vector, and
every root from `TsaRootStore::pinned()`.

---

## 9. Ruling 8 — A107, resolved

**RULING 8. Vectors carry the RECORDED instant, per artifact, from that
artifact's own capture-log line. Never normalised, never synthetic, never
invented later. A107 is resolved by this ruling and closed.**

### 9.1 A107 is genuinely open, and D101 §7.4 does not close it

Two things, both checked:

- **§7.4 carries no ruling marker.** D101's markers run
  6a (`:718`), 6b (`:728`), 6c (`:745`), then 7 (`:803`). §7.4 sits at `:752`
  inside Ruling 6's section and is guidance.
- **§7.4's number is wrong about its own subject.** It instructs the
  `description` to record *"~129 s"*. Measured (§1.7), both frozen tokens are
  **128 s**. 129 is the mode of three probes to unrelated hosts, quoted as
  though it were a property of the tokens.

So A107 was not ruled, and the guidance that looked like a ruling would have
put a wrong number in a frozen file.

### 9.2 The values

| case | `fetch_date_unix` | source |
| --- | --- | --- |
| 1 | 1 785 698 419 | `D60-CAPTURE.log` freetsa row, `utc=2026-08-02T19:20:19Z` |
| 2 | 1 785 698 426 | `D60-CAPTURE.log` digicert row, `utc=2026-08-02T19:20:26Z` |
| 3 | *(none — no upgrade group; `expect.fetch_date` is `null`)* | — |
| 4, 5, 6 | 1 786 098 992 | `A25-upgrade-headers/CAPTURE.log`, `utc_start=2026-08-07T10:36:32Z` |
| 7 | *(none)* | — |

### 9.3 Why the recorded value, over the two alternatives

**Against normalising (+128 s).** D101 §7.4's reason stands — it destroys the
one committed artifact demonstrating that `gen_time <= fetch_date` is false in
reality, which is A32's whole content. And one more, which §7.4 did not have:
the raw HTTP `Date` headers were **not retained**. Only the derived offsets
survive, as prose at `D60-CAPTURE.log:21-23`. A "normalised" value would be
re-derived from a sentence — which is what the vector regime exists to stop.

**Against the synthetic constant.** `ots_writer::FETCH_DATE = 1_785_000_100`
is 2026-07-25T17:21:40Z — **eight days before the tokens were issued** — and
its own doc comment says *"No rule reads it."* Two objections, and the second
is decisive. First, it is unreachable: it lives in `anchor::testing`, which
§8.2 forbids the executor to name, so using it means transcribing a literal
and severing it from its declaration. Second, and more important, `fetch_date`
would become the only field in a document of recorded artifacts that records
nothing. `anchor` is the kind whose reviewability rests entirely on
`description` and `provenance` (D101 §7.1); a fabricated value inside it is
the one thing that cannot be repaired by better prose.

**For the recorded value.** It is what a real client writes: the host's own
clock at fetch time. The 128 s is not an error the vector inherits — it is the
fact, faithfully preserved, and A32 exists because of it. Nothing reads the
field (R72 pins that it moves no other slot value), so there is no correctness
tiebreak; the tiebreak is provenance, and only one option has any.

### 9.4 Cases 4/5/6 take the *header* capture, and why

The group is a reconstruction from two campaigns: bodies fetched
2026-08-03T09:03Z, headers 2026-08-07T10:36Z. D79 makes the upgrade group
all-or-nothing and `OtsUpgrade::fetch_date` documents itself as *"when the
upgrade/header was fetched"* — **both**. The group did not exist until its
last component did, so the later instant is the honest one.

Rejected: 1 785 747 818, the upgrade-body capture. It would date the group four
days before the header it carries, which is the single thing the field could
be read as denying.

### 9.5 What the `description` must say — exact claims

Three sentences, each true of the artifacts it describes:

1. *"Cases 1 and 2 carry the capture host's own clock reading. Measured against
   each token's `genTime`, that clock was **128 s slow for both**. The log's
   headline of 129 s (`D60-CAPTURE.log:17-23`) is the largest of three probe
   offsets (+129/+128/+129) and is not the figure for these two artifacts.
   `gen_time <= fetch_date` is FALSE for both cases; that is correct and no
   check may assert otherwise (A32, D59 §6(a))."*
2. *"Cases 4–6 carry `utc_start` of the 2026-08-07 header campaign, which is
   the later of the group's two capture instants — the group is all-or-nothing
   (D79) and did not exist until its header did. That campaign recorded **no**
   clock offset, so this value's skew is unmeasured; it is the recorded instant
   and nothing more."*
3. *"No verification rule reads `fetch_date`. It is pinned here as a
   pass-through: the verdict must echo the input unchanged and move nothing
   else (R72)."*

### 9.6 Residue

None for A22. One thing this does **not** rule: whether `D60-CAPTURE.log`'s
headline sentence should be softened. §4.4 says a capture log is a record and
is not edited; if a future lane disagrees, it needs its own argument, and it is
not A22's.

---

## 10. Ruling 9 — the committed headers

**RULING 9. A22 consumes the header bytes and thereby closes the "consumed by
nothing" rot. Case 5 depends on the bytes, not on any `include_bytes!`. Wiring
`replay.rs` is a different job and is not A22's.**

Confirmed: `A25-upgrade-headers/` is committed (fourteen files) and **no
`include_bytes!` anywhere names it**; `antseal-anchor/src/testing/replay.rs:55-72`
still wires only `A16-A17-live/`'s height-800000 header. D101 §1.6/§9.1's
*"it is untracked"* is stale.

A22 consumes three of those files through `gen_vectors.py`, which reads
`esplora-blockstream-header-960767.txt` and emits its 160 hex characters into
`inputs.cases[].upgrade.block_header_hex` and case 5's `online[].header_hex`.
After A22 the bytes live in a frozen, retained, wasm-verified document — a
stronger home than an `include_bytes!` would give them, and exactly the model
D101 RULING 6 sets out.

What A22 does **not** close: `antseal-anchor`'s transport stubs still cannot
replay a promotion round at a height this project actually attests, because
`replay.rs` knows only 800000. That is a stub-fixture job in the network crate.
**New row, A-domain (next free A112, not registered here):** *wire the three
`A25-upgrade-headers` height/header pairs into `antseal-anchor`'s
`testing::replay::fixtures` so a must-agree promotion round can be replayed
offline at 960767/960768/960771, the heights this project's own upgraded `.ots`
attests.*

---

## 11. Kill criteria

Each is checkable before the vector is written, and A22's first hour is
checking them. D101's K1–K6 stand unchanged except K3.

| # | Criterion | Status |
| --- | --- | --- |
| **K7** | The spliced bytes do not parse under the real `parse_ots` at the real limits | **Measured clear on shape** (§1.4), and **confirmed by construction** on rule order: `merge_upgrade` itself re-parses after every splice (`upgrade.rs:372`), so the archive bodies are already known to splice into parseable artifacts. **Gate**: RULING 2a's test is the executable proof and must be green before the vector is frozen |
| **K8** | The ops do not derive the committed headers' merkle roots | **Clear, measured, all three** (§1.3). Had this failed, cases 4/5 would be unbuildable without a fetch and the lean would have been right |
| **K9** | O5 preempts O4 for the merged artifact, so case 4 renders `pending` not `attested` | **Clear from source** (§1.5) — O4 returns before O5 is reached. This is the criterion most likely to be assumed the other way from `tasks/A.md:265`'s trap note |
| **K10** | The executor cannot be written without naming `anchor::testing` | **Clear** (§8.1). Every needed API is public and ungated. **Gate**: build `wasm-bitmatch` before writing the executor (§8.3) |
| **K11** | The generator cannot reproduce the frozen artifact from the archive | **Clear — I reproduced it in this round** (§1.2), in Python, offline, from committed inputs. D101 K5 does not fire on either reading (§3) |
| **K12** | D87's budget is breached | **Clear, re-measured.** Artifact hex 47 174 chars + headers 640 + envelope/`expect` ≈ 14 KB ⇒ **~62 KB**, ~4.2 % of the 1 461 590 B headroom; v1 goes to ~698 KB / ~33 %. **This revises D101 K3's "~35 KB, 1.7 %"**, which assumed one shared artifact copy and five cases |

**Not kill criteria**, named so they are not mistaken for some: the artifact
being a reconstruction rather than a live client's output (§2.3); the
2026-08-07 campaign's unmeasured clock offset (§9.4 records it as unknown, not
as a blocker); a future legitimate change to `merge_upgrade`'s splice rule
(§3.3 — the cross-check is code and is edited).

---

## 12. Consequences — the exact edit set

| file | edit | § |
| --- | --- | --- |
| `testdata/vectors/v1/anchor/anchor.json` | new — seven cases, four artifacts, `verify_at_unix` 1 786 100 000 | 5 |
| `testdata/vectors/v1/anchor/gen_vectors.py` | new — reads the archive, performs the splice in the pinned order, emits `inputs` only; prints each artifact's sha256 + length for the commit message; **closes D101 §7.2's left-link gap** by recording per-file digests for the two D60 tokens | 3.2, 4.2 |
| `testdata/vectors/v1/anchor/README.md` | new — states that this generator is a **derivation record, not a cross-check**, and why (no independent RFC 3161 reference exists); carries §9.5's three clock sentences | 3.2, 9.5 |
| `crates/antseal-core/src/test_util/vectors_anchor.rs` | new, `vectors_storage_address.rs` shape; **names no `anchor::testing` item**; asserts D101 §3.5's coverage 1–5 with 6 replaced by 6′ and 5a added | 6, 8 |
| `crates/antseal-core/src/test_util/vectors.rs` | `KNOWN_KINDS` entry + dispatch arm | — |
| `crates/antseal-anchor/src/ots/upgrade/tests.rs` | RULING 2a's cross-check: real `merge_upgrade` ×3 over committed fixtures, sha256 `c2bf8b2c…`. **A14's, not A22's** | 3.3 |
| `testdata/vectors/v1/FROZEN.sha256` | `#! kind anchor A22` + digest line + D101 §4.3c's prose paragraph | — |
| `testdata/vectors/v1/INDEX.json` | roster entry (`slug`, `path`, `kind`, `task`, `pins`) | — |
| `testdata/vectors/README.md` | the `anchor` row gains its `inputs`/`expect` shape; budget figure updated to the post-A22 measurement | 11 |
| `testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md` | derivation paragraph: rule, order, intermediate sizes, final sha256, attested heights, pointer to the vector | 4.4 |
| `testdata/anchors/README.md` | D101 RULING 6c's retention sentence for quoted captures | — |
| `tasks/A.md` A22 Accept | replaced by §7.1's four **numbered** rows | 7.1 |
| `tasks/Q.md:1373`, `D94:555`, `TODO.md:540` | drop the count, cite "A22 Accept rows 1 and 2"; quote the former wording | 7.2 |
| `docs/decisions/D101-…md` §9 rows 4/5, §9.2, §3.5 assertion 6, §7.4, §8 K3 | corrected in place with the former wording quoted, per the house rule | 2.1, 2.4, 6.2, 9, 11 |
| **not edited** | `testdata/anchors/A25-bootstrap/D60-CAPTURE.log` — a capture log is a record | 4.4 |
| `docs/decisions/README.md` | this decision's index row — **applied 2026-08-11** under [D119](D119-decision-index-identity-and-the-index-row-sections.md) RULING 4, which demotes the former `## Index row` section to this row | — |

Zero wire bytes. Zero format-version bumps. Zero moved digests. Zero new error
codes. Zero network access. No existing vector is touched.

**Ordering.** Q124 (the `README.md:418` contradiction) lands before or with the
`#! kind anchor` append — D101 §5's ruling, unchanged.

---

## 13. What this record does not decide

- **Whether `merge_upgrade`'s splice rule may change.** §3.3 makes the
  cross-check editable code precisely so that question stays open; it does not
  answer it.
- **Whether `testdata/anchors/` gains a freeze.** D101 §7.3 added a retention
  sentence, not a mechanism, and that stands.
- **The `identity` payload (`subject_dn_der`).** D101 §3.3 defers it to A72.
  Unaffected.
- **Whether `verdict_event_ok` extends to `anchor/`.** D101 §4.3/A108. Case 6's
  arrival changes nothing about the hatch — it moves no existing digest.
- **A109's `MAX_OTS_DEPTH` window.** The spliced artifact is depth 85 and
  supplies one more data point (no shipped artifact approaches 1 024) but the
  decision is A109's and expires at first release, not here.
- **A105/A106.** Named for the property and the doc attribution respectively;
  neither is touched.
- **R17's aggregate pins, R69's vector.** M3 and after-A22 respectively.
