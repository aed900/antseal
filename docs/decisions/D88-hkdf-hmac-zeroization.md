# D88 — Disposition of the un-zeroized HKDF/HMAC key state (C21 residual risk R1)

- **Status: RESOLVED — option (d), a fourth option C22 did not list: enable
  the non-default `zeroize` feature on the existing `sha2 = "=0.11.0"`
  workspace pin. Measured: it wipes the entire 144-byte `Hkdf<Sha256>`,
  including the block buffer that holds `W` verbatim. C22's premise — "no
  feature fixes it" — is FALSE, and options (a), (b) and (c) are all
  rejected in consequence.**
- **Date: 2026-07-28** (planning; C22 implements; no format impact, no
  golden-vector impact, no API change)

## Context

`docs/zeroization-audit.md` R1 (C21, 2026-07-28) records the highest-severity
finding in that audit: every `derive_*` call in
`crates/antseal-core/src/crypto/hkdf.rs` builds an `hkdf::Hkdf<Sha256>` whose
internal `Hmac<Sha256>` is keyed with the HKDF **PRK**, that `Hkdf::extract`
additionally materialises and discards a raw 32-byte PRK, that both are
`W`-equivalent for that work, and that **neither is zeroized**. MVP-SPEC.md
line 143 requires `zeroize` on `W` and derived keys, so this is a live
contradiction of a normative spec line, carried into the M0 freeze.

R1 then states, and C22's task text repeats, that no fix is available:

> `hkdf = "=0.13.0"` exposes **no** `zeroize` feature […] `hmac = "=0.13.0"`
> *does* have `zeroize = ["digest/zeroize"]` […] but enabling it **would not
> help**.

Both halves of that sentence are individually true. The conclusion drawn from
them is not, and §1 shows why: the mechanism that actually wipes is **drop
glue on fields**, not the `ZeroizeOnDrop` marker trait, and the field that
needs a `Drop` lives in `sha2`, which neither `hkdf` nor `hmac` was examined
for.

## 1. Verification of C22's mechanism claims against the pinned sources

Read from `~/.cargo/registry/src/index.crates.io-.../`, at the exact locked
versions (`Cargo.lock`: `hkdf 0.13.0`, `hmac 0.13.0`, `digest 0.11.3`,
`sha2 0.11.0`, `block-buffer 0.12.1`, `zeroize 1.9.0`).

| # | C21/C22 claim | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | `hkdf =0.13.0` has no `zeroize` feature | **TRUE** | `hkdf-0.13.0/Cargo.toml` has no `[features]` table at all; the only optional dep is `kdf`. |
| 2 | `GenericHkdf<H>` derives `Clone, Debug`, no `Drop`, no `Zeroize` | **TRUE** | `hkdf-0.13.0/src/lib.rs:84-87`. |
| 3 | `hmac =0.13.0` has `zeroize = ["digest/zeroize"]` and our pin does not enable it | **TRUE** | `hmac-0.13.0/Cargo.toml` `[features]`; `Cargo.toml:87` declares `hmac = "=0.13.0"` bare. |
| 4 | `Hmac<D>` comes from `buffer_fixed!(… impl: MacTraits KeyInit)` and `MacTraits` expands to `BaseFixedTraits MacMarker`, which never names `ZeroizeOnDrop` | **TRUE** | `hmac-0.13.0/src/lib.rs:34-39`; `digest-0.11.3/src/buffer_macros/fixed.rs:69-79` (`MacTraits`) vs `:54-65` (`FixedHashTraits`, which *does* name it). |
| 5 | **Therefore no feature fixes it** | **FALSE** | See §2. |

Claim 5 does not follow from claims 1–4, and the reason is visible three
lines further down the same macro. The `ZeroizeOnDrop` arm at
`digest-0.11.3/src/buffer_macros/fixed.rs:464-487` emits **only a marker
impl**:

```rust
#[cfg(feature = "zeroize")]
impl … $crate::zeroize::ZeroizeOnDrop for $name … {}
```

preceded by two `const _` assertions that `$core_ty` and `Buffer<$core_ty>`
already are `ZeroizeOnDrop`. It contains **no `Drop`**. The trait is a claim
*about* the type's fields; the wiping is done by those fields' own `Drop`
impls, run by ordinary drop glue. Whether `Hmac<Sha256>` advertises
`ZeroizeOnDrop` is therefore irrelevant to whether its bytes are wiped.

Two further corrections to R1's account of the exposure, also from source:

- **R1 undercounts.** `expand_multi_info`
  (`hkdf-0.13.0/src/lib.rs:142-163`) **clones** the PRK-keyed HMAC once per
  32-byte output block (`let mut hmac = self.hmac.clone();`) and keeps
  `prev: Option<Output<H>>` — *the derived key material itself* — past the
  loop. `HmacCore::new_from_slice`
  (`hmac-0.13.0/src/block_api.rs:53-69`) leaves a 64-byte `Block<D>` holding
  `key ⊕ 0x5c` (trivially inverted). None of these appear in R1's "one
  stack-resident `Hkdf` plus one discarded PRK array".
- **`W` itself is in the buffer, not just a derivative.** `Hkdf::extract`
  keys the HMAC with the *salt* (empty) and feeds `W` as IKM. `W` is 32
  bytes and SHA-256's block is 64, so `W` sits verbatim in the
  `BlockBuffer` until `finalize` compresses it. R1 describes the exposure as
  "`W`-equivalent"; it is in fact `W` itself, in the clear.

## 2. The measurement

Probe: place the value in a raw allocation the probe owns, poison the
allocation with `0xAA`, construct, `ptr::drop_in_place`, read the bytes back.
`hkdf =0.13.0` / `hmac =0.13.0` / `sha2 =0.11.0`, the workspace's exact pins.
Source kept at
`/tmp/…/scratchpad/hmac-zeroize-probe/` (scratch, deliberately not committed
— C22 re-creates it as the acceptance test described in §6).

| feature set | `Hkdf<Sha256>` (144 B) | `Hmac<Sha256>` with `W` buffered (144 B) | raw `W` recoverable | raw PRK `Output<Sha256>` (32 B) |
| --- | --- | --- | --- | --- |
| *(none — today's pin)* | 114 B non-zero | 113 B non-zero | **yes** | 32 B non-zero |
| `hmac/zeroize` | 66 B non-zero | 65 B non-zero | no | 32 B non-zero |
| **`sha2/zeroize`** | **0 — fully wiped** | **0 — fully wiped** | **no** | 32 B non-zero |
| `sha2/zeroize` + `hmac/zeroize` | 0 — fully wiped | 0 — fully wiped | no | 32 B non-zero |

`sha2/zeroize` alone is sufficient and `hmac/zeroize` adds nothing on top of
it. The chain, all read from source:

1. `sha2 = { features = ["zeroize"] }` gates a real `Drop` on
   `Sha256VarCore` that zeroizes `state` and `block_len`
   (`sha2-0.11.0/src/block_api.rs:89-101`).
2. `sha2`'s `zeroize` feature also forwards `digest/zeroize`
   (`sha2-0.11.0/Cargo.toml`), which forwards `block-buffer/zeroize`
   (`digest-0.11.3/Cargo.toml`), which gates a real `Drop` on `BlockBuffer`
   (`block-buffer-0.12.1/src/lib.rs:433-442`) — that is the buffer holding
   `W`.
3. `Hmac<Sha256>` is `{ core: HmacCore<Sha256>, buffer: Buffer<…> }`
   (`digest-0.11.3/src/buffer_macros/fixed.rs:11-15`); `HmacCore<D>` is
   `{ digest: D::Core, opad_digest: D::Core }`
   (`hmac-0.13.0/src/block_api.rs:14-17`); `<Sha256 as EagerHash>::Core` is
   `CtOutWrapper<Sha256VarCore, U32>` (`sha2-0.11.0/src/lib.rs:34-36`),
   which holds a `Sha256VarCore`. Drop glue runs (1) twice and (2) once per
   HMAC instance, including every clone `expand_multi_info` makes.

### 2b. A second, unrecorded gap the same feature closes

The audit's table E covers only buffers inside `crypto/`. The same probe run
over a plain `Sha256`, fed the GGM child preimage `0x06 ‖ seed ‖ b`
(MVP-SPEC.md line 79; `crypto/domain.rs:95-100`, reached from
`content/ggm.rs:326` `child_seed`):

| feature set | dropped `Sha256` (104 B) | 32-byte GGM seed recoverable from the residue |
| --- | --- | --- |
| *(none — today's pin)* | 95 B non-zero | **yes** |
| `sha2/zeroize` | 0 | no |

GGM covering seeds are secret puncturable-PRF material — a leaked ancestor
seed opens leaves the reveal deliberately withheld
(`docs/security-assumptions.md` §3). **Every** `child_seed` call currently
strands one in a dropped hasher. This is not in `docs/zeroization-audit.md`
at all, and it is a stronger argument for the feature than R1 itself.

## 3. Options, and what each really costs

### (a) Accept permanently — REJECTED

Defensible only under C22's false premise. A fix exists, costs one word of
`Cargo.toml`, changes no bytes and no API. Accepting a documented
contradiction of a normative spec line when the fix is a feature flag is not
a residual risk, it is an unfixed bug with a paragraph attached.

### (b) Upstream a `ZeroizeOnDrop` addition to `hmac`'s `buffer_fixed!` — REJECTED

**As specified it would not compile, and would wipe nothing if it did.** The
`ZeroizeOnDrop` arm emits a marker plus `const _` assertions that `$core_ty:
ZeroizeOnDrop`; `HmacCore<D>` has no such impl, so adding the trait name to
`hmac/src/lib.rs:38` fails the `check_core` assertion. Making it pass needs a
`ZeroizeOnDrop` impl on `HmacCore<D>` bounded on `D::Core: ZeroizeOnDrop` —
i.e. an `hmac` change *and* a `sha2` feature enable. The `sha2` feature enable
alone already produces the wiping; the upstream PR would only add the
advertisement. Cost: an unbounded wait on a third-party maintainer, a re-pin
event under `docs/dependency-policy.md` §4, for zero behavioural delta.

### (c) In-house RFC 5869 extract/expand over a zeroizing HMAC — REJECTED for v1

Rejected on a cost/benefit that C22 could not compute without §1's mechanism
detail:

- It moves a **frozen derivation** (MVP-SPEC.md line 77, HKDF label registry
  lines 94–98) into our own code — a pin-governance event under P7 and
  `docs/dependency-policy.md` §4, taken deliberately or not at all.
- **It is strictly weaker than (d) on its own.** In-house HKDF still calls
  `hmac::Hmac`, so it cannot touch the HMAC's internal SHA-256 states, the
  `BlockBuffer` holding `W`, or `get_der_key`'s 64-byte `key ⊕ 0x5c` block —
  which is the single most directly key-revealing residue in the whole chain
  and lives inside `hmac`, not `hkdf`.
- On top of (d) it would buy exactly two 32-byte stack arrays: the discarded
  PRK and `expand_multi_info`'s `prev`. That is not worth writing our own
  copy of a frozen derivation.
- Closing `get_der_key` as well would mean reimplementing **HMAC**, not
  HKDF — ~60 lines of ipad/opad over `Sha256`, and a second frozen primitive
  in our own code. Not for v1.

Recorded revisit trigger, so this is a deferral and not a dismissal: **if a
future task must also wipe `get_der_key`'s block** (e.g. a hardened-target
build, or an attested-enclave deployment), reopen with (c)+HMAC as one unit,
not (c) alone.

### (d) Enable `sha2`'s non-default `zeroize` feature — **ADOPTED**

One word. Wipes the PRK-keyed HMAC state, the extract-side HMAC state, every
per-block clone, the `BlockBuffer` holding `W` verbatim, and — beyond R1's
scope — every GGM seed and every commitment preimage left in a dropped
`Sha256`. Measured, §2.

## 4. The exact edit

`Cargo.toml`, the workspace `[workspace.dependencies]` entry currently at
line 80. Change:

```toml
sha2 = { version = "=0.11.0", default-features = false }
```

to:

```toml
sha2 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }
```

and extend the comment block above it (currently lines 74–79) with the
justification, naming D88.

**Nothing else changes.** In particular:

- `hmac = "=0.13.0"` stays bare — §2 measured that `hmac/zeroize` adds
  nothing once `sha2/zeroize` is on, and an inert feature is a maintenance
  claim we would have to keep defending.
- No new crate enters the graph. `digest 0.11.3` wants `zeroize ^1.7`,
  `block-buffer 0.12.1` wants `^1.8`; the workspace already pins
  `zeroize = "=1.9.0"` (Cargo.toml:148) as a direct dependency, so the
  feature resolves against the locked version and `Cargo.lock` gains no
  package. Confirm with a no-op `cargo update -w` diff.
- `default-features = false` is preserved, so `alloc`/`oid` stay off and the
  wasm32 surface is unchanged.
- **No golden vector byte changes.** The feature gates `Drop` impls only; no
  `update`, `finalize`, or state-initialisation path is touched. This is
  the invariant §6 makes C22 prove rather than assert.

## 5. Cost, measured and honestly bounded

`sha2/zeroize` is global: every `Sha256` in the process now zeroizes ~104
bytes on drop, including the ones hashing entirely public data (Merkle nodes,
`work_id`, `anchor_digest`). On a quiet machine, one run of a release-mode
microbenchmark over the shapes this codebase actually hashes:

| shape | no feature | `sha2/zeroize` | delta |
| --- | --- | --- | --- |
| SHA-256 over 34 B (GGM child preimage) | 323.4 ns | 339.3 ns | +4.9 % |
| SHA-256 over 65 B (Merkle node) | 657.7 ns | 689.6 ns | +4.9 % |
| SHA-256 over 4 KiB | 20 209 ns | 21 074 ns | +4.3 % |
| HKDF-SHA256, 32 B OKM | 2 721 ns | 2 865 ns | +5.3 % |

**Do not over-trust these numbers.** A second, interleaved run on the same
machine while cargo builds were in flight produced swings of ±50 % in both
directions, i.e. the load noise floor is an order of magnitude above the
effect. The honest statement is: *the effect is small enough that a loaded
machine cannot resolve it, and one quiet measurement puts it near 5 % on
hash-bound work.* The GGM fine tree is the only place in the system where
this could matter at scale (one `child_seed` per tree edge).

**Gate, not a guess** — §6 makes C22 re-measure and hands the number to G18's
perf/memory budget (MVP-SPEC.md line 153). Escalation threshold: **if the
measured regression on G18's fine-tree budget exceeds 10 %, do not silently
absorb it — reopen D88** and evaluate a narrower construction (a
`zeroize`-free hasher type alias for provably-public preimages) as a separate
decision. Below 10 %, land it and record the number.

## 6. What C22 must do, in order

1. Apply the §4 one-line edit and the comment.
2. Prove the no-byte-change invariant **before** anything else is believed:
   `cargo test -p antseal-core --features test-util` green with
   `testdata/vectors/` unmodified, and `scripts/vector-freeze.sh` (no
   `--update`) green. Any vector drift means §4's reasoning is wrong and the
   edit must be reverted, not re-frozen.
3. Re-run the §2 probe as a **committed regression test**, not a scratch
   binary. Home: `crates/antseal-core/tests/zeroization_residue.rs`, native
   only (`#![cfg(not(target_arch = "wasm32"))]` — R5 already records that the
   claim is meaningless under wasm32). Two cases, both using the documented
   NON-SECRET fixture `W = 00 01 02 … 1f` (project rule 6):
   - `dropped_hkdf_state_retains_no_master_secret_bytes` — build
     `Hkdf::<Sha256>::new(Some(&[]), W)` in an owned allocation poisoned with
     `0xAA`, `drop_in_place`, assert every byte is `0x00`.
   - `dropped_sha256_retains_no_ggm_seed` — same shape over
     `child_seed`'s preimage; assert the seed is not recoverable.
     Document the `drop_in_place`-then-read technique and why it is a probe,
     under the project's `unsafe`-needs-documented-invariants rule.
4. Re-run the §5 benchmark on an idle machine and record the four numbers in
   `docs/zeroization-audit.md` R1's new disposition block. Apply the 10 %
   escalation rule.
5. `cargo build -p antseal-core --target wasm32-unknown-unknown` green;
   `cargo deny check` green; `Cargo.lock` diff empty.
6. Land the §7 doc edits.

## 7. Exact documentation edits

### `docs/zeroization-audit.md`

Table D, last row, replace the "Feature that provides it" cell:

> | `hkdf::Hkdf<Sha256>` (internal `Hmac<Sha256>`) | the PRK-keyed HMAC state | **`sha2` feature `zeroize` (D88)** — not `hmac`'s; the wipe comes from `Sha256VarCore`'s and `BlockBuffer`'s `Drop`, reached through drop glue |

Add a row to table E:

> | `Sha256` block buffer (GGM child preimage `0x06 ‖ s_v ‖ b`) | `crypto::domain::tagged_sha256`, reached from `content::ggm::child_seed` | **Wiped** — `sha2/zeroize` (D88). Before D88 the parent seed was fully recoverable from the dropped hasher; measured. |

Replace R1's heading and its "Why it cannot currently be fixed" section with
a dated disposition. The heading becomes:

> ### R1 — HKDF/HMAC internal key state (**RESOLVED 2026-07-28 by D88**; a narrowed residue remains)

and the disposition line, which is the sentence Q14 and the threat model both
quote:

> **[2026-07-28, D88]** Resolved by enabling the non-default `zeroize`
> feature on the `sha2 =0.11.0` pin: drop glue then wipes the PRK-keyed HMAC
> state, both SHA-256 chaining states, every per-block clone, and the block
> buffer that held `W` verbatim — measured, not inferred. C21's finding that
> "no feature fixes it" was wrong: `digest`'s `buffer_fixed!` `ZeroizeOnDrop`
> arm is a marker impl with no `Drop`, so the `ZeroizeOnDrop` bound on
> `Hmac<D>` was never the mechanism. **Narrowed residue, accepted
> permanently:** four plain `hybrid_array::Array` stack temporaries have no
> `Drop` under any feature — the discarded PRK in `Hkdf::extract`,
> `expand_multi_info`'s `prev` OKM block, `get_der_key`'s 64-byte
> `key ⊕ 0x5c` derived-key block, and `finalize_fixed_core`'s inner hash.
> Closing them means reimplementing HKDF *and* HMAC in-house, which moves two
> frozen primitives into our own code; option (c) alone would close only the
> first two. Exposure is stack-resident, never heap, never logged, never
> serialized, for the duration of one derivation — the same window in which
> `W` is resident anyway.

Update the "Honest part" preamble: R1 is no longer "a genuine gap in a
third-party crate with no available fix" — say **four residual risks stand;
R1 is resolved with a narrowed, permanently accepted residue.**

### `docs/security-assumptions.md`

The frozen block is **not** touched — this is an operational property, and
that doc already says so ("this audit is an operational property, not a
format assumption, so it sits outside that freeze"). Add one paragraph to
**Notes outside the freeze**, before "Related records":

> **Secret residue in dropped hashers (D88).** Enabling `sha2`'s non-default
> `zeroize` feature makes every dropped `Sha256`/`Hmac<Sha256>` wipe its
> chaining state and block buffer. This matters to class 3 (GGM PRG hiding)
> more than to the HKDF finding that prompted it: before D88, every
> `child_seed` call left its parent seed recoverable in a dropped hasher, and
> a leaked ancestor seed opens leaves a reveal deliberately withheld. The
> assumption itself is unchanged — this is about whether the secret the
> assumption is stated over survives its own function call.

### `docs/dependency-policy.md`

§1 (the exact-pin class) gains a note under the AEAD/HKDF/SHA-2 stack row:

> `sha2`'s **`zeroize` feature is load-bearing** (D88): dropping it silently
> restores recoverable `W` and GGM-seed residue in dropped hashers. Treat
> feature removal as a version bump under §4, and note that the compile-time
> `ZeroizeOnDrop` assertions in `crypto.rs::zeroization_sweep` do **not**
> catch it — the wipe is drop glue, not a trait bound. The §6 residue tests
> are the only guard.

That last sentence is the important one and is why step 3 of §6 is not
optional: this is a property with **no compile-time detector**.
[Corrected 2026-07-28 by C24 — see the amendment at the end of this record:
there *is* half a detector, and the half that is missing is the load-bearing
half.]

### `tasks/Q.md` — Q14 freeze checklist

One row, verbatim:

> - [ ] **Zeroization dispositions closed (C21/C22/D88).** `Cargo.toml` shows
>   `sha2 = { version = "=0.11.0", default-features = false, features =
>   ["zeroize"] }`; `crates/antseal-core/tests/zeroization_residue.rs` green
>   on native; `docs/zeroization-audit.md` R1 carries the dated D88
>   disposition and its narrowed residue; R2–R5 carry dated accepted
>   dispositions. **Known-and-accepted, not open.**

## 8. Permanence

**None of this is format surface.** No wire byte, no error code, no report
field, no vector. It can be revisited at any time without a format version
bump — which is precisely why it should be fixed now rather than deferred
past a freeze that has nothing to do with it.

The one thing that *is* sticky is the `docs/zeroization-audit.md` R1
disposition text: it is quoted by `docs/threat-model.md` §2.10 and by Q14's
sign-off, so a later change must be a new dated entry under the register's
"never by silently rewriting history" rule, not an edit.

## 9. What the implementer must report back

1. The `Cargo.lock` diff (expected: **empty**). If it is not empty, stop —
   §4's "no new package" claim is wrong and D88 must be reopened.
2. Vector-freeze result *before* any `--update`: green or drifted. Drift
   falsifies §4 and the edit must be reverted.
3. The four re-measured benchmark numbers from an idle machine, and whether
   the fine-tree path exceeds the 10 % escalation threshold.
4. Confirmation that the two residue tests fail when the feature is removed
   (run them once with the feature off — a residue test that passes either
   way is worthless).
5. Whether `hmac/zeroize` was left off, per §4.
6. Anything found in `crypto/` or `content/` where a secret preimage is built
   into a buffer **we** own and not wiped — the `Vec` at `ggm.rs:501` in the
   test module is one shape of this; the production paths need the same
   sweep, and any hit is C23's, not C22's.

## Consequences and open actions

1. **C22 implements §4/§6/§7.** M0, size S. It is no longer "decision at M0,
   implementation at M1" — the implementation is one line plus tests and
   belongs before Q14, because the Q14 checklist row in §7 asserts it.
2. **C23 registered** (`tasks/C.md`): sweep `crypto/` and `content/` for
   secret preimage buffers we own and do not wipe, which is the class §2b's
   GGM finding belongs to and which C21's table E scoped too narrowly.
3. **C24 registered** (`tasks/C.md`): a guard that the `sha2` `zeroize`
   feature cannot be silently dropped, since no trait assertion can see it.
4. **G18's perf budget inherits the §5 number.** Whoever runs G18 must know
   the fine-tree budget is being measured *with* `sha2/zeroize` on, or the
   budget will be set against a build that no longer exists.
5. **`docs/zeroization-audit.md`'s "no available fix" wording is wrong on
   disk today** and is quoted in `docs/threat-model.md` §2.10 — both must
   move in the same commit, or the threat model will contradict the audit.

## Outcome

**RESOLVED, 2026-07-28.** Option (d): `sha2 = { version = "=0.11.0",
default-features = false, features = ["zeroize"] }`. Options (a), (b) and (c)
rejected with reasons in §3. C21's R1 is resolved with a narrowed, permanently
accepted residue of four `Drop`-less stack arrays. A second, previously
unrecorded gap — GGM covering seeds recoverable from dropped hashers — is
closed by the same edit. No format impact; no golden vector changes; no new
package in `Cargo.lock`.

---

## Amendment — 2026-07-28, from the C22/C23/C24 implementation

Four errors in this record, found by implementing it. The outcome — option
(d), enable `sha2`'s `zeroize` feature — is unchanged and was confirmed by
measurement. What follows is wrong in the reasoning, not in the verdict.

**1. §9.1's stop-condition is wrong and would have aborted a correct
implementation.** It says the `Cargo.lock` diff is expected to be empty and to
stop if it is not. The diff is *not* empty: `block-buffer` and `digest` each
gain a `zeroize` edge, because `digest/zeroize = ["dep:zeroize", ...]`
activates an optional dependency. What is actually invariant is stronger and
easier to check: `cargo update -w` reports "Locking 0 packages" — no new
package, no version change — and `cargo tree -p antseal-core -e normal` is
byte-identical. **§4's claim ("gains no package") is the correct one; §9.1's
is not.** Use §4's.

**2. §6.3's two-case test specification cannot witness this record's headline
claim.** `Hkdf::new` is `extract(salt, ikm).1`, and the extract context is
consumed *inside*, so the returned `Hkdf` holds only the PRK-keyed HMAC — **`W`
verbatim is not in it.** The implementation's first run proved this the
expensive way: the `Hkdf` case failed on its byte count while its "`W`
recoverable" assertion passed **vacuously**. A third case over
`HkdfExtract<Sha256>` is required, and without it the strongest finding in
this record would have shipped with no test behind it. §2's table is
internally consistent — two columns are two probes — but the summary prose
conflates them.

**3. §5's 4 KiB cost figure (+4.3 %) is wrong.** It is ≈0 %, which is what
the mechanism requires: a fixed ~104-byte wipe amortised over 64 block
compressions. Measured costs are +3.5 % at 34 B, +2.2 % at 65 B, ≈0 % at
4 KiB, +2.4 % on HKDF — all well under the 10 % escalation gate, and scaling
inversely with input size exactly as a fixed per-drop cost must.

**4. §7's "no compile-time detector" is too strong.** `digest` re-exports
`zeroize` under `#[cfg(feature = "zeroize")]` and `sha2` re-exports `digest`,
so `use sha2::digest::zeroize::Zeroize;` fails to compile without the feature
(demonstrated: `E0432`). But it is only **half** a detector, and the missing
half is the one that matters: `hmac/zeroize` forwards `digest/zeroize` too, so
the compile-time check is blind to **`sha2`'s own** feature — and therefore to
`Sha256VarCore`'s chaining-state `Drop`, which is the entire mechanism this
decision turns on. Hence C24's three layers, in three separate test binaries
so that layer 1's compile error cannot bury layers 2 and 3.

**One finding this record missed entirely, now closed by C23.**
`ggm_walk::next_salt` copied the whole 32-byte leaf seed into a local array
merely to truncate it to 16 bytes — a full GGM ancestor seed, un-wiped, on
**every leaf of every fine tree**. It is deleted rather than wiped: the
truncation now reads from the borrowed `Seed32`. This was outside both C21's
`crypto/`-scoped tables and this record's file list.

**Residue counts, measured rather than estimated** (this record's figures in
brackets): dropped `Hkdf<Sha256>` 114 of 144 non-zero [114]; dropped
`HkdfExtract<Sha256>` 108 of 144 with `W` verbatim [113]; dropped `Sha256`
over a GGM child preimage 94 of 104 with the parent seed verbatim [95]. All
zero afterwards, with the probe's control passing throughout so that "all
zero" is a measurement rather than a probe artefact.
