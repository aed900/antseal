# D86 — The decode layer in the user-facing verdict, and the two `layer()` accessors

- **Status: RESOLVED — two answers.** (A) The decode layer **never enters
  `VerificationReport`**, in v1 or any future version: the report is a
  success-only artifact and `layer` is already the report's word for two
  unrelated things. (B) The two accessors are reconciled by making the
  layer **total on both types** — `Option` is dropped, and the manifest
  side derives its layer from a new `ManifestError::map()`. This
  **overturns** the lean recorded in tasks/F.md F26, which proposed
  harmonising *downward* (bundle arm returns `None` for schema
  rejections).
- **Date: 2026-07-28**
- **Owning task: F26** (implemented by F26; consumes F6/F9/F15; constrains
  U30/D65 at M3)
- Index note: `docs/decisions/README.md` (which other planners are editing
  concurrently) gains its row at merge — the verbatim row is in §10.

## Context

F15 asserted the decode layer on all twenty format tamper fixtures and
found the two accessors disagree about what "no layer" means:

- `SealProofError::layer()` → `Some(ProofLayer::Bundle)` for **every**
  layer-1 arm, schema rejections included (`bundle-reserved-key`), because
  a `SealProofError::Bundle` is layer 1 by construction;
- `ManifestError::layer()` → `None` for a schema rejection, because such
  an error names its own *map*, which is more precise than a layer.

Read together, `layer == null` means "schema rejection **inside the
manifest**", which no caller would guess. The caveat is currently stated
in three places (`docs/testing/error-code-contract.md` §2,
`testdata/tamper/format/README.md`, `FormatFixture::layer`'s doc comment)
because a reader hits it immediately.

F26 framed the risk as a freeze risk: "cheap now, expensive after Q14 if
the answer turns out to be *yes, and it is part of the report's byte
format*". §1 shows that route is closed, and §2 shows the defect is worse
than the one F26 named.

## 1. The freeze risk does not exist — the report cannot carry a layer

Three facts, verified against the code and the committed vectors at
`aa169ac`:

1. **The report is success-only.** D27 §4: "*The report never carries
   errors. `VerificationReport` exists only for a bundle that passed the
   evidence pipeline; failures live in `VerifyError`/`VerifyFailures`.*"
   `crates/antseal-core/src/verify/report.rs` restates it at module level.
   A decode layer is a property of a *failure*. On the one code path where
   a report exists, there is no decode error and therefore no layer to
   report. There is no field to add.
2. **No `layer` key is in the report bytes today.** The string `layer`
   occurs **zero** times in
   `testdata/vectors/v1/report/verification-reports.json` — across all 21
   pinned `report_json` byte strings and the `report` mirrors. The
   `VerificationReport` declaration order is
   `report_version, work, evidence, storage_linkage, anchors,
   supporting_evidence, reveal`; no member of any nested type is named
   `layer`.
3. **The word is already taken, twice.** `evidence` is the **evidence
   layer** (MVP-SPEC.md line 118) and `storage_linkage` is the
   **storage-linkage layer** (line 119) — the report's single most
   load-bearing distinction ("storage is the product's bonus, not its
   proof"). A `layer` field meaning "which of three CBOR decode passes"
   would sit two fields away from the two things the spec calls layers.
   In a byte format that freezes forever, that is disqualifying on its
   own.

So the expensive-after-Q14 scenario F26 guarded against is structurally
unreachable, and D86 is a normal engineering decision made on its merits.

## 2. The real defect: the fixture table's third column is null exactly where it is needed

F15's thesis, recorded in `docs/testing/error-code-contract.md` §2, is
that the `(code, layer)` pair "*is* pairwise informative" and is therefore
"the finer instrument a per-layer code family would have been". The
committed table contains a counterexample:

| fixture | surface | code | layer |
| --- | --- | --- | --- |
| `body-unknown-key` | `Manifest::decode` | `manifest-unknown-key` | `null` |
| `envelope-unknown-key` | `Manifest::decode` | `manifest-unknown-key` | `null` |

Two deliberately different mutations, at two different layers, with an
identical observable. `envelope-unknown-key` exists to prove the
envelope's own strict pass rejects an unknown key — and its assertion
(`code == "manifest-unknown-key" && layer == null`) is satisfied verbatim
by the body fixture. **The fixture cannot distinguish what it was written
to distinguish.** `format_tamper_fixtures.rs`'s message "`{}` did not fail
at its mapped layer" is, for this pair, unfalsifiable.

This is the defect worth fixing, and F26's proposed fix (harmonise
downward) does not touch it. It is not a Q14 deadline — nothing here is
frozen — but it *is* a pre-M3 deadline: the `--json` failure envelope
(U30, schema stability D65, due M3) will be designed by someone reading
error-code-contract §2, and a false claim there is inherited.

## 3. Decision A — the decode layer never enters `VerificationReport`

**Normative, permanent, and stated in the error-code contract:**

> The decode layer is **pipeline context for a failure**. It is never a
> field of `VerificationReport`, in v1 or in any future report version,
> because the report exists only for a bundle that passed (D27 §4) and
> because `layer` is already the report's word for the evidence layer and
> the storage-linkage layer (MVP-SPEC.md lines 118/119).

Consequences:

- **`crates/antseal-core/src/verify/report.rs` is not edited by F26.** No
  field is added, none is reordered, none is renamed. `REPORT_VERSION`
  stays whatever R32 sets it to.
- The layer's three sanctioned homes are: the error types (Rust API,
  §4), F15's fixture table (test evidence, §6), and — at M3 and only by
  U30/D65's own decision — the CLI/page **failure** envelope, which is a
  different artifact from the report.
- **Constraint on U30/D65, recorded here so it is not rediscovered:** if
  the failure envelope carries the decode layer, its JSON field name is
  **`decode_layer`**, never `layer`. `layer` is reserved, permanently, for
  the two spec-named verdict layers. This does not decide *whether* U30
  carries it — that stays D65's.

## 4. Decision B — the layer becomes total on both types

`Option<Layer>` is the wrong type: `None` currently encodes the *positive*
fact "this is a manifest schema rejection" as an absence. The fix is not
to make the other accessor also lie by omission (F26's lean, §8) but to
delete the absence: **the layer is always known, because the decoder that
raised the error always knows which map it was reading.**

### 4.1 `MapId` gains a layer projection

`crates/antseal-core/src/manifest/registry.rs`, on `impl MapId`:

```rust
    /// Which of the two manifest decode layers this map is read in
    /// (registry §7.6.3). The envelope is layer 2; every other map is a
    /// sub-map of the body byte string and is therefore layer 3.
    ///
    /// This is a *coarsening* of the map, not a competitor to it: a
    /// schema rejection still names its own map, which is strictly more
    /// precise. The layer exists because the bundle side has no `MapId`,
    /// so the layer is the finest thing the two error families share
    /// (D86 §4).
    #[must_use]
    pub const fn layer(self) -> crate::manifest::Layer {
        match self {
            Self::Envelope => crate::manifest::Layer::Envelope,
            Self::Body | Self::FileEntry | Self::Descriptor | Self::UnitEntry => {
                crate::manifest::Layer::Body
            }
        }
    }
```

The match is variant-wildcard-free, so a sixth `MapId` fails compilation
here until it is assigned a layer.

### 4.2 `ManifestError` gains `map()`, and `layer()` derives from it

`crates/antseal-core/src/manifest/error.rs`. **One** new function carries
the whole mapping; `layer()` becomes a two-line derivation, so the two can
never drift:

```rust
    /// The registry map this rejection is about (registry §7).
    ///
    /// Total: every rejection is raised while decoding exactly one map,
    /// and the raise sites already know which — `envelope.rs` and
    /// `body.rs` each open with `const MAP: MapId = …`. Exposing it makes
    /// the "a schema error names its own map" property (F6) reachable
    /// programmatically instead of only by matching the variant.
    ///
    /// The exhaustive, wildcard-free match is the compile-time guard: a
    /// new variant or a new `FixedLenField`/`CondField`/`ContainerField`/
    /// `ManifestListKind`/`EnumId`/`AlgPosition` discriminant fails
    /// compilation here until it is assigned a map.
    #[must_use]
    pub const fn map(&self) -> MapId { /* table in §4.3 */ }

    /// Which decode layer rejected (registry §7.6.3).
    ///
    /// Total — see [`Self::map`]. Before D86 this returned
    /// `Option<Layer>` with `None` for schema rejections, which made
    /// `layer == null` mean "schema rejection *inside the manifest*" and
    /// left `manifest-unknown-key` at the envelope indistinguishable from
    /// the same code at the body (D86 §2).
    #[must_use]
    pub const fn layer(&self) -> Layer {
        self.map().layer()
    }
```

### 4.3 The `map()` table — normative, verified against `registry-v1.json`

Every row was checked against `docs/format/registry-v1.json`'s
`maps[].fields`. **The implementer must not reproduce this from memory:**
re-derive it from the registry and add the test in §7.4.

| `ManifestError` variant (and discriminant) | `MapId` | layer |
| --- | --- | --- |
| `Envelope { .. }` | `Envelope` | 2 |
| `Body { .. }` | `Body` | 3 |
| `InputTooLarge { .. }` | `Envelope` | 2 |
| `UnknownKey { map }` / `ReservedKey { map }` / `MissingKey { map }` | `map` (carried) | derived |
| `WrongLength { field: SealId }` | `Body` | 3 |
| `WrongLength { field: PathCommit \| RawCommit \| CanonCommit \| FineRoot }` | `FileEntry` | 3 |
| `WrongLength { field: UnitCommit \| Nonce \| Address }` | `UnitEntry` | 3 |
| `WrongLength { field: Pubkey(_) }` | `Body` | 3 |
| **`WrongLength { field: Signature(_) }`** | **`Envelope`** | **2** |
| `UnexpectedField { field: CanonCommit \| FineRoot }` | `FileEntry` | 3 |
| `UnexpectedField { field: FineTreeDomain \| UnicodeVersion }` | `Descriptor` | 3 |
| `UnexpectedField { field: UnitCommit }` | `UnitEntry` | 3 |
| `MissingField { .. }` | same as `UnexpectedField`, per discriminant | 3 |
| `EmptyContainer { field: Files \| Pubkeys }` | `Body` | 3 |
| `EmptyContainer { field: Units \| NormalUnits }` | `FileEntry` | 3 |
| **`EmptyContainer { field: Signatures }`** | **`Envelope`** | **2** |
| `ListTooLong { list: Files }` | `Body` | 3 |
| `ListTooLong { list: Units }` | `FileEntry` | 3 |
| `UnknownEnumValue { enumeration: DescriptorKind \| FineTreeDomain \| FineTreeFlag }` | `Descriptor` | 3 |
| `UnknownEnumValue { enumeration: UnitKind }` | `UnitEntry` | 3 |
| `WrongRangeArity { .. }` | `UnitEntry` | 3 |
| `DescriptorDomainMismatch { .. }` | `Descriptor` | 3 |
| `UnsupportedFormatVersion { .. }` | `Body` | 3 |
| `SigPolicyEmpty` | `Body` | 3 |
| `DuplicateAlg { position: SigPolicy \| Pubkeys }` | `Body` | 3 |
| **`DuplicateAlg { position: Signatures }`** | **`Envelope`** | **2** |
| `UnregisteredAlg { position: … }` | as `DuplicateAlg`, per position | — |
| `UnitIdMismatch { .. }` | `UnitEntry` | 3 |

The five bolded rows are the non-obvious ones and the reason §7.4 demands
a registry-sourced test rather than a hand-written one: `signatures` is
key 1 of the **envelope** (registry §7.1), while `pubkeys`/`sig_policy`
are keys 5/6 of the **body** (§7.2). `FineTreeFlag` is
`canon_descriptor` key 1 `fine_tree_present`, **not** a file-entry field.
`InputTooLarge` is `MAX_MANIFEST_BYTES`, which D10 §1 defines as the
**layer-2 input**.

### 4.4 `SealProofError::layer()` becomes total

`crates/antseal-core/src/bundle/proof.rs`:

```rust
    /// Which of the three strict decode layers rejected (registry
    /// §7.6.3). Total: a [`Self::Bundle`] failure is layer 1 by
    /// construction, and a [`Self::Manifest`] failure carries its own
    /// layer ([`ManifestError::layer`]).
    ///
    /// Before D86 this returned `Option<ProofLayer>`, `None` for a
    /// manifest schema rejection — an asymmetry that made `null` mean
    /// "schema rejection *inside the manifest*" (D86 §2).
    #[must_use]
    pub const fn layer(&self) -> ProofLayer {
        match self {
            Self::Bundle { .. } => ProofLayer::Bundle,
            Self::Manifest { source } => match source.layer() {
                Layer::Envelope => ProofLayer::ManifestEnvelope,
                Layer::Body => ProofLayer::ManifestBody,
            },
        }
    }
```

`ProofLayer`, `Layer`, `MapId` and their `Display` impls are unchanged.
`code()` is unchanged on both types. **No error code is minted, renamed,
retired, or re-scoped by D86** — the append-only rule
(`docs/testing/error-code-contract.md` §3) is not engaged.

### 4.5 The fixture column stays `Option`, for a different and better reason

`FormatFixture::layer` and `Observed::layer` keep type
`Option<&'static str>` / `Option<String>`. After D86 the rule is a
**surface** property, not an error property:

> `layer` is `null` **iff** the fixture's surface is not a layered
> decoder. Exactly one surface qualifies: `Surface::Canonical`
> (`check_canonical`), the schema-agnostic strict pass, which has no
> notion of layers. `Manifest::decode` and `SealProof::decode` always
> report a layer.

That is a rule a reader can state in one line, which the current rule is
not.

## 5. What R32 must know (asked for explicitly; the answer is "nothing")

**D86 does not touch the report byte format and therefore does not couple
to R32.** No field is added to `VerificationReport`, so no report vector
changes, `REPORT_VERSION` is unaffected, and
`testdata/vectors/v1/report/verification-reports.json` and its
`FROZEN.sha256` line are untouched by F26. The two tasks may land in
either order, in parallel, without a merge hazard: F26 edits
`manifest/`, `bundle/`, `test_util/`, `tests/` and
`testdata/tamper/format/`; R32 edits `verify/report.rs` and
`testdata/vectors/v1/report/`. The file sets are disjoint.

The one ordering constraint that does exist is **F26 before or with the
error-code-contract edit**, since §7.3 replaces a paragraph F15 wrote.

## 6. Exact committed artifacts to re-emit

Only one, and its diff is three values.

**`testdata/tamper/format/FIXTURES.json`** — regenerate with

```sh
cargo test -p antseal-core --features test-util --test format_tamper_fixtures \
  -- --ignored emit_format_tamper_fixtures
```

The diff a reviewer must see, and nothing else in the `fixtures` array:

| fixture id | `expected.layer` before | after |
| --- | --- | --- |
| `body-reserved-key` | `null` | `"manifest body"` |
| `body-unknown-key` | `null` | `"manifest body"` |
| `envelope-unknown-key` | `null` | `"manifest envelope"` |

`body-nesting-too-deep` **stays `null`** — its surface is `check_canonical`
(§4.5), and D10 §6 records why the over-deep case cannot be a pipeline
row. Every `sha256`, `len`, `code`, `row`, `mutation`, `surface` and
`base` value, and both `bases` entries, must be **unchanged**: D86 changes
attribution, not bytes. A digest change in this diff means the
regeneration picked up unrelated drift and must be investigated before
commit.

The `_readme` block is generated from `build_table()` in
`crates/antseal-core/tests/format_tamper_fixtures.rs`; its last paragraph
is replaced by §7.2 before regenerating.

**Not re-emitted, and this must be verified rather than assumed:**
`testdata/vectors/**` (unchanged — `scripts/vector-freeze.sh` must stay
green with no `--update`), `testdata/tamper/MATRIX.json`,
`testdata/tamper/format/*.cbor` (all 19 committed fixture files),
`testdata/tamper/format/base/*`, `docs/format/registry-v1.json`.

## 7. Verbatim text for the affected documents

### 7.1 `docs/format/registry-v1.md` and `registry-v1.json` — not affected

Checked. §7.6.3's table and the JSON mirror's `decode_layers` describe
layers by *input* and *error class* (`"ManifestError::Envelope"`,
`"ManifestError::Body"`, `"bundle-schema (new, F9)"`). Those statements
stay true verbatim. **No registry row changes, and the registry JSON is
not re-emitted.** `MapId::registry_name` and the 1:1 map test are
untouched.

### 7.2 `crates/antseal-core/tests/format_tamper_fixtures.rs` — the `_readme` tail

Replace the final four `_readme` lines (currently beginning
"`expected.layer` is null for a manifest SCHEMA rejection…") with exactly:

```
"`expected.layer` is null IFF the surface is not a layered decoder —",
"which is only `check_canonical`, the schema-agnostic strict pass.",
"`Manifest::decode` and `SealProof::decode` always report one of the",
"three layers of registry section 7.6.3, for canonicality and schema",
"rejections alike (decision D86)."
```

### 7.3 `docs/testing/error-code-contract.md` §2 — replace the F26 caveat

Delete the paragraph beginning "Caveat a reader hits immediately, and F26
owns:" and its four following lines, and put in its place exactly:

```
The layer is **total** on both accessors (decision D86, 2026-07-28):
`ManifestError::layer()` and `SealProofError::layer()` return a layer, not
an `Option`, for schema rejections as well as canonicality ones. The
manifest side derives it from `ManifestError::map()`, which names the
registry map the decoder was reading; the envelope is layer 2 and every
sub-map of the body byte string is layer 3. That is what makes the
`(code, layer)` pair genuinely pairwise informative: before D86,
`manifest-unknown-key` at the envelope and at the body were one
observable, so `envelope-unknown-key` could not prove it hit the envelope.

The decode layer is **failure context only**. It is not a field of
`VerificationReport` and never will be: the report exists only for a
bundle that passed (D27 §4), and `layer` is already the report's word for
the evidence layer and the storage-linkage layer (MVP-SPEC.md lines
118/119). If U30's `--json` failure envelope carries it (D65's call, M3),
the field is named `decode_layer`.
```

Then **append** a new dated entry to the changelog at the end of the file
— do not edit F15's entry, which is history:

```
- **2026-07-28 (M0 wave 6, F26/D86)** — **no code minted, no code changed.**
  The two `layer()` accessors are reconciled by making the layer total on
  both, deriving the manifest side from a new `ManifestError::map()`. The
  finding that forced it was not the documented asymmetry but its
  consequence: `body-unknown-key` and `envelope-unknown-key` were one
  observable, so §2's claim that the `(code, layer)` pair is pairwise
  informative had a counterexample in the committed fixture table. Three
  `expected.layer` values in `testdata/tamper/format/FIXTURES.json` moved
  from `null` to a layer; no digest, code, or row changed. D86 also closes
  the report question permanently: the decode layer is failure context and
  is never a report field.
```

### 7.4 `testdata/tamper/format/README.md` — the `expected.layer` bullet

Replace the bullet beginning "**`expected.layer`** is which of the three
strict layers…" (and its "null … schema rejection inside the manifest"
tail) with exactly:

```
- **`expected.layer`** is which of the three strict layers of registry
  §7.6.3 the failure is attributed to. It is `null` **iff** the fixture's
  surface is not a layered decoder — only `check_canonical` qualifies.
  `Manifest::decode` and `SealProof::decode` attribute a layer to every
  rejection, canonicality and schema alike (D86).
```

The "pairwise informative across the layer …" sentence lower in the file
becomes true as written and needs no edit.

## 8. Losing options, with their real costs

**(i) Leave both accessors as they are; correct only the prose.** Zero
code. Cost: `envelope-unknown-key` stays a fixture that cannot observe
what it was built to observe, and error-code-contract §2 has to be
*weakened* — "the pair is pairwise informative **except** for manifest
schema rejections" — which is exactly the hedge that invites the next
contributor to mint `manifest-unknown-key-envelope`, the per-layer code
family §2 exists to forbid. Rejected: the cheapest option makes the
document argue against itself.

**(ii) Harmonise downward — bundle arm returns `None` for schema
rejections (the register's lean).** Small diff. Costs, all real: it
*deletes* true information from two committed fixtures
(`bundle-reserved-key`, `bundle-unknown-key` lose `Some("bundle")`); it
leaves the §2 counterexample untouched, because envelope-vs-body was never
the bundle arm's problem; and restoring the lost discrimination would then
need a **fourth**, manifest-only `map` column in the fixture table — the
same work as (iii), spread over two nullable columns instead of removing
one. Its only genuine merit is that `layer()` would then mean one clean
thing ("which layer's canonical-CBOR pass rejected"), and that merit
survives into (iii) as a strictly larger set. Rejected.

**(iii-lite) Total only where a `MapId` is already carried** (the three
key-band variants). Four lines; fixes the counterexample. Cost: the rule
becomes "the layer is known iff the variant happens to carry a `MapId`",
which is harder to state than either "always" or "never" and is an
accident of the payload rather than a property of the decoder. Rejected
as a final answer, kept as the fallback if §4.3 turns out to have an
ambiguous row (it does not — every row was checked against the registry).

**(iv) `enum { Canonicality(Layer), Schema(MapId) }` (F26's second
suggestion).** Makes the distinction a payload rather than an absence,
which is the right instinct. Costs: `MapId` and `BundleMapId` are two
different types (`manifest/registry.rs` and `bundle/registry.rs`), so the
sum type needs either a third variant or a unifying enum before it can
span both error families; the fixture table's third column becomes a sum
type that has to be flattened to a JSON string anyway; and the
`Canonicality`/`Schema` split re-encodes information already carried by
the code's own family (`cbor-` vs `manifest-`/`bundle-`). §4 gets the same
facts from `map()` and `layer()` as two plain accessors, each
independently useful, with no new type. Rejected as strictly more
machinery for the same facts.

*Note for a future reader:* `BundleError::{UnknownKey, ReservedKey,
MissingKey}` **do** carry `map: BundleMapId`, so a symmetric
`BundleError::map()` is constructible if a caller ever needs bundle
sub-map precision. D86 does not add it: the bundle is one layer, and every
`bundle-` code is unambiguously layer 1 by prefix (D78), so the accessor
would have no consumer today. F27's Notes record it as the next
discriminator to reach for if one is ever needed.

**(v) Put the layer in the report.** Refuted in §1 and §3 — not a
trade-off, a structural impossibility plus a naming collision.

## 9. Permanence

Nothing D86 changes is frozen at Q14:

- `ManifestError::layer`, `ManifestError::map`, `SealProofError::layer`,
  `MapId::layer` are compiled Rust API on an unpublished pre-1.0 crate.
- `testdata/tamper/format/FIXTURES.json` is **not** under the Q6 freeze —
  `scripts/vector-freeze.sh` covers `testdata/vectors/v<n>/` only. It is
  still a committed artifact whose regeneration must be a reviewed diff
  (§6).
- No error code is touched, so §3's append-only rule is not engaged.

What **is** permanent is Decision A: `layer` is reserved forever in the
report's namespace for the evidence and storage-linkage layers, and the
decode layer never becomes a report field. That is the sentence to carry
into Q14's freeze checklist.

## 10. Register row (for `docs/decisions/README.md`, added at merge)

```
| [D86](D86-decode-layer-in-verdict.md) | Decode layer in the verdict — **never a `VerificationReport` field** (the report is success-only per D27 §4, and `layer` already names the evidence + storage-linkage layers, lines 118/119); the two `layer()` accessors reconciled by making the layer **total on both**, derived from a new `ManifestError::map()`. Overturns F26's lean (harmonise *downward*): the real defect was not the documented asymmetry but that `manifest-unknown-key` at the envelope and at the body were **one observable**, so `envelope-unknown-key` could not prove it hit the envelope — a counterexample to error-code-contract §2's own claim. Three `FIXTURES.json` layer values change; no code, digest, or report byte changes; **no coupling to R32** | RESOLVED | 2026-07-28 |
```

## 11. What the implementer must report back

1. **The `map()` table, re-derived — not copied.** State, per row, which
   `docs/format/registry-v1.json` `maps[].fields` entry justifies it, and
   report any row where §4.3 is **wrong**. Five rows are non-obvious
   (§4.3); if any of them is wrong, say so rather than making the test
   match the table.
2. **The `FIXTURES.json` diff, verbatim.** Confirm it is exactly three
   `expected.layer` values and nothing else — in particular that no
   `sha256`, `len`, `code`, or `row` moved. If anything else moved, stop
   and report before committing.
3. **`scripts/vector-freeze.sh` green with no `--update`.** D86 must not
   touch a single golden vector; prove it rather than assume it.
4. **The four other `layer()` assertion sites**, each with its new value:
   `crates/antseal-core/src/manifest/error.rs` (the
   `SigPolicyEmpty.layer()` line — now `Layer::Body`),
   `crates/antseal-core/tests/bundle_codec.rs:443` (removes `SEAL_ID` from
   the **body** → now `ProofLayer::ManifestBody`; its doc comment above
   the test also states the old rule and must be rewritten),
   `crates/antseal-core/tests/codec_properties.rs:334` (the
   `Some(Layer::Body)` unwraps to `Layer::Body`), and
   `crates/antseal-core/src/bundle/proof.rs`'s `exemplars()` table.
5. **A new test, and its name**: that `ManifestError::map()` agrees with
   `docs/format/registry-v1.json` for every field-bearing discriminant —
   the registry-sourced check §4.3 demands. Report what it caught, if
   anything.
6. **Confirmation that `verify/report.rs` was not opened**, and that
   `git diff --stat` contains no path under `testdata/vectors/`.
7. **The wasm32 build and the bit-match lane**, both green
   (`ManifestError` is in the WASM-safe tier and `test_util::tamper_rows_format`
   is compiled for wasm32).
8. Anything in the repo that still states the old rule and is **not** in
   §7 — grep for `schema rejection` and for `layer == null`.
