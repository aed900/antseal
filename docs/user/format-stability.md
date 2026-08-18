# Format stability

**Will a bundle sealed today still verify in ten years?** Yes, and this page is
both the promise and the machinery that keeps it honest.

A `.sealproof` bundle is self-contained. Verifying one needs the bundle and a
verifier and nothing else: no antseal service, no account, no network call, and
in particular no dependence on Autonomi being reachable — storage is the
product's bonus, never its proof. What is left to guarantee is the *format*
those bytes are written in. That is what this document states, and it is a
normative policy rather than an intention.

## 1. The promise

`MVP-SPEC.md` line 123 is normative. Under the heading *Format stability
(normative)* it states, in full:

> every released manifest/bundle format version remains verifiable by all
> future CLI and page releases; per-version golden vectors are retained in CI
> indefinitely; the hosted page supports all released versions.

Three obligations follow.

1. **A released version's byte behaviour never changes.** Not its key numbers,
   not its field lengths, not its rejection classes. A change to any of those
   is a *new version*, never an edit to an old one.
2. **A future release still decodes every older version.** Support is added by
   appending a row to a version-dispatch table, never by widening an old
   decoder to be lenient about something a newer version introduced.
3. **The evidence is retained.** Each version's golden vectors are kept
   indefinitely and executed by every future release's CI.

Two things about line 123 deserve saying plainly, because a reader who checks
the citation will notice them.

**It is conditioned on *released*.** Line 123 is a *compatibility* rule: it
binds a format version from the moment that version ships. **As of 2026-08-17
no antseal release has happened** — `docs/decisions/D104-max-ots-depth-lowering-window.md`
§1.5 records three independent confirmations of that.

**The freezes below are stronger than line 123 requires, and are already in
force.** Byte-immutability of the wire registry and of the golden vectors comes
from antseal's own M0 freeze gate (task Q14), not from line 123, and it applied
from the day that gate ran. Line 123 is what the freeze exists to protect once
a version ships. Anyone quoting line 123 as the source of byte-immutability
hands you a conditional whose condition is false today; the freeze is not soft.

## 2. Obligation 1 — a released version's bytes never move

Format v1 *is* a document: `docs/format/registry-v1.md`, with a machine mirror
`docs/format/registry-v1.json`. It is the normative text a third-party verifier
implements from, and its own opening blockquote states the rule:

> Every key assignment, type, presence rule, byte length, enum value, tuple
> shape and reserved range below is **format-permanent**: changing one is a
> format-version event, not an edit (MVP-SPEC.md line 123; the procedure is
> Q27's).

That parenthetical is why this page exists: the frozen registry names *this
policy* as the procedure to follow, and the machine mirror `registry-v1.json`
does the same in its `change_procedure` field. (The line-123 half of the
parenthetical is the one wrong citation in it — the rule is unconditional and
rests on the freeze gate, not on line 123's *released* condition. The registry's
bytes cannot be edited to say so, so the correction lives as a dated entry in
`docs/format/frozen-registry-errata.md`, queued for the next registry version.)

The same blockquote states the direction rule:

> Two directions, not one. A later release may **relax** a v1 rule (a bundle
> that used to be rejected starts being accepted) but may never **tighten** one
> (a bundle that used to be accepted starts being rejected) — line 123 promises
> every released format version stays verifiable forever. Additive v1.x fields
> come from the reserved bands of §9 and from nowhere else.

Both files' exact bytes are pinned by `docs/format/FROZEN.sha256`. The guard is
the `format-freeze` CI lane (`scripts/format-freeze.sh`, authoritative checker
`crates/antseal-core/tests/format_freeze.rs`); once the manifest reads
`#! status frozen`, `--update` refuses to modify or drop an entry and the only
legal change is an addition — a `registry-v2.*` pair beside v1's, never
replacing it. The lane self-tests before it reports: it mutates and deletes a
registry file in a scratch copy of the tree and requires the digest check to go
red *with the right message*, so a green run means something.

The code side is fenced structurally rather than by comment. The v1 decode path
is reachable only through a witness type `V1` (`crates/antseal-core/src/format.rs`)
that has a private field and no public constructor; the only place that mints
one is the version dispatcher, after it has read the discriminant and found it
equal to 1. A v2 decoder therefore *cannot* be added as a second row of v1's
table — it takes a `V2` witness, which is a different type. "Just make the v1
decoder accept the new optional key too" is not a one-line edit that slips
through review; it does not compile.

## 3. Obligation 2 — every future release still decodes every older version

`antseal_core::format::SUPPORTED_VERSIONS` is the authoritative list of what a
given build decodes. It grows by appending; it never edits or removes an entry.
Today it is `[1]`.

The version discriminant is map key 0 in both versioned top-level maps (the
manifest body and the bundle), and canonical CBOR maps ascend, so the version is
the first thing on the wire and is read before anything else is parsed. An
artifact declaring a version this build does not know is rejected as
*unsupported version*, naming the versions the build does support — a distinct
class from any integrity failure. "This bundle needs a newer verifier" and "this
bundle has been tampered with" are different sentences, and antseal never
conflates them.

## 4. Obligation 3 — the evidence is retained, per version, indefinitely

Golden vectors are the record of what a version's bytes meant. They live in
`testdata/vectors/v<n>/` and the retention rule is that a version directory,
once created, is kept forever: nothing ages out, is archived, or is pruned — not
when a newer version lands, not when the old format stops being *emitted*. Old
bundles must keep verifying, so the vectors that pin the old format must keep
running.

The enforcement (task Q6, executed at the Q14 gate) is:

- **`testdata/vectors/v<n>/FROZEN.sha256`** pins the exact bytes of every
  committed vector of that version *and* is that version's must-exist list.
  Three failure classes, not one: modified (digest mismatch), **deleted**
  (`MISSING` — the class a test runner structurally cannot see, because it can
  only fail on files it finds), and committed-but-unlisted.
- **Two independent layers**, both required: coreutils `sha256sum -c`, which
  shares no code with antseal so a bug in our own hasher cannot make a tampered
  tree look clean, and `crates/antseal-core/tests/vector_freeze.rs`, the
  authoritative checker carrying the tests-of-the-test for every failure class.
- **The `vector-freeze` CI lane** (`scripts/vector-freeze.sh`) runs both on
  every push, and self-tests first: it mutates one frozen byte and deletes one
  frozen file in a scratch copy and requires the digest check to go red by name.
- **Discovery is a directory walk** in both the vector runner and the freeze
  guard, so a retained version needs no per-version wiring and cannot be
  forgotten. Adding `v2/` neither disturbs nor releases `v1/`.
- **`testdata/vectors/v<n>/INDEX.json`** is the per-version roster — what
  exists, who owns it, what it pins. It and the freeze manifest are mutually
  enforcing (`crates/antseal-core/tests/vector_index.rs`), and the roster's
  `format_version` must name a version `SUPPORTED_VERSIONS` lists, so a
  retained version's vectors and its decoder can never drift apart.

Deleting a retained version is not a maintenance action. It would silently drop
the guarantee that its format still verifies.

The policy statement lives in `testdata/README.md` ("Vector retention policy")
and the mechanics — directive vocabulary, the before/after-freeze rules, the
index contract — in `testdata/vectors/README.md`. This page does not restate
them; it references them, and owns the criteria in §7 below.

## 5. Both verifiers support every released version

There are two ways to verify, and the obligation binds both.

**The CLI** links `antseal-core`, so its accepted set *is* `SUPPORTED_VERSIONS`.

**The hosted page** at `https://antseal.org/` runs the same `antseal-core`
compiled to WebAssembly — all verification lives in the library, so there is no
second implementation that could fall behind. The page reports its own
capability from the module's own export rather than from injected HTML: the
footer renders `formats <list>` straight from `supported_format_versions`
(`crates/antseal-wasm/src/build_info.rs`), and the result panel prints the
verified bundle's own format version. A stale page beside a fresh module, or the
reverse, cannot present a consistent-looking footer.

That the two agree is not assumed. The `wasm-bitmatch` CI lane executes the
committed vectors natively and under wasm32 and requires byte-identical results.
The `cross-os` lanes run the vector-consuming suites on Linux on every push, and
on macOS and Windows on every pull request and once a week, so a
platform-dependent difference in how a vector is read cannot hide.

The standing obligation to extend that coverage with every version released —
CLI, wasm32 and the page path, over the full historical set, plus a release
checklist item that forbids shipping a version bump without its vectors — is
tracked as task **R28** and is continuous rather than one-off.

## 6. Unicode tables are retained per recorded version

This is the subtlest way an aging bundle could be broken, so antseal designs
against it explicitly.

Text files get a canonical rendition — UTF-8, NFC-normalized, LF line endings,
no BOM — and every commitment is over those canonical bytes. **NFC depends on
the Unicode version.** A verifier that re-normalized with whatever tables it
happened to ship would eventually compute a different canonical form for the
same honest input, and an untouched ten-year-old bundle would be reported as
tampered. That is a false accusation produced entirely by the verifier, and it
is the failure this rule exists to prevent.

So:

- The Unicode data version is **frozen at seal time and recorded in the file's
  canonicalization descriptor** (wire registry §7.3, key 3). v1's registered
  value set is exactly `{"unicode-17.0.0"}`, and that value set is inside the
  Q14 freeze.
- A verifier that must recompute canonicalization applies **the
  descriptor-recorded version, never "latest"**.
- v1's table is **Unicode 17.0.0**, shipped by the exact pin
  `unicode-normalization = "=0.1.25"`. The mapping is machine-asserted rather
  than commented: `crates/antseal-core/src/canon/unicode.rs` carries a test
  asserting the crate's own `UNICODE_VERSION` constant equals `(17, 0, 0)`, so
  a dependency bump that changed the data version turns the suite red instead
  of silently re-defining what a seal means.
- Future Unicode versions are **added** to the registry in `antseal-core`.
  Every table ever shipped is **retained forever**; removing, renaming or
  altering a registered entry is a format break. New versions are reachable
  because dispatch goes through a resolved `UnicodeVersion` value, never a raw
  string.
- A descriptor naming a version this build does not register resolves to a
  distinct `UnknownUnicodeVersion` error — again, "you need a newer verifier",
  never an integrity failure.

## 7. Evolution prefers reserved slots to breaking changes

A format version bump is expensive and it is the last resort, not the first
move. v1 was designed with the room to avoid one.

- **Every v1 key assignment lives in `0..=23`** (single-byte CBOR heads). Within
  that band, unassigned keys are **reserved**: their presence in v1 input fails
  with a distinct reserved-slot error naming the key. Keys `>= 24` are not
  reserved for v1.x and fail with the plain unknown-key error. Two error bands,
  on purpose.
- **Each map reserves the remainder of its band**, and the headroom was recorded
  at the freeze so exhaustion is visible before it is reached (registry §9).
- **Three named reserved slots** already exist, one per committed v1.1 item, so
  each can ship as an additive v1.x field rather than a format-version event:
  bundle key 10 `range_reveals` (sub-unit byte-range reveal selection), receipt
  key 3 `chain_inputs` (payment-receipt verification chain), and `sig_alg`
  values 2–15 (future signature algorithms). All three reject-if-present in v1
  with the *same* error a nameless reserved key raises, so assigning one in
  v1.x never changes an existing error code.
- **Reserving is not designing.** None of the three shapes is specified;
  specifying one is a later recorded decision, not an editorial pass.
- **Some things have no reserved space, deliberately.** The manifest envelope
  `{0: body, 1: signatures}` is frozen across all future versions — it is what
  you must parse in order to find the version, so it can never carry a
  version-specific change. Arrays are positional, so a future element cannot be
  "reserved"; extending `byte_range`, `cover_entry` or `path_node` is a version
  bump. That is why per-entry extensibility lives in the enclosing map.
- **An exhausted band is a format-version event, never a key `>= 24`.**

## 8. What forces a format-version bump

A bump is forced when, and only when, a change would alter what a released
version's bytes mean, or which bytes it accepts. Concretely:

| a bump is forced by | why |
| --- | --- |
| Changing any key assignment, type, presence rule, fixed byte length, enum value, tuple shape or reserved range in the registry | the registry's own freeze: these are format-permanent |
| **Tightening** — wanting an artifact a released version accepted to be rejected | the released version may never tighten; the stricter rule has to live in a new version, with the old one still accepting exactly what it always accepted |
| Adding a field where no reserved slot exists: extending a positional array, or adding a key to the manifest envelope | no additive room exists by construction |
| Exhausting a map's `0..=23` band | the alternative, a key `>= 24`, is ruled out |
| Removing, renaming or altering a registered Unicode descriptor value | it changes the canonical form of already-sealed text |
| Changing the bytes of a frozen golden vector of a released version, other than a re-emitted verdict record (below) | the vector *is* the record of what that version's bytes meant |

A bump is **not** forced by, and must not be spent on:

| not a bump | why |
| --- | --- |
| Assigning a **named reserved slot** as a new optional field in v1.x | additive by design, and it raises no new error code |
| **Raising** a parser cap | limits may be raised, never lowered (rules F1–F4, quoted in §10) |
| A recomputed verdict that moves no format surface | the report version is unchanged; the ceremony is a re-emit |
| Setting or changing an artifact-internal limit over a foreign format | verifier policy, outside the freeze — see §10 |
| Fixing prose, comments or citations that move no pinned byte | no wire surface is involved |

The load-bearing asymmetry is the direction rule of §2: relaxing a v1 rule keeps
old bundles verifying, tightening one does not. When in doubt, ask the only
question that matters — *would an honest bundle that verified yesterday stop
verifying?* If yes, it is a bump, whatever else it looks like.

## 9. The freeze procedure for a new version

A new version is frozen the way v1 was, and the ceremony is deliberately
identical (task Q14 executed it for v1). Nothing about v1 moves during it.

This section is the procedure the rest of the tree points at: rule F4 of the
freeze boundary in §10 says that lowering an artifact-internal limit "is a
format-version event and requires the full freeze procedure", and the frozen
wire registry's own `change_procedure` field says the same of any change to its
bytes. Both mean the seven steps below.

1. **Settle the definitions first.** The CBOR profile and its exactly pinned
   encoder, the domain-tag registry, id encodings, length-prefixed HKDF info,
   the pinned Unicode version and the signature context string are decided
   before anything is frozen.
2. **Land `registry-v<n>.md` and its `registry-v<n>.json` mirror beside v1's**,
   never replacing them, and add both to `docs/format/FROZEN.sha256`. The must-
   freeze set is discovered rather than listed, so a new registry cannot land
   unfrozen.
3. **Add the version to the code as its own path**: a new `V<n>` witness type,
   its own decoder entry point and its own dispatch row, then append `<n>` to
   `SUPPORTED_VERSIONS`. The v1 path is untouched by construction, not by care.
4. **Create `testdata/vectors/v<n>/`** with its `INDEX.json` roster and a
   `FROZEN.sha256` starting at `#! status pre-freeze`, and record the must-exist
   obligations as pending entries. The freeze parser **refuses `status frozen`
   while the pending set is non-empty** — that is what makes this gate
   executable rather than prose.
5. **Turn every gate green before the tag exists**: the vector freeze and its
   self-test, the registry freeze, the full tamper matrix, an independent
   cross-check with an empty discrepancy report, the native↔wasm32 bit-match
   over the new vectors, and the traceability rows for the milestone.
6. **Flip the manifests to `#! status frozen`, record the sign-off with names
   and dates, and cut an annotated `format-v<n>-freeze` tag plus a CHANGELOG
   entry.** After the tag, additions are the only legal change to either
   manifest.
7. **Do not ship the version without its vectors.** The release checklist item
   is R28's, and CI fails if a released version's vectors are missing, altered,
   or fail on the CLI, on wasm32, or on the page path.

## 10. The v1 freeze boundary

One boundary is worth stating on a user-facing page because it is the one most
easily misread as a loophole.

antseal's parsers impose numeric limits on two different things, and only one of
them is format surface.

**Inside the v1 freeze** is the *envelope*: the fact that an `.ots` file, an
RFC 3161 timestamp token, an intermediate certificate and a payment-receipt
payload travel as opaque CBOR byte strings in their registered keys, together
with the byte and count caps over those fields and their error codes.

**Outside it** is every numeric limit on the *internal* structure of those
foreign artifacts — DER nesting depth, certificate count and size within a
chain, signed-attribute count, `.ots` operation count and branch depth. Those
are **verifier policy over formats antseal does not own**. They are **not** an
exception to line 123, and no exception is created, named or otherwise.

Three rules make that true rather than merely asserted: such a limit is
evaluated **only in the anchor stage**; an over-limit artifact fails **that
anchor alone**, never the bundle's own integrity verdict; and such a limit may
afterwards be **raised, never lowered**. A limit that can only loosen cannot
retroactively invalidate an honest bundle, which is exactly what line 123
protects — and under those rules no released verifier has ever rendered a
verdict that depends on one of them.

The authoritative statement is the two rows below, reproduced from the decision
record `docs/decisions/D84-anchor-artifact-limits-permanence.md` §7. They are
**byte-identical** to the copies in antseal's freeze checklist (`tasks/Q.md`)
and in `docs/format/anchor-artifact-limits.md` §2, checklist markers included,
because `scripts/check-traceability.py --freeze-boundary` compares all three
byte for byte and fails if any drifts. Edit the record first, then every copy.

<!-- FREEZE-BOUNDARY:BEGIN — D84 §7 verbatim. Byte-identical copies live in `tasks/Q.md` (Q14), `docs/format/anchor-artifact-limits.md` §2 (A27) and here; `scripts/check-traceability.py --freeze-boundary` fails if they drift. Edit D84 first, then all three copies. -->

- [ ] **Anchor-artifact freeze scope (D84).** Inside the v1 freeze: the
  anchor **envelope** — that an `.ots`, a TSA token, an intermediate
  certificate and a receipt payload are opaque CBOR `bstr`s in their
  registered keys (`docs/format/registry-v1.md` §7.8, §7.9); D10's byte and
  count caps over those fields — rows 6, 7, 8, 9, 16, 17, 18, 19:
  `MAX_OTS_ANCHOR_COUNT`, `MAX_TSA_ANCHOR_COUNT`, `MAX_INTERMEDIATE_COUNT`,
  `MAX_TX_HASH_COUNT`, `MAX_OTS_BYTES`, `MAX_TSA_TOKEN_BYTES`,
  `MAX_CERT_BYTES`, `MAX_RECEIPT_PAYLOAD_BYTES` — with their error codes;
  and rules **F1–F4** of D84 §4 (limits are
  evaluated only in the anchor stage; an over-limit artifact fails that
  anchor alone as `invalid`; limits may afterwards be raised, never
  lowered). **Outside the v1 freeze:** every numeric limit on the
  *internal* structure of those artifacts — DER nesting depth, certificate
  count and size within a validated chain, signed-attribute count, `.ots`
  op count, operand length, branch depth/width, attestation count. Those
  are verifier policy over foreign formats, are set at M2 against A25's
  recorded real artifacts (MVP-SPEC.md lines 153 and 155 place them there),
  and are **not** an exception to line 123 — under F1–F3 no released
  verifier ever rendered a verdict that depends on them, because M0/M1
  rendered every anchor `absent` (R12 replaced that stub at M2, and this
  row is the historical statement it was always meant to be).
- [ ] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage populates anchor states that
  report v1 **already carries** — `AnchorState::ALL` is all seven at the
  freeze — so R12 moves recomputed verdicts, not format surface, and
  `REPORT_VERSION` stays 1 (**D94**: a VERDICT EVENT re-emits the frozen
  vector under the full ceremony and bumps nothing). A bump remains
  available for a genuine field addition; line 123's promise is that v1
  reports remain verifiable, not that v1 is the last version.

<!-- FREEZE-BOUNDARY:END -->

## 11. What this page does not promise

- **It is not a promise about time.** Format stability says an old bundle still
  parses and still verifies its own integrity. What its timestamp anchors are
  worth is a separate question with its own answer — see
  `docs/user/timestamp-authorities.md`.
- **It is not a promise about Autonomi.** The evidence layer is offline by
  construction and no verdict depends on the network being reachable. If
  Autonomi were gone tomorrow, a `.sealproof` in your possession would verify
  exactly as it does today; only the optional storage-linkage re-fetch would be
  unavailable.
- **It is not a promise that v1 is the last version.** It is the promise that a
  v1 bundle stays verifiable, forever, by every release that comes after it.

## Where to check any of this yourself

| claim | where it is enforced |
| --- | --- |
| v1's normative text cannot change | `docs/format/registry-v1.md`, pinned by `docs/format/FROZEN.sha256`; lane `format-freeze` |
| v1's decoder cannot be widened | the `V1` witness type in `crates/antseal-core/src/format.rs` |
| every version's vectors are kept and run | `testdata/vectors/v<n>/FROZEN.sha256`; lane `vector-freeze`; policy in `testdata/README.md` |
| the vectors and the decoder cannot drift apart | `testdata/vectors/v<n>/INDEX.json` and `crates/antseal-core/tests/vector_index.rs` |
| the page verifies what the CLI verifies | lane `wasm-bitmatch`; `supported_format_versions` in `crates/antseal-wasm/src/build_info.rs` |
| the Unicode table matches its recorded version | the pin assertion in `crates/antseal-core/src/canon/unicode.rs` |
| the freeze boundary above has not drifted | `python3 scripts/check-traceability.py --freeze-boundary` |
