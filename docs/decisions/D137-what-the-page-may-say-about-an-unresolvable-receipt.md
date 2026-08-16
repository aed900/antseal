# D137 — What the verifier page (and the CLI) may say about a receipt whose chain it cannot establish

- **Status: RESOLVED — the lean (arm **(c)**) is CONFIRMED IN DIRECTION AND
  OVERTURNED IN SCOPE, and the row's account of the other two arms is wrong in
  both directions.**
  **Arm (a) is not "a format question wearing a page question's clothes" that
  should "be routed as one". It is a CLOSED format question, closed at the
  freeze, on a threat model.** `docs/format/registry-v1.md` §7.6.1 lists *"any
  chain identifier (`chain_id`, network name) in §7.10"* as one of **six
  checked absences**, with the rationale *"a sealer-written `chain_id` would
  steer the verifier's RPC choice — the same hazard as a bundle-side nonce or a
  bundle-supplied trust root"*. `crates/antseal-core/tests/format_registry_freeze.rs:805-820`
  bans the three names `chain_id`, `chain`, `network` on the receipt map by
  name, and `no_bundle_map_grows_a_deliberately_absent_field` is **green
  today** (measured: 28 passed, 0.04 s). Routing arm (a) would be filing a
  request to un-freeze a checked absence.
  **And the registry already anticipated R85's exact scenario, in the same
  cell**: *"A receipt captured on Sepolia or a devnet simply **fails to
  resolve** against Arbitrum One at v1.1, which is the correct outcome."* That
  is the whole defect in one word. **The registry licenses "fails to resolve".
  The page says "is not on chain".** Those are different propositions, and the
  gap between them — not the pinning, not the guard, not the missing datum — is
  what R85 found.
  **A network datum is unreachable AND forbidden — but a different chain datum
  is reachable and is being thrown away.** Both surfaces call `eth_chainId`,
  compare the answer, and discard it (`index.template.html:593-597`;
  `confirm.rs:243-267`). The chain the probe ran against is **measured, on both
  endpoints, immediately before the receipt query**. The guard *passing* is not
  the bug — **the guard passing is the fact that licenses naming the chain**,
  because an endpoint reporting anything else never reaches the receipt query
  at all.
  **Arm (b) is refused, but the row's argument against it is misattributed.**
  D56 O7 governs **OTS anchors** — `AnchorState::Invalid`, code
  `anchor-ots-online-block-absent` — and the receipt echo produces no
  `AnchorState`, no headline and no state
  (`ReceiptEvidence::is_headline_eligible()` is hard-`false` with, in its own
  words, *"no code path that could make it return `true`"*). There is no
  *"genuine mainnet refutation"* whose *"strength"* (b) could cost. (b) fails on
  a different ground: it would discard a true measurement.
  **Arm (c) as the row states it is INCOMPLETE, and that is the overturn.**
  *"State the probed chain in the rendered line"* is line-only, and
  `ReceiptEcho` has **two** fields — `outcome: ReceiptEchoOutcome` and `line:
  String` (`overlay.rs:450-455`). Correcting only `line` leaves
  `{"outcome":"not-on-chain"}` in the `--json` envelope asserting the identical
  falsehood in machine-readable form — **and the machine-readable half is the
  half D65 exists to let scripters gate on**. The ruled arm is **(c′)**: the
  sentence and the token change together, from one measured datum.
  **The CLI shares the defect, reached from the other direction.** Its guard is
  network-parametric (`guard_chain_id(client, endpoint, network)`,
  `expected_chain_id(network)`), so it *can* be pointed at Sepolia — but the
  network comes from the **operator's** global `--network` flag or
  `default_network`, defaulting to `arbitrum-one`, and **never from the
  bundle**. A third party verifying a Sepolia-sealed bundle with defaults gets
  the byte-identical false sentence at `verify_out.rs:309` (in `overlay_lines`,
  `:300`). **Both surfaces are ruled here, in one act.**
  **And a second defective line the row does not name**: `receipt_confirmed_line`
  says *"confirm the recorded transaction **on Arbitrum**"* — network-blind. On
  `--network arbitrum-sepolia` a testnet confirmation renders as an unqualified
  Arbitrum confirmation, which is **worse in kind**, because a mis-scoped
  *confirmation* reads as evidence **for** the seal. It is fixed here, in the
  same edit, for the same reason.
- **Date: 2026-08-15** (M3 planning round, D137 lane; briefed to overturn the
  lean rather than confirm it. Every claim below was measured in this tree
  today — two `cargo test` runs, the frozen registry read directly, the frozen
  bundle vector decoded, and one subagent measurement lane whose findings are
  quoted with their `file:line`. Nothing is taken on report except where
  marked.)
- **Owning task: R85.** Discharges **D133 §3 R9**'s deferral of the
  receipt-bearing fixture twin. Consumers: **R84** (the emitter), **R27** (the
  browser venue), **R24** (the fetch/render path this corrects), **Q237** (the
  M3 gate).
  Builds on **D8 §3** (the receipt record's internal split, and the chain
  identifier ruled a checked absence), **D10** (the receipt caps), **D55** (the
  pinned Arbitrum pair and the chain-id guard it added over A17's `Do`),
  **D56** (the positive-answer rule for refutations, and O7's actual scope),
  **D64** (the overlay's fixed structure and the receipt echo's presence rule),
  **D65** (the `--json` stability commitment, and what a scripter may gate on),
  **D66** (browser endpoint policy and the override), **D93** (online refutation
  precedence), **D98 rider 4** (the supporting-evidence register), **D130/D131**
  (R18's wording route to the page, and the per-root scan floors), **D132 §5
  R4/R5** (the probe plan, the guard's position, the four disclosed
  identities), **D133** (the page fixture regime).
- **Constraint honoured:** this record writes exactly one file. No crate, no
  template, no task file and no tracker is touched by this lane.

---

## 1. What was measured

### (a) The receipt record carries no network datum, and cannot be given one

`ReceiptRecord` (`crates/antseal-core/src/bundle/schema.rs:738-743`) is three
fields — `tx_hashes`, `block_number`, `payload` — and registry §7.10 assigns
key **3** to a **named reserved** slot, `chain_inputs`, for the v1.1
*verification chain*, explicitly *"reject-if-present in v1"*.

The brief asked me to walk the receipt sub-structure rather than take the row's
word for it, because that is a different question from `VerificationReport`'s
field list. Walked, and the answer is stronger than the row's:

- §7.10's own closing paragraph: *"**And there is no chain identifier,
  deliberately** — a checked absence (§7.6.1), because a sealer-written
  `chain_id` would steer the verifier's RPC choice."*
- §7.6.1's table row, in full, is quoted in the Status block above. Its
  consequence column names the hazard class: *"the same hazard as a bundle-side
  nonce or a bundle-supplied trust root"*.
- §7.10 forecloses the reserved-slot escape too: *"MVP verdict is unchanged and
  unchangeable by this slot … **No reserved slot can promote it**, and none
  should be read as promising to."*
- §12's coverage checklist, line 1585: *"the receipt's **chain** — checked
  absence: no `chain_id` or network name."*
- §13's closed record, row 4: *"A chain identifier is a checked absence. **D8
  §3**."*

And the absence is **asserted, not merely unimplemented**. `crates/antseal-core/tests/format_registry_freeze.rs:805-820`:

```rust
    // Banned on the receipt (D8 §3b): a sealer-written chain identifier would
    // steer the verifier's RPC choice. The chain is pinned by the verifier.
    let banned_on_receipt: &[(&str, &str)] = &[
        ("chain_id",  "the chain is pinned by the verifier (line 137), never named by the artifact"),
        ("chain",     "the chain is pinned by the verifier (line 137), never named by the artifact"),
        ("network",   "the chain is pinned by the verifier (line 137), never named by the artifact"),
    ];
```

**Measured today**: `cargo test -p antseal-core --test format_registry_freeze`
→ `28 passed; 0 failed` in 0.04 s, including
`no_bundle_map_grows_a_deliberately_absent_field`. §7.6.1's own header states
the reason the test exists: *"An absence nobody tests is an absence that grows
back."*

**So the row is right that the datum does not exist, and understates why.** It
does not exist because carrying it was considered, argued and refused on a
threat model, and the refusal is under CI.

### (b) The row's two field-count claims are correct — verified, not accepted

`VerificationReport` (`crates/antseal-core/src/verify/report.rs:147-179`) has
exactly **seven** fields: `report_version`, `work`, `evidence`,
`storage_linkage`, `anchors`, `supporting_evidence`, `reveal`. The word
*network* appears nowhere in the type or its field docs. `ProbePlan`
(`crates/antseal-core/src/verify/plan.rs:113-127`) has exactly **two**:
`blocks`, `receipt`. Both as the row states.

### (c) A different chain datum IS reachable — it is measured and discarded

Page, `verifier-web/index.template.html:592-597`:

```js
  const guard = await rpc(endpoint, "eth_chainId", []);
  if (guard.class) return failed(endpoint, guard.class);
  const reported = quantity(guard.result);
  if (reported === null) return failed(endpoint, "payload");
  if (reported !== ARBITRUM_CHAIN_ID) return failed(endpoint, "wrong-chain");
```

`reported` is a measured `u64` from the endpoint, on the wire, immediately
before `eth_getTransactionReceipt` (`:599`). It is compared and dropped.

CLI, `crates/antseal-anchor/src/arbitrum/confirm.rs:243-267` — same shape, with
the expected value parameterised by network rather than pinned:

```rust
fn guard_chain_id(client: &HttpClient, endpoint: &Endpoint, network: NetworkId)
    -> Result<(), EndpointFailure>
{
    let Some(expected) = expected_chain_id(network) else { /* devnet: refuse */ };
    let reported = hex_u64(...)?;
    if reported == expected { return Ok(()); }
    Err(EndpointFailure::WrongChain { endpoint: …, expected, reported })
}
```

Note what `EndpointFailure::WrongChain` already does
(`crates/antseal-anchor/src/agree.rs:98`):

```rust
#[error("{endpoint}: serving chain id {reported}, expected {expected}")]
```

**The wrong-chain failure already names the chain id. The not-on-chain success
does not.** The datum is in scope, three lines earlier, in both surfaces.

### (d) The rendered claim, and what actually licenses it

`crates/antseal-core/src/verify/wording.rs:898-903`:

```rust
/// Receipt echo: both RPCs agreed the transaction is not on chain.
#[must_use]
pub const fn receipt_not_on_chain_line() -> &'static str {
    "receipt: both RPC endpoints agree the recorded transaction is not on chain — supporting \
     evidence only"
}
```

Frozen byte-for-byte at
`crates/antseal-core/tests/snapshots/verdict-wording.txt:122`.

What was measured to produce it: two nodes, **each having positively answered
that it serves chain 42161**, returned `null` for this transaction hash. What
the sentence asserts: the transaction is not on *any* chain. The second does
not follow from the first, and for a Sepolia-sealed receipt it is false.

The neighbouring line has the same shape of error, one degree weaker
(`wording.rs:886-896`):

> `receipt: both RPC endpoints confirm the recorded transaction on Arbitrum (block 377262147) — supporting evidence only`

*"on Arbitrum"* is true of Arbitrum One **and** Arbitrum Sepolia. The CLI can
be pointed at either. A reader shown an unqualified "Arbitrum" confirmation for
a testnet payment is being told something materially misleading **in the
direction that favours the seal**, which is the direction this project's
positioning discipline (MVP-SPEC.md line 28; `BANNED_TOKENS`) is otherwise
strict about.

### (e) The echo is two datums, not one — and arm (c) reaches only one

`crates/antseal-core/src/verify/overlay.rs:419-455`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptEchoOutcome {
    Confirmed { block_number: u64, status_success: bool },
    NotOnChain,
    Disagreed,
    Failed { failures: Vec<EndpointProbeFailure> },
}

pub struct ReceiptEcho {
    pub outcome: ReceiptEchoOutcome,
    pub line: String,
}
```

`NotOnChain` is a unit variant under `rename_all = "kebab-case"`, so the
`--json` envelope carries `"outcome":"not-on-chain"` beside the sentence
(`verify_out.rs:226-243`). D65's whole subject is what a scripter may gate on
inside `result.overlay`. **An arm that corrects the prose and leaves the token
corrects the half a human reads and leaves the half a machine reads.**

The page, by contrast, needs no JS change for a token edit: `renderOverlay`
reads only `overlay.receipt.line` for this element —
`setLine($("overlay-receipt"), overlay.receipt ? overlay.receipt.line : null)` —
and the page's `token()` helper already handles both encodings (*"a unit
variant is its name, a struct variant is a one-key object"*), so promoting
`NotOnChain` to a struct variant is invisible to it.

### (f) Both surfaces render the module's sentence verbatim — and the sentence is not scan-protected

The anti-divergence machinery already exists.
`crates/antseal-core/tests/verdict_wording.rs`'s
`no_renderer_source_spells_a_frozen_verdict_string` scans two roots with
**per-root floors** (`SCAN_ROOTS = [("crates/antseal-cli/src", 40),
("verifier-web", 1)]`, D131 §5 R2), and fails any renderer that spells a
single-sourced string as a code literal. The CLI renders
`overlay.receipt.line` at `verify_out.rs:309`; the page renders it at
`renderOverlay`. Neither authors it. **That is why one edit to `wording.rs`
moves both surfaces at once.**

But: **`receipt_not_on_chain_line()` is not in `single_sourced()`**
(`verdict_wording.rs:667-757` — the table holds `RECEIPT_CLASS`, which is a
different string, and no receipt-echo line). The sentence is snapshot-frozen
but **not** protected against a renderer copying it. Nothing would redden.

Two mechanics of that scan matter to the implementer and are easy to get
backwards, so they are measured here rather than guessed:

1. `occurrences()` (`verdict_wording.rs:860-876`) **skips comment lines** whose
   trimmed start is `//`, `<!--` or `*`. A `//`-prefixed JS comment in
   `index.template.html` may therefore quote a frozen sentence safely; a
   non-`//` continuation line may not.
2. The planted-fault test `the_source_scan_catches_a_planted_copy_of_a_frozen_sentence`
   (`:936-953`) plants **only** `UNANCHORED_BANNER`. It proves the *predicate*
   is fallible. It proves nothing about whether any given needle is spelled
   correctly, and a misspelled needle is an assertion nothing reachable can
   redden — this project's named dominant defect class.
3. Nothing asserts that a `single_sourced()` needle actually occurs in the
   rendered set. `the_snapshot_covers_every_element_the_accept_row_names`
   (`:529-563`) checks eleven hand-listed rows against the snapshot; the needle
   table is not among them.

### (g) The CLI shares the defect, and its chain is an operator datum

Measured through the whole path:

| step | site |
| --- | --- |
| both endpoints return `null` | `confirm.rs:203-205` — `if result.is_null() { return Ok(None); }` |
| pair agrees on `None` | `confirm.rs:169` — `Agreement::Agreed(None) => ArbitrumConfirmation::Absent` |
| projected into core | `confirm.rs:137` — `Self::Absent => Some(ReceiptConfirmation::NotOnChain)` |
| into the probe log | `crates/antseal-cli/src/verify_host.rs:176-179`, `:323-344` |
| into the echo | `overlay.rs:796`, `overlay.rs:808` |
| printed | `crates/antseal-cli/src/verify_out.rs:309` (in `overlay_lines`, `:300`), indented by `ROW_INDENT` |

Network resolution on the online path
(`crates/antseal-cli/src/commands.rs:585-599`):
`effective_network(globals.network, &config)` = **flag > config > default**,
with `NetworkId::default() == ArbitrumOne`
(`crates/antseal-net/src/network.rs:205-210`). `--network` is `global = true`
(`cli.rs:62-73`); the `Verify` subcommand itself declares only `bundle`,
`--online`, `--live` (`cli.rs:164-178`).

So: **the CLI can be pointed at Arbitrum Sepolia, and nothing in the bundle
tells it to.** Endpoint overrides (`[verify] arbitrum_endpoints`,
`config.rs:541-548`) change the URLs but never the expected id — which is why
overriding to Sepolia RPCs under `--network arbitrum-one` fails closed as
`WrongChain`, exactly as the row records for the page.

The CLI's defect is therefore **the same mechanism with a different entry
point**: the page cannot be told the chain; the CLI can, by someone who already
knows the answer the bundle does not carry. In the ordinary third-party case —
which is the entire point of a `.sealproof` — the two surfaces are
indistinguishable.

*(Taken on report from a measurement subagent, quoted with file:line, and
spot-checked by me at `confirm.rs:243-267`, `endpoints.rs:48-70` and
`network.rs:52-91`; the guard, the selectors and the two chain ids read as
reported.)*

### (h) `antseal-core` cannot see a chain name, and that settles the wording form

`crates/antseal-core/Cargo.toml`'s `[dependencies]` does **not** include
`antseal-net`. Core cannot import `NetworkId`, `ARBITRUM_ONE_CHAIN_ID` or
`NetworkId::as_str`. A wording function that rendered *"Arbitrum One"* would
need a name table inside core, duplicating `NetworkId` across a crate boundary
with no compiler edge to keep them honest — the exact shape D107/D111 exist to
prevent.

**The parameter is therefore a plain `u64`, and the line names the number.**
That is forced by a dependency measurement rather than chosen by taste, and it
has a second virtue: an id core has never heard of still renders correctly,
which a name table cannot promise.

---

## 2. The three arms, dismantled

### (a) — condition the refutation on the seal's own network

**Dead, and not merely "route it elsewhere".** §1 (a) measures that the datum is
a frozen checked absence with a security rationale and three banned field names
under a green CI assertion. Implementing (a) requires:

1. deleting three entries from `banned_on_receipt`;
2. taking registry key 3 or 4 on §7.10, against §7.10's own *"No reserved slot
   can promote it"*;
3. a **format-version event** by D105's classes;
4. and — fatally — accepting a **sealer-written** field that steers the
   verifier's RPC choice, in a document whose assembler *is* the adversary
   (§7.6.1's own framing, MVP-SPEC.md line 121).

Point 4 alone ends it. A hostile sealer writing `chain_id: 421614` would
redirect the verifier to a testnet where the sealer can produce transactions at
will, and the receipt would then *confirm*. **Arm (a) converts a false
refutation into a purchasable false confirmation.** The row prices it as a
routing question; it is a regression.

### (b) — demote the both-null case to a non-conclusion

**Refused — on the right ground, which is not the row's.**

The row says (b) *"costs the genuine mainnet refutation its strength and must be
argued against D56 O7's precedent that a refutation needs a positive answer."*
Measured, **D56 O7 does not reach this mechanism.** O7 reads
(`D56 §5:349-350`):

```text
O7.  upgrade.is_some() && online == Some(NoSuchBlock)  ->  AnchorState::Invalid
                                                           code "anchor-ots-online-block-absent"
```

It is an **OTS anchor state rule**. Its stated reason (D56 §3:202-206) is that
collapsing it *"would let an `.ots` claiming a block beyond the chain tip render
`attested` for ever"* — i.e. O7 exists to stop a **false `attested`** persisting.
The receipt has no such exposure: `ReceiptEvidence::class()` is the single
variant `SupportingEvidenceNoProvenTime`, `is_headline_eligible()` returns
`false` from a method whose doc says *"there is no code path that could make it
return `true`"*, and `ReceiptConfirmation` has, in `model.rs`'s words, *"no path
to an `AnchorState` or to a verified time"* — asserted differentially by
`receipt_evidence_cannot_reach_the_block_evidence_anchor_rules_read`
(`model.rs:1410`). **There is no refutation here to weaken.**

The *principle* the row is reaching for is real and lives in D56 — *"two
endpoints agreeing that X does not exist is agreed evidence … not a missing
entry"* — and it is the principle that **refuses (b)**: two mainnet endpoints
agreeing they hold no receipt for a hash is a genuine, positively-answered
measurement, and collapsing it into "no conclusion" destroys it. `null` from
`eth_getTransactionReceipt` is not an error; it is the JSON-RPC method's defined
successful answer meaning *this node has no receipt for that hash*. It is a
positive answer **about the chain the guard just established**, and the honest
fix is to say which chain — not to stop saying anything.

### (c) — state the probed chain in the rendered line

**Right in direction, incomplete in scope.** §1 (e): `ReceiptEcho` is two
fields. §1 (d): two lines carry the error, not one. §1 (f): the sentence is not
scan-protected. §1 (g): the CLI needs the same edit and is not mentioned in the
arm at all.

There is also a trap inside (c) that a literal reading walks straight into. On
the **page**, the chain id can only ever be 42161 — the guard makes it so. An
implementer who satisfies (c) by interpolating `ARBITRUM_CHAIN_ID` into the
string produces a test whose assertion *"the line names 42161"* **cannot fail**.
On the **CLI** the same datum genuinely varies (42161 / 421614). The ruling
below is written so the varying case is what the test asserts, because that is
the only form of the assertion with teeth.

### (c′) — the arm the row did not list, and the one ruled

Sentence **and** token, both receipt lines that make a presence claim, both
surfaces, from one datum: **the chain id the guard enforced on every endpoint
whose answer was used.**

The mechanism that makes it *true* rather than better-worded: the receipt query
is unreachable from an endpoint that did not positively report the expected
chain id. Page: `:597` returns before `:599`. CLI: `confirm.rs:199` returns
before `:202`. Therefore, at the moment the line is rendered, **every endpoint
that contributed to it has answered `eth_chainId` with exactly the number the
line names.** The sentence stops being an inference about the transaction and
becomes a report of what was asked and answered — which is the standard the
frozen registry itself set when it wrote *"fails to resolve against Arbitrum
One"*.

---

## 3. The ruling

**R1 — Arm (c′). The two receipt-echo lines that assert something about *where*
the transaction is become chain-scoped; the two that assert nothing about
presence do not change.**

| function | today | ruled |
| --- | --- | --- |
| `receipt_not_on_chain_line()` | `…agree the recorded transaction is not on chain — supporting evidence only` | `…agree the recorded transaction is not on Arbitrum chain {chain_id} — supporting evidence only` |
| `receipt_confirmed_line(block, status)` | `…confirm the recorded transaction on Arbitrum (block N…) — supporting evidence only` | `…confirm the recorded transaction on Arbitrum chain {chain_id} (block N…) — supporting evidence only` |
| `receipt_disagreed_line()` | unchanged | unchanged |
| `receipt_failed_line(failures)` | unchanged | unchanged |

The dividing rule, so a later line knows which side it is on: **a line that
asserts the transaction's presence or absence must name the chain it asserts it
about; a line that reports only what the endpoints did need not.** `disagreed`
and `failed` report the probe, not the transaction.

**R2 — The parameter is a `u64` chain id, and the line names the number, not a
network name.** Forced by §1 (h): `antseal-core` does not depend on
`antseal-net` and must not grow the edge to render a label. Signatures become
`receipt_not_on_chain_line(chain_id: u64) -> String` and
`receipt_confirmed_line(chain_id: u64, block_number: u64, status_success: bool) -> String`.
The first stops being `const fn` returning `&'static str`; that is the cost and
it is accepted.

**R3 — The machine-readable token changes in the same act, because the sentence
is only half the claim.**

```rust
pub enum ReceiptEchoOutcome {
    Confirmed { chain_id: u64, block_number: u64, status_success: bool },
    NotOnChain { chain_id: u64 },
    Disagreed,
    Failed { failures: Vec<EndpointProbeFailure> },
}
```

`NotOnChain` becomes a struct variant, serializing as
`{"not-on-chain":{"chain_id":42161}}` — which reads correctly as *"not on chain
42161"* and matches `Confirmed`'s existing struct-variant shape. **No page JS
changes**: the receipt element reads `.line` only, and `token()` already handles
both encodings (§1 (e)). This is a `result.overlay` shape change and therefore
a D65 §"scope" event, not a `REPORT_VERSION` event — the overlay is a sibling
document and never enters the report bytes.

**R4 — The chain id is the value the guard enforced, and it travels beside the
endpoints, not beside the facts.** `ProbeLog` gains it next to
`ProbeEndpoints`, because *which chain* and *which endpoints* are both
properties of the **probe run**, never of the bundle and never of the agreed
facts. `ReceiptFacts` and `ReceiptConfirmation` do **not** change:
`OnlineEvidence` is the input anchor rules read (D55 §4), and a chain id must
never become reachable from there.

**R5 — The illegal state is unrepresentable, not merely unwritten.**
`ProbeLog::with_receipt(probe: ReceiptProbe)` becomes
`with_receipt(probe: ReceiptProbe, chain_id: u64)`, so a probed receipt without
its chain cannot be constructed. `receipt_echo` takes the chain id and returns
`None` for `NotAttempted` exactly as today. This is §7.6.2's move applied to a
runtime type: *"With the split, it cannot be written."*

**R6 — The page reports the chain id it measured; it does not re-assert the
pin.** `evidence.receipt` gains a required `chain_id` number, taken from
`reported` — the value the guard read off the wire — not from
`ARBITRUM_CHAIN_ID`. The two are provably equal *because the guard ran*, and
sourcing it from the measurement rather than the constant is what keeps the
datum a measurement. `crates/antseal-wasm/README.md`'s online-evidence schema
gains the field (it is that schema's documented home); `deny_unknown_fields`
already forces this to be a deliberate, versioned edit rather than a silent
one.

*Refused alternative, recorded so it is not re-proposed*: a per-endpoint
`chain_id` on each `ReceiptResponse`. It invents a disagreement case the guard
already excludes, and creates a second place where "which chain" is decided.
One decider, at the guard.

**R7 — The CLI passes `expected_chain_id(network)`, and the `None` arm is
asserted rather than assumed.** `verify_host.rs` already holds `network` in
scope at the `probe_online` call. `expected_chain_id(NetworkId::Devnet)` is
`None`, and `verify_rpcs(NetworkId::Devnet)` is also `None` — so no pair exists
and no receipt is probed. That coincidence is load-bearing and must be asserted,
not relied on: **if `expected_chain_id(network)` is `None`, no receipt probe may
be attempted.** `devnet_has_no_overlay_and_the_guard_refuses_rather_than_defaults`
(`confirm/tests.rs:646`) already pins both `None`s; the new assertion pins the
implication.

**R8 — The input token `"not-on-chain"` in the page→wasm evidence document does
NOT change.** It names what **one endpoint** answered, and the guard has already
established which chain that endpoint serves, so it is scoped by construction.
Only its doc comment is corrected (`crates/antseal-wasm/src/online.rs:123`, from
*"answered, negatively: not on chain"* to *"answered with no receipt for this
transaction hash"*). Recorded as a **deliberate non-change** so the next reader
does not "finish the job". The two identically-spelled tokens — evidence input
at `index.template.html:601` / `wasm/README.md:70`, and overlay output at
`overlay.rs:437` — are different values in different directions, and only the
output one moves.

**R9 — R18's frozen set is touched, and this is what it costs.** Exactly **three
snapshot rows change** and **two are added**
(`crates/antseal-core/tests/snapshots/verdict-wording.txt:120-122`):

```
receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 42161 (block 377262147) — supporting evidence only
receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 42161 (block 377262147; the transaction reverted) — supporting evidence only
receipt: both RPC endpoints agree the recorded transaction is not on Arbitrum chain 42161 — supporting evidence only
receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 421614 (block 377262147) — supporting evidence only
receipt: both RPC endpoints agree the recorded transaction is not on Arbitrum chain 421614 — supporting evidence only
```

**The Sepolia twins are not decoration — they are the snapshot's teeth.** The
generator (`verdict_wording.rs:310-318`) must emit each parameterised line
**twice, with two different chain ids**. Emitting one instance would let a
hard-coded `42161` sit in the snapshot indefinitely; emitting two makes it
visible as two identical rows and reddens R11's differential.

Re-blessing is the documented act, and it is a **wording-snapshot event**:

```text
ANTSEAL_BLESS=1 cargo test -p antseal-core --test verdict_wording
```

…*"and then justify the diff in review: after R18 the strings are frozen, so a
moved byte here is a **wording-snapshot event**, never a tidy-up"* (that file's
own header). This record is that justification, and the reviewer should check
the diff is exactly the five rows above and nothing in sections 1–10. Note this
is **not** the cheap "additions are not edits" case the header describes for
R19: two shipped sentences are being respelled.

Positioning is unaffected — neither new string contains any of `BANNED_TOKENS`
(`notary`, …) or the state words `proven` / `invalid` / `attested` / `existed no
later than` that
`receipt_lines_carry_no_state_word_and_no_headline_shape`
(`wording/tests.rs:601-618`) forbids.

**R10 — Both receipt lines join `single_sourced()`, and the needles are fixed
clauses, not whole sentences.** Following the R19 precedent recorded in that
table (*"Needles are the fixed tails and labels rather than the whole formatted
sentence: a row carrying interpolated numbers has no literal form to search
for"*):

- `both RPC endpoints agree the recorded transaction is not on Arbitrum chain `
- `both RPC endpoints confirm the recorded transaction on Arbitrum chain `

**This is the assertion that keeps the two surfaces from diverging again**
(§1 (f)): with the needles on the table,
`no_renderer_source_spells_a_frozen_verdict_string` reddens if either
`crates/antseal-cli/src` or `verifier-web` ever spells either clause as a code
literal, so both surfaces must keep taking `overlay.receipt.line` verbatim from
core, and one `wording.rs` edit keeps moving both.

**R11 — One new assertion closes the "needle that cannot fire" hole.** A needle
that does not occur in the real rendered output can never catch anything, and
nothing checks that today. Add, in `verdict_wording.rs`:

```rust
#[test]
fn every_single_sourced_needle_occurs_in_the_rendered_set() { … }
```

asserting each `single_sourced()` needle is a substring of `render_document()`,
naming the missing needle on failure. It is genuinely fallible: misspell a
needle, or respell the sentence it targets, and it reddens.

**R12 — The `wrong-chain` override path is unchanged, and that is asserted at
three levels rather than stated in prose.** See §5.

**R13 — The receipt-bearing fixture twin's `tx_hash` is
`e1e1…e1` (32 × `0xe1`)**, taken from frozen material. See §6.

**R14 — The reasoning lives beside three constants, with one normative home.**
See §7.

---

## 4. Refused shapes

| refused | why |
| --- | --- |
| Arm **(a)** — a network datum in the bundle | §2 (a). A frozen checked absence with a threat model, three banned names under green CI, and — decisively — it converts a false refutation into a **purchasable false confirmation** |
| Arm **(a′)** — put it in reserved key 3 instead | §7.10 forecloses it in writing: *"No reserved slot can promote it, and none should be read as promising to."* Key 3 is the v1.1 *verification chain*, a different subject |
| Arm **(b)** — demote both-null to a non-conclusion | §2 (b). Destroys a true, positively-answered measurement; D56's actual principle cuts against it; and D56 O7 never governed this mechanism |
| Arm **(c)** as literally stated — line only | §1 (e). Leaves `{"outcome":"not-on-chain"}` asserting the same falsehood to every `jq` consumer, which is precisely what D65 exists for |
| Rendering a network **name** (`"Arbitrum One"`) | §1 (h). Core has no edge to `antseal-net`; a name table in core is a second `NetworkId` with no compiler edge keeping it honest |
| Changing the page→wasm **input** token | R8. It names one endpoint's answer, already scoped by the guard; the change would be a coordinated three-file wire edit for a token no human reads |
| Chain-scoping `disagreed` / `failed` | R1's dividing rule. Neither asserts anything about where the transaction is |
| Putting the chain id on `ReceiptFacts` / `ReceiptConfirmation` | R4. Those feed `OnlineEvidence`, which anchor rules read (D55 §4); a chain id must never become reachable from an anchor rule |
| Committing the receipt twin to `testdata/` | D133 §3 R2's regime is unchanged: materialised into `target/`, never committed |
| Giving the twin a **real** Arbitrum One transaction hash | §6. A live probe would then return a real receipt for an unrelated stranger's payment — a **false confirmation**, strictly worse than the defect being fixed |

---

## 5. Both surfaces, and the `wrong-chain` path

**What the page does.** Unchanged fetch sequence; unchanged guard; unchanged
`wrong-chain` classification. It adds one measured number to the evidence
document (R6) and renders the module's corrected sentence verbatim, as it
already does.

**What the CLI does.** Unchanged fetch sequence; unchanged guard; unchanged
`WrongChain` failure and its message. It passes `expected_chain_id(network)`
into the probe log (R7) and prints the module's corrected sentence verbatim, as
it already does.

**What keeps them from diverging.** R10's two needles on `single_sourced()`,
enforced by `no_renderer_source_spells_a_frozen_verdict_string` over both
scan roots with their per-root floors, plus R11 proving the needles can fire.
Neither surface may author the sentence; both must take `overlay.receipt.line`.

**`wrong-chain` is unchanged by construction, and that is asserted three ways:**

1. **Structurally.** The guard returns before the receipt query on both
   surfaces (`index.template.html:597` before `:599`;
   `confirm.rs:199` before `:202`), and no rule in §3 edits either statement.
   The chain id R4 carries is read at the same call the guard already makes.
2. **CLI, already green.** `chain_id_mismatch_is_unavailable_not_agreed`
   (`crates/antseal-anchor/src/arbitrum/confirm/tests.rs:438`) drives two stubs
   reporting `0x66eee`, and asserts `expected == 42_161`, `reported ==
   0x0006_6eee`, and that `failures[0].to_string()` **contains `expected
   42161`** — a message assertion, not an exit code. It must stay green
   unmodified; if it needs an edit, the ruling has been implemented wrongly.
3. **Page, newly asserted.** Today there is **no** browser assertion on the
   page's `wrong-chain` path — D133 records that R27's four cases are block
   cases and *"none needs a receipt"*. The twin R13 mints makes a fifth case
   cost almost nothing: mock `eth_chainId` → `0x66eee` on both endpoints and
   assert the rendered receipt element carries the **failed** line naming
   `wrong-chain`, **and — the negative control — that it does not carry the
   absence line**. Both halves, or the case proves only that something was
   rendered.

A fourth, cheap differential worth having in `overlay/tests.rs`: a `wrong-chain`
run produces `ReceiptEchoOutcome::Failed { .. }` and **never**
`NotOnChain { .. }`, so a `--json` consumer can distinguish *"we could not
ask"* from *"we asked, on chain N, and there is nothing there"*. That
distinction is the entire point of this record and should be machine-checkable,
not only readable.

---

## 6. The test and its negative control

R85's Accept requires *"a test with a negative control"*. There are two tests
and two planted faults.

### 6.1 The test

`the_receipt_lines_name_the_chain_they_were_probed_on`, beside
`receipt_lines_carry_no_state_word_and_no_headline_shape` in
`crates/antseal-core/src/verify/wording/tests.rs`. Core cannot see
`antseal-net`, so the two ids are literals in the test, with a comment saying
why:

```rust
const ONE: u64 = 42_161;      // antseal_net::network::ARBITRUM_ONE_CHAIN_ID
const SEPOLIA: u64 = 421_614; // antseal_net::network::ARBITRUM_SEPOLIA_CHAIN_ID
```

Assertions, in order of what they catch:

1. **The differential — the one that cannot be satisfied by a constant.**
   `assert_ne!(receipt_not_on_chain_line(ONE), receipt_not_on_chain_line(SEPOLIA))`,
   and the same for `receipt_confirmed_line`. Message must contain the literal
   phrase **`two chains must render two different lines`**, and print both
   rendered strings. An implementation that interpolates `ARBITRUM_CHAIN_ID`
   instead of its parameter fails here and nowhere else.
2. **Exact values, read back.** Each of the four renders is compared to its
   full expected string, not to a `contains` predicate. `"42161"` is a prefix of
   `"421614"`, so a containment check on the mainnet id passes on the Sepolia
   line — a substring assertion here would be a fifth member of this project's
   `assertions-that-cannot-fail` family.
3. **The old claim is gone.** No render may contain the unqualified clause
   `is not on chain `, so a "fix" that appends the chain id while leaving the
   universal claim intact fails.
4. **Neither line names the other's chain** —
   `!mainnet_line.contains("421614")`.

### 6.2 The negative controls, verified by MESSAGE

**Planted fault 1 — the parameter is ignored.** Edit
`receipt_not_on_chain_line(_chain_id: u64)` to return the mainnet spelling
regardless. Required observations:

- `the_receipt_lines_name_the_chain_they_were_probed_on` fails **with the phrase
  `two chains must render two different lines` in its message**;
- `the_wording_document_matches_the_committed_snapshot` fails with *"the
  rendered wording set differs from the committed snapshot"*.

Verification protocol, because a nonzero exit proves only that something went
wrong:

```bash
cargo test -p antseal-core --lib verify::wording 2>&1 \
  | grep -F 'two chains must render two different lines'
# and check ${PIPESTATUS[0]} for the cargo status, never $? after the pipe
```

**Planted fault 2 — a renderer copies the sentence.** Add
`out.push("… is not on Arbitrum chain 42161 …".to_owned());` as a **code
literal** (not a comment — `occurrences()` skips `//` lines, §1 (f)) to
`crates/antseal-cli/src/verify_out.rs`, and separately to
`verifier-web/index.template.html` on a non-comment line. Required:
`no_renderer_source_spells_a_frozen_verdict_string` fails naming **that
file and line number**, once per root. This is what proves R10's new needles are
spelled correctly — the existing planted-fault test covers only
`UNANCHORED_BANNER` and would stay green through a misspelled needle.

**Planted fault 3 — a needle that cannot fire.** Corrupt one character of a
`single_sourced()` needle; R11's new test must fail naming that needle. This is
the control on the control.

All three faults are reverted before the row is ticked, and — per this
project's evidence rule — the **failure messages** are pasted into the row's
Notes, not merely the fact that something went red.

---

## 7. The receipt-bearing fixture twin (discharging D133 §3 R9)

**R13, in full.** The twin's `tx_hash` is
`e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1` — 32
repetitions of `0xe1` — with `block_number: 300000000` and the 41-byte
`payload`, taken **whole** from the frozen F13 bundle vector.

Measured from `testdata/vectors/v1/bundle/bundle.json`, case index **5**,
`every-anchor-kind-with-receipt`:

```json
"receipt": { "block_number": 300000000,
             "payload": { "len": 41, "sha256": "b6c87e7f…354a" },
             "tx_hashes": ["e1e1…e1", "e2e2…e2"] }
```

`ReceiptTarget` takes `record.tx_hashes().first().copied()`
(`crates/antseal-core/src/verify/plan.rs:143`), so the emitted plan's `tx_hash`
is deterministically the `e1e1…` entry. Nothing is invented.

**Why this and not something else:**

1. **The emitter gains no bytes of its own.** D133 §2's winning shape was
   *"sourced from **frozen** vectors so the emitter has no independent bytes of
   its own"*, and this is the same move for the receipt half. The material is
   already committed, already under CI, already re-encoded by `vector-freeze.sh`.
2. **It is manifestly synthetic.** Thirty-two repetitions of one byte is not a
   Keccak hash and nobody will mistake it for one or look it up.
3. **A real mainnet hash would be the dangerous choice.** A live probe against
   the pinned pair would return a genuine receipt for a stranger's unrelated
   payment, and the page would render a **confirmation** for a bundle that paid
   for nothing. That is a demonstration of a worse defect than the one being
   fixed.
4. **Under this ruling it demonstrates the fix, not the defect.** D133 §3 R9
   deferred the twin because *"a fixture whose `tx_hash` points at nothing would
   commit a demonstration of the defect"*. After R1, a hash that points at
   nothing renders *"both RPC endpoints agree the recorded transaction is not on
   Arbitrum chain 42161 — supporting evidence only"*, which is **true**.
   **The deferral discharges itself; the ruling is what makes the fixture
   buildable.** The emitter's own note at
   `crates/antseal-core/tests/page_fixtures.rs:280-282` — *"`receipt` stays
   `None`: the receipt-bearing twin is R85's, deferred because its transaction
   hash would point at whatever R85 has not yet ruled"* — is now answered and
   should be replaced by a citation of this record.

**Regime, unchanged:** a third file materialised into
`target/verifier-web-fixtures/` by `ANTSEAL_EMIT_PAGE_FIXTURES=<ABSOLUTE dir>`,
**never committed** (D133 §3 R2). The build is the one line D133 predicted —
add a `receipt` to `parts` in the attested fixture's construction — plus the
assertion that `plan.receipt` is `Some` with the expected 32 bytes, because
otherwise the emitter would be trusted to have done what it says.

**Does R27's suite need it?** Not for the four block cases — D133 §1 (f) proved
one fixture serves all four and none carries a receipt, and **that stands
unchanged**. The twin exists for the two cases *this record creates*: the
chain-scoped absence line, and §5's `wrong-chain` fail-closed case. It is
therefore R85's fixture, not R27's, and R27 cites it rather than owning it.

---

## 8. Where the reasoning is recorded

R85's Accept row 3: *"the next reader of `ARBITRUM_CHAIN_ID` finds the reasoning
beside the constant rather than in a wave record."*

**There are three constants, in three crates, and `antseal-core` — where the
sentence is authored — can see none of them.** So this cannot be one comment,
and the row's singular phrasing needs unpacking. Note also the near-collision
that will mislead a lane: R85 says `ARBITRUM_CHAIN_ID`, which is the **page's**
constant (`verifier-web/index.template.html:337`); `antseal-net`'s is
`ARBITRUM_ONE_CHAIN_ID` (`network.rs:52`).

| site | what goes there | citation |
| --- | --- | --- |
| `verifier-web/index.template.html:337`, at `const ARBITRUM_CHAIN_ID` | The one R85 names. What the guard's success licenses (naming this chain) and what it does not (concluding anything about other chains); that a bundle cannot and must not carry its own chain, with the reason | `D137 §3 R1`, `§2 (a)` |
| `crates/antseal-anchor/src/arbitrum/endpoints.rs:64`, at `expected_chain_id` | That this value reaches the rendered sentence, so changing the table changes what the CLI says; and R7's `None` implication | `D137 §3 R7` |
| `crates/antseal-core/src/verify/wording.rs`, at both parameterised functions | Why the parameter is a `u64` and not a name — core has no `antseal-net` edge — and why `disagreed`/`failed` do not take one | `D137 §3 R1`, `§3 R2` |

**This document is the normative home; the three sites carry a pointer plus the
one sentence each needs locally, never a restatement of the argument.** Prose
duplicated across sites is what D107 and D111 exist to contain, and a fourth
copy of the threat model would be a fourth thing to keep true.

**Mechanical warning, measured**: the page comment must be written with `//` at
the start of each line. `occurrences()` skips lines whose trimmed start is
`//`, `<!--` or `*` (`verdict_wording.rs:864-869`), so a `//` block may quote
the sentence safely — but a continuation line that does not start with one of
those markers is scanned as code and will redden
`no_renderer_source_spells_a_frozen_verdict_string` once R10's needles are on
the table.

**Nothing is added at `crates/antseal-net/src/network.rs:52`.** That constant is
the payment-side definition of Arbitrum One; the verification-side reasoning
does not belong on it, and a comment there would be read by a reader with a
different question.

---

## 9. Corrections this record makes

**To `tasks/R.md` §R85 and its `TODO.md` row:**

1. Arm (a) is not *"a format question … and should be routed as one"*. It is a
   **closed** format question — registry §7.6.1's sixth checked absence, D8 §3's
   closed-record row 4 — and re-opening it would admit a sealer-controlled input
   that steers the verifier's RPC choice. §2 (a).
2. Arm (b)'s stated obstacle is misattributed. D56 O7 is an **OTS anchor** rule
   producing `AnchorState::Invalid`; the receipt echo produces no state and is
   hard-ineligible for the headline. There is no refutation strength to lose.
   §2 (b).
3. Arm (c) is **line-only and therefore incomplete**. `ReceiptEcho` has two
   fields; the token half is the half D65 exists for. §1 (e).
4. *"The CLI shares the guard and should be checked"* — checked: **it shares the
   defect**, through the operator's `--network` default rather than a pin.
   §1 (g).
5. **A second defective line is unrecorded**: `receipt_confirmed_line`'s
   unqualified *"on Arbitrum"*, which mis-scopes a **confirmation** — an error
   in the direction that favours the seal. §1 (d).
6. **The frozen sentence is not scan-protected**: it is absent from
   `single_sourced()`, so a renderer could copy it today and nothing would
   redden. §1 (f).
7. **Size.** The row's *"Size stays XS for the edit"* is correct only for the
   string. The edit ruled here is **S**: two wording functions, one enum, one
   builder signature, the wasm bridge and its README schema, one page field, one
   CLI argument, a snapshot re-bless, two needles, two new tests, one browser
   case and one fixture. The row's own instinct — *"the ruling is the expensive
   half"* — remains right about where the difficulty sat.

**To this lane's brief:**

- The brief asked whether a network datum is *"already in the sealed
  document"*. It is not, **and the more useful finding is that it is
  forbidden** — which is a stronger result than "unreachable", because it
  closes arm (a) permanently rather than deferring it.
- The brief framed arm (c) as *"the cheapest arm"*. Measured, (c) is cheapest
  **only** in its incomplete form; the honest version is a superset of it and
  the row's XS sizing does not survive.
- The brief's instruction to *"measure whether the CLI has the same defect, a
  different one, or none"* has a three-way answer the phrasing does not cover:
  **the same defect, plus a parameter that lets an operator who already knows
  the answer avoid it** — which is no help in the third-party case a
  `.sealproof` exists for.

---

## 10. Spec conformance

- **Line 110** (*receipt as supporting evidence*) — unchanged and reinforced.
  Every ruled string retains the `— supporting evidence only` tail; R4 keeps the
  chain id out of `OnlineEvidence` so no anchor rule can reach it.
- **Line 137** (*"two public Arbitrum RPCs"*, user-overridable; *"distinct from
  the offline cryptographic verdict"*) — the pinned pair, the override and the
  fail-closed guard are all unchanged (§5). The overlay stays advisory.
- **Line 28** (never a notary; positioning) — no ruled string contains a banned
  token, and the change removes an over-claim rather than adding one.
- **Line 127 / line 174** (one authoritative wording set, snapshot-tested at
  M3) — honoured through the documented bless act, with the diff justified here
  (R9).
- **Line 121** (the assembler is the sealer, who is the adversary) — the load
  bearing sentence in §2 (a)'s refusal of arm (a).
- **Line 186** (Risks: malicious verifier host) — unaffected; nothing here
  changes what the page fetches or from whom.

---

## 11. Residual risk

1. **The page's chain id remains a page-side pin.** After this ruling the page
   still cannot verify a Sepolia-sealed receipt — it names the chain it probed
   and stops. That is the correct outcome per registry §7.6.1's *"fails to
   resolve … which is the correct outcome"*, but it means a maintainer testing
   on Sepolia sees an honest non-answer rather than a confirmation. Accepted:
   the receipt is supporting evidence with no verdict weight, and the CLI with
   `--network arbitrum-sepolia` covers the maintainer's case.
2. **Two identically-spelled tokens survive** (R8). A future reader may still
   try to unify them. Mitigated by R8 recording the non-change with its reason;
   not eliminated.
3. **R6 changes a page↔wasm wire schema.** `deny_unknown_fields` means an
   un-updated page and an updated module fail loudly rather than silently, which
   is the right failure — but the two must ship together, and the page artifact
   is built by `scripts/verifier-page-build.sh`, whose staleness is R83's
   subject. **A stale wasm module against a fresh template is exactly the
   failure R83 records as invisible to a green `--check`.** The implementing row
   should rebuild from clean, not from `target/`.
4. **The chain id in the evidence document is page-supplied.** Core validates
   its shape, not its truth; a hostile page could report `chain_id: 1` and get a
   sentence naming chain 1. This is not a new exposure — a hostile page can
   already fabricate the entire evidence document, including confirmations — and
   the overlay is advisory in both directions. Recorded so it is not discovered
   later as a finding.
5. **Nothing asserts the page's guard and the CLI's guard stay the same
   shape.** They are two implementations of one rule in two languages, and §5's
   assertions constrain each surface separately. A cross-surface differential
   over the guard would need a harness that does not exist; out of scope here
   and named for whoever wants it.

---

## 12. Discovered work — described, not registered

*(Named for a registrar, not registered by this lane.)*

- **`the_source_scan_catches_a_planted_copy_of_a_frozen_sentence` covers one
  needle out of the table's twenty-seven.** Parameterising it, or at least
  R11's new test, closes
  a whole family of un-firable assertions rather than the one this record needs.
- **`ReceiptEchoOutcome` has no `token()` method**, unlike
  `OverlayOutcomeClass` and `AggregateDelta`, which both carry wildcard-free
  ones (L2). It relies on `rename_all` alone, so its tokens are un-greppable and
  un-asserted. R3 is the moment to notice this; adding the method is a separate
  small row.
- **The overlay document has no committed golden vector.** The report has 21;
  the overlay has a wording snapshot and unit tests. R3 changes a shipped JSON
  shape with no vector to diff it against, and D65's stability commitment is
  weaker than it reads for exactly that reason.
- **`ReceiptRecord::block_number`'s doc says "The payment's **Arbitrum One**
  block number"** (`schema.rs:788`), which is the same network-blind assumption
  in a third place — and unlike the rendered lines it is a *sealer-recorded*
  value that no probe checks. Registry §7.10 already calls it display-only and
  unverified; the doc comment overstates it.

---

## Outcome

The lean survives in direction and not in scope. The page and the CLI both stop
asserting that a transaction is not on chain and start reporting, truthfully,
that two endpoints serving a named chain hold no receipt for it — with the
machine-readable token carrying the same scope as the sentence, because half a
correction is a correction only to the half of the audience that reads prose.
The frozen registry turns out to have written the honest phrasing already —
*"fails to resolve against Arbitrum One … which is the correct outcome"* — in
the very cell that forbids the datum arm (a) wanted, and the fix is to make the
rendered sentence say what the registry had said all along. Arm (a) is closed permanently
rather than routed, on the ground that a sealer-written chain id would let a
seller of proofs choose the chain his own proof is checked against. And D133's
deferred fixture becomes buildable in the same act, from bytes the tree already
holds, because a transaction hash that points at nothing is no longer a
demonstration of a defect once the sentence beside it is true.

---

## Correction — §5 point 3 names a string the page never renders, and §6.1's assertion order makes its own assertion 3 unfirable, 2026-08-16

**(1) The corrected instruction, quoted verbatim**, from **§5 point 3**:

> assert the rendered receipt element carries the **failed** line naming
> `wrong-chain`, **and — the negative control — that it does not carry the
> absence line**

**The measured fact.** `probe_failure_class_label(ProbeFailureClass::WrongChain)`
renders **`"wrong chain"` — with a space**. The hyphenated `wrong-chain` is the
**evidence-document class token**, produced page-side at the guard
(`if (reported !== ARBITRUM_CHAIN_ID) return failed(endpoint, "wrong-chain")`)
and consumed as an input by the wasm boundary; it is not display text and never
reaches the rendered receipt element. A browser assertion written against §5
point 3's literal instruction searches the DOM for a string the page does not
contain, and fails on a correct page.

**What was asserted instead, and why it is the stronger form.** The R85 act-2
lane asserted the **discriminator** rather than either spelling: a **failure**
line names the endpoints and no chain, an **absence** line names the chain and
no endpoint. That is **§3 R1's own dividing rule** — *"a line that asserts the
transaction's presence or absence must name the chain it asserts it about; a line
that reports only what the endpoints did need not"* — applied as a test, and it
restates no frozen string, which is what `no_renderer_source_spells_a_frozen_verdict_string`
requires of any assertion in that surface. The negative-control half of §5
point 3 is kept exactly as written.

**(2) The corrected structure, quoted verbatim**, from **§6.1**, which
introduces its list with *"Assertions, in order of what they catch"*:

> 3. **The old claim is gone.** No render may contain the unqualified clause
> `is not on chain `, so a "fix" that appends the chain id while leaving the
> universal claim intact fails.

**The measured fact.** Assertion **2** immediately above it compares **each of
the four renders to its full expected string**, not to a `contains` predicate —
by this record's own reasoning, because `"42161"` is a prefix of `"421614"`.
Once assertion 2 passes, every render is byte-determined, so assertion 3 cannot
fail without assertion 2 having already failed and aborted the test first.
Planting the obvious fault — a renderer that appends the chain id while leaving
the universal clause — reddens assertion **2**, never assertion 3. Assertion 3
was shown fallible only by planting the sentence **and** the expected strings,
i.e. by simulating a lane that updates the test instead of the code. Assertion 4
(*"neither line names the other's chain"*) is dominated the same way.

**Assertion 3 is still worth having** — it is the one that survives a future
edit which loosens assertion 2 — but it guards a **narrower** case than §6.1's
ordering implies, and a reader must not count it as an independent witness.

**Authority.** The **R85 act-2** lane, 2026-08-16, both findings by planting the
faults §6.2 prescribes and reading the messages; registered by the registrar at
the wave-21 close in the same commit as R85's tick, because the corrected text is
what the shipped tests depart from.

**Which rulings still stand.** All of them, and neither error touches the
argument. §3 R1's dividing rule, R2, R5 (`ProbeLog::with_receipt(probe,
chain_id)` — the illegal state unrepresentable), R7, **R8's deliberate
non-change of the `"not-on-chain"` input token**, **R9's snapshot arithmetic —
which is CORRECT as written: *"Exactly three snapshot rows change and two are
added"*, and the shipped diff is exactly those five rows** — R10's two needles,
R11's occurrence test and §8's three recording sites (including its explicit
*"nothing is added at `network.rs:52`"*) are all untouched and all shipped.
§6.2's three planted faults were driven and each reddened by its own message,
including the control on the control. The `wrong-chain` override path is
unchanged and `chain_id_mismatch_is_unavailable_not_agreed` is green
**unmodified**, which is R85's Accept row 2.
