# D73 — Counting the ≥10 external completions with no telemetry: the bundle is the evidence, the third leg cannot be evidenced at all, and the metric is two numbers

- **Status: RESOLVED — and the register's own framing is overturned twice, on
  measurements taken in this repository.** The register asks *"facilitated
  sessions vs self-report vs both"* (`tasks/Q.md:1031`). **Both named arms
  count claims.** The arm the register never listed — **the participant hands
  over the `.sealproof` bundle itself**, which the maintainer verifies offline
  with the shipped binary — is the only candidate in the space that produces
  something a non-participant cannot fabricate, and it is **adopted**. The
  second overturn is larger: **the metric is not uniformly measurable.** Legs 1
  and 2 (seal, reveal) leave third-party signatures behind and are
  cryptographically evidenced. **Leg 3 — third-party page verification — leaves
  nothing, and leaves nothing *by construction*.** D29 froze the verification
  report as a byte-deterministic function of the bundle, and the
  `wasm-bitmatch` CI lane asserts the page emits those same bytes; therefore a
  pasted verdict string or a verdict screenshot is **reproducible by anyone
  holding the bundle, the sealer included, and carries zero bits** about
  whether a third party ever looked. Q35's own *"optional shared verdict
  screenshots"* (`tasks/Q.md:571`) is that vacuous artifact, and it is
  **refused**. The ruling is therefore that the metric is reported as **two
  numbers, never one**, and that leg 3 wears the product's own
  *"asserted by sealer — NOT verified"* discipline, applied to the project's
  measurement of itself.
- **A third premise, from the brief that commissioned this record, is corrected
  on the file.** The verifier page is **not** "zero network by ruling". D129 §5
  R6 sets `connect-src https:` — **scheme-only, deliberately not the six pinned
  hosts** — and R24/D66 give the page a live online overlay against two esplora
  and four Arbitrum RPC endpoints. **The CSP does not forbid a counter beacon.**
  Page-side counting dies for four other reasons, named in §3.1, and this
  paragraph exists so that a future reader who discovers the permissive
  `connect-src` does not conclude the question was never really settled.
- **Date: 2026-08-16**
- **Owning task: Q35.**
- Related: **D29** (the frozen report byte format — the determinism that kills
  three candidates at once), **D129** (the page's file shape, the in-artifact
  CSP, and §5 R9 assertion 8's zero-network requirement), **D66/D64** (the page
  *does* reach the network, in an opt-in overlay), **D62** (GitHub Pages, apex
  `https://antseal.org/`, no backend and none possible), **D69** (`verify` exit
  codes — the mechanical form of falsifier X1), **D68** (the bundle filename a
  participant will be handing over), **Q21/Q25** (wallet linkability and
  fresh-address-per-work hygiene, the two rows that kill on-chain counting),
  **Q65** (publish scope — the repo is private *today*, measured, which blocks
  the GitHub-issue venue), **Q22** (the docs a participant reads first),
  **Q34** (the release the count is taken after), **D125/`docs/instrument-ledger.md`**
  (assertions that cannot fail — the defect class this record is written
  against).

---

## 1. The metric, verbatim, and what it actually asks for

`MVP-SPEC.md:157`, the operative sentence quoted exactly:

> **MVP success metric: ≥10 external users complete seal → reveal → third-party page verification.**

Q35's own `Do` expands it (`tasks/Q.md:571`):

> completion = an external user seals their own work, reveals a subset, and an
> independent third party verifies the bundle on the hosted page.

**Read those two together and the shape of the metric changes.** A "completion"
is not one person doing three things. It is **two people**: a sealer who does
legs 1 and 2, and *someone else* who does leg 3. The spec's own word is
**third-party**; Q35's is **independent third party**. A sealer who verifies
their own bundle on the page has **not** completed the chain.

Three consequences follow immediately, and they govern everything below.

1. **The counted subject is the sealer.** Ten completions means ten sealers,
   each of whom got at least one independent person to open the page. The
   third parties are *required events inside each sealer's chain*, not counted
   subjects. Counting third parties instead would be a different, larger, and
   even less measurable number.
2. **The actor in leg 3 is, by the product's own definition, a stranger to the
   project.** `MVP-SPEC.md:26`: *"**Counterparties/verifiers need zero
   install** (drag a proof file onto a web page)."* The one person whose act
   the metric hinges on is the one person the project has deliberately
   engineered to need no account, no install, and no relationship with us. That
   is not an oversight to be instrumented around — it is the product working.
   **Leg 3 is unmeasurable because the actor is a stranger by design**, not
   merely because telemetry is banned.
3. **The chain must not be collapsible to one person.** Any method that lets a
   single participant report all three legs from one seat is measuring
   something the spec did not ask for.

### 1.1 Where "zero telemetry" actually comes from

Measured, because a constraint's authority matters when it is about to
disqualify things. `grep -rni "telemetry"` over the repository (excluding
`target/`) returns **exactly four hits, all in the tracker**:

| hit | text |
|---|---|
| `TODO.md:90` | *"**D73** (zero-telemetry success metric, Q35)"* |
| `TODO.md:985` | *"**D73** Success-metric measurement method with zero telemetry (Q35)"* |
| `tasks/Q.md:571` | *"measurement without telemetry (the page has no backend)"* |
| `tasks/Q.md:1031` | *"Success-metric measurement method with zero telemetry (facilitated sessions vs self-report vs both)"* |

**The word appears nowhere in `MVP-SPEC.md`, in any decision record, or in any
line of code.** So the *phrase* is the tracker's. The *substance*, however, is
**normative spec**, and that is the authority this record leans on:

- `MVP-SPEC.md:17` — *"Rust CLI (non-custodial, user's own wallet) + static web
  verifier page (same core via WASM). **No backend.**"*
- `MVP-SPEC.md:38` — *"the page is `antseal-core`-WASM with **no network layer
  and there is no backend**"*
- and the page has no backend and cannot acquire one — `D62` rules GitHub Pages
  serving a static artifact from the apex, and a static host runs nothing;
- `MVP-SPEC.md:186` names **malicious verifier host** as a threat class whose
  whole mitigation is *"reproducible build, published hash, canonical URL,
  footer build-hash, CLI cross-check advice"* — every one of which is about
  *reducing* what the user must trust the host to do;
- `MVP-SPEC.md:185` commits the receipt to being **excluded from bundles by
  default** precisely because it *"links every seal to one wallet, and that
  wallet to an identity"*.

A measurement method that contradicts any of those is disqualified on the
spec, not on a tracker phrase. This record uses the spec lines.

---

## 2. What each leg actually leaves behind

| leg | artifact it produces | forgeable by someone who did not do it? | checkable by the maintainer, offline? |
|---|---|---|---|
| **1. seal** | anchors inside the manifest: ≥1 RFC 3161 TSA token, an OTS attestation, optionally an Arbitrum receipt | **No.** A TSA token is a third party's signature over `anchor_digest` at `genTime`, verifiable against the pinned root store. Forging one is forging the TSA. | **Yes** — the whole anchor stack verifies offline; that is project rule 4 and M2's exit criteria. |
| **2. reveal** | the `.sealproof` bundle: the reveal set, its GGM openings against `fine_root`, the hybrid signatures over the policy | **No.** The openings only close against a `fine_root` that the anchors bind. | **Yes** — `antseal verify <bundle>`, no network. |
| **3. third-party page verification** | **nothing** | — | — |

Row 3 is the finding. It is worth being precise about *why* the cell is empty,
because the obvious objection is "surely the verifier can copy the verdict".

### 2.1 The determinism result — one measurement, three candidates dead

`crates/antseal-core/src/verify/report.rs:182-187` documents the frozen
contract:

> The canonical, deterministic byte form of this report (D29): compact JSON,
> struct-declaration field order, lowercase-hex binary, kebab-case enum names.
> Two serializations of equal reports are byte-identical; native and wasm32
> builds must bit-match (Q5).

D29 is **frozen** — its Status line reads *"RESOLVED — FROZEN 2026-07-28 at Q14
as report v1 … this format no longer may change"*. The bit-match half is not an
aspiration either: `crates/wasm-bitmatch/` is a live CI job (`ci.yml:590`,
context `wasm-bitmatch`) whose own header states the requirement — *"must
produce **byte-identical** … the WASM build must bit-match native
verification"*. And D129 §5 R9 assertion 8 requires the built page to produce
*"a report byte-identical to native for at least one R9 vector"*.

**Therefore the page's verdict is a pure, deterministic function of the bundle.**
Given the bundle, the verdict bytes are computable by anyone, on any platform,
offline, in either implementation. It follows that:

- a **pasted verdict string** proves possession of the bundle and nothing more;
- a **screenshot of the page** proves the same, less reliably, and is trivially
  editable besides;
- **the sealer can produce either one without ever showing the bundle to
  another human.**

This is the project's dominant defect class arriving at the product level: an
observation that would be identical in the world where the metric is met and in
the world where it is not. Q35's `Do` proposes exactly it. It is refused in §3.2.

### 2.2 What a submitted bundle proves — and the caveat the project already wrote

The bundle is real evidence for legs 1 and 2, but it is not evidence of
everything, and the codebase already states the limit better than this record
could. `crates/antseal-core/src/verify/report.rs:227-232`, on `work_id`:

> The one value in this group a recipient can act on, and it acts by
> comparison: a work id obtained independently of the bundle either equals this
> one or does not, and a substituted body does not survive that. On its own,
> recomputing a digest over bytes the bundle supplied proves only
> self-consistency — **the comparison is where the evidence is.**

That sentence is the design rule for this entire record. A participant's bundle,
checked against itself, establishes self-consistency plus the third-party
attestations it carries. It establishes **nothing about identity, distinctness,
or leg 3** until it is compared against something the participant did not
supply. §4 R5 is that comparison set, and it is the substance of the ruling.

What a submitted bundle **does** prove, stated exactly:

1. A real seal happened, at or before the TSA `genTime` — a time a third party
   signed and the submitter cannot move.
2. A real reveal happened, and the revealed units open against the anchored
   `fine_root`.
3. The seal was produced by the holder of a specific keypair, because the
   manifest carries `pubkeys` (registry §7.2 key 5, `docs/format/registry-v1.md:573`
   — *"map, req, uint keys = `sig_alg` → bstr of that algorithm's exact pubkey
   length; non-empty"*) and the signatures close against it.

Point 3 is the lever. It is what makes the count **falsifiable** rather than
merely reportable, and §4 R5 X2 is built on it.

---

## 3. The methods rejected, each with the specific thing that kills it

### 3.1 Page-side counting — dead, but not for the reason usually given

**The correction first.** The page's CSP is `default-src 'none'` with, per D129
§5 R6, **`connect-src https:` — scheme-only, and deliberately not the six
pinned hosts.** D129 §1 (m) records why: naming the hosts *"silently breaks
spec line 137's overrides"*, because line 137 mandates the endpoints be
*"user-overridable"* and D66 §3 R4 forbids the page from naming CORS as a
cause, so a `connect-src` rejection would be undiagnosable. The page also
already reaches the network on purpose: R24/D66's opt-in online overlay hits
`blockstream.info`, `mempool.space` and four Arbitrum RPCs.

**So "the CSP forbids a beacon" is false, and anyone who checks will find it
false.** The method dies on four other things:

1. **There is nothing to beacon *to*.** D62 rules the host is GitHub Pages
   serving a static artifact. A static host has no endpoint. Acquiring one
   means standing up a server — which is telemetry infrastructure by any
   definition, and is the thing the constraint names.
2. **A load-time or verify-time beacon reddens a committed CI assertion.**
   D129 §5 R9 assertion 8: *"The page loads and verifies, headless, from a
   `file://` URL, with **zero** network requests and a report byte-identical to
   native for at least one R9 vector."* D136 sharpens it — the driver asserts
   the page *attempts* zero further requests, *"which is strictly stronger than
   blocking them … a page that asked and was refused has still asked"*. Any
   beacon on the load or verify path fails that assertion at the next push.
   (Honest limit: a beacon behind an explicit opt-in click would *not* trip
   assertion 8, because assertion 8 never clicks. Reasons 1, 3 and 4 cover it.)
3. **It makes the maintainer an observer of every verification.** A beacon
   from the canonical page tells us an IP, a time, and — if it carries any
   bundle-derived value — *which bundle* a stranger is checking. `MVP-SPEC.md:186`
   scopes **malicious verifier host** as a threat and the whole page design is
   about shrinking what the host can learn or lie about. Adding a channel by
   which the host learns who verified what is moving the wrong way, and it does
   so on the exact surface the threat model is scoped around. A counter that
   "records only a total" is indistinguishable, from the visitor's side, from
   one that records everything.
4. **It enters the reproducible artifact.** R25 publishes a hash of a
   single-file page and invites strangers to reproduce it. A beacon endpoint
   becomes a URL inside the hashed bytes — a permanent, published statement
   that the canonical verifier phones home.

**Refused. No beacon, no endpoint, no third-party analytics on the Pages site,
now or later.**

### 3.2 Pasted verdict strings and verdict screenshots — vacuous

Killed by §2.1. The verdict is a deterministic function of the bundle; the
sealer can emit it byte-for-byte without another human existing. A verdict
screenshot is the same information with a forgery surface added. **This is an
observation that cannot distinguish the metric being met from the metric not
being met, which is the definition of the defect class this project logs in
`docs/instrument-ledger.md`.** Q35's `Do` names it (*"optional shared verdict
screenshots"*); Q35's plan must drop it.

**One narrow survival, and it is not evidence of leg 3:** a pasted verdict that
*disagrees* with the maintainer's own recomputation is informative — it means
the participant ran a different build, a tampered page, or a different bundle.
That is a **bug report**, valuable and welcome, and it belongs in a defect row,
not in the metric.

### 3.3 A GitHub issue template or discussion thread — venue blocked today, and it counts claims anyway

Two independent kills.

**The venue does not exist.** Measured 2026-08-16:
`gh repo view aed900/antseal --json visibility` → `{"visibility":"PRIVATE"}`.
External users cannot open an issue on a private repository. Making it public
is **Q65** (`TODO.md:811`), which is open, is *"deferred by the maintainer
2026-07-28"*, and carries a pre-public scrub. **A method whose venue depends on
an undecided, deferred decision cannot be the primary instrument**, and Q35's
plan must not be written as though the venue is available.

**And the mechanism is weak even after Q65.** An issue body is a claim. It
requires a GitHub account — friction the spec explicitly designed *out* of leg
3 (`MVP-SPEC.md:26`). It excludes exactly the demographic the metric is meant
to reach.

**Not refused as a *channel*.** If the repo goes public, an issue or discussion
thread is a perfectly good **place to attach a bundle** — the evidence is the
bundle, the thread is transport. §4 R2 rules transport as maintainer's choice
precisely so that this record does not have to be reopened when Q65 lands.

### 3.4 Email / reply-to confirmation — a claim, plus PII we did not need

An email confirms a mailbox, not a completion. It adds personal data the
project has no other reason to hold, about people whose threat model
(`docs/threat-model.md` §2.3 scope) is partly about **not** being linkable.
And it still has no channel to the third-party verifier, who is a stranger.

**Refused as evidence. Permitted as transport** (§4 R2) — a mailbox is a fine
way to receive a bundle, and it is the only transport available while Q65 is
undecided.

### 3.5 On-chain observation of payer addresses — refused three times over, and the measurement found something else

This method was measured properly rather than dismissed, because the chain
genuinely is public and no telemetry would be involved. Three independent
kills, any one of them sufficient — **and the measurement turned up an
unrelated finding that matters more than the method does** (§3.5.4).

#### 3.5.1 There is no antseal marker on-chain. None.

A seal's entire on-chain footprint is an ERC-20 `approve` followed by 1..n
`payForQuotes(DataPayment[])` calls
(`crates/antseal-net/src/ant_backend.rs:732-756`), to the **global Autonomi
payment vault**, whose address `crates/antseal-net/src/network.rs:68-71`
transcribes *verbatim from `evmlib-0.9.0/src/lib.rs:71-72`* and pins against
upstream in a test (`network.rs:790-794`). The calldata is built by upstream
(`evmlib-0.9.0/src/contract/payment_vault/handler.rs:61-71`) over upstream's
own three-field struct — `rewardsAddress`, `amount`, `quoteHash`. **There is no
memo field, no tag, and not one antseal-authored byte in the calldata.**
antseal has no contract of its own on any network.

The stored chunks give no census route either, by design: they are
randomized-AEAD ciphertext with no header, no magic and no version byte
(`crates/antseal-net/src/blob.rs:62-66`;
`crates/antseal-core/src/crypto/unit_aead.rs:212-224` returns the nonce
*separately*, so it is not prepended), deliberately **not** convergent
(`crates/antseal-core/src/crypto/manifest_aead.rs:18-21` — *"two sealers with
the same manifest bytes upload different ciphertexts"*), and addressed by
BLAKE3 over those random bytes (D32). And `MVP-SPEC.md:110` records the
consequence for the anchor side: *"no on-chain datum contains
`anchor_digest`"*.

So there is no filter from `payForQuotes` callers down to antseal users.

#### 3.5.2 The project's own guidance breaks the count, on purpose

`MVP-SPEC.md:185`, normative:

> **Wallet linkability** (receipt links every seal to one wallet, and that
> wallet to an identity) → receipt excluded from bundles by default
> (`--include-receipt` to opt in); wallet-hygiene docs (**fresh address per
> work/client**); threat-model section.

Q25's `Do` (`tasks/Q.md:461`) commits to writing exactly that: *"the
fresh-address-per-work-or-client recommendation"*. It is echoed in D44
(`docs/decisions/D44-wallet-import-formats.md:91-98`), written out for a user
in `docs/devnet/sepolia-devnet.md:147-152`, and instructed to the maintainer at
the release gate (`tasks/Q.md:550`).

**We instruct users to break address-based counting.** A compliant user
contributes *n* addresses for *n* works; a non-compliant one contributes 1. So
`n_addresses` is neither an upper nor a lower bound on `n_users` — it can move
in both directions independently of the quantity it estimates, which is not a
measurement. And the project cannot both publish Q25 and lean on this number.

#### 3.5.3 Watching the chain to count your own users is surveillance with a public-data alibi

The data being public makes the act lawful; it does not make it something a
project whose threat model is scoped around wallet linkability should build
into its own success reporting. The moment the maintainer keeps a table of
addresses believed to belong to named participants, the project holds the
linkage database `MVP-SPEC.md:185` exists to warn users about.

**Refused on all three grounds. No address table is built, and none is kept.**

#### 3.5.4 What the measurement found instead: antseal payers ARE distinguishable, by an accident of hygiene

This does not rescue the method — §3.5.2 and §3.5.3 stand regardless — but it
is a real, previously unrecorded observability property and it must not be lost
with the method that surfaced it.

`crates/antseal-net/src/ant_backend.rs:49-51`:

> The ERC-20 allowance for the payment vault is approved with the **exact
> quoted total** (never upstream's `U256::MAX`, `evmlib-0.9.0/src/wallet.rs:416-427`
> — S1 §7's wallet-hygiene note).

Implemented at `ant_backend.rs:437-455`: query `token_allowance`, return early
only `if current >= total`, otherwise `approve_to_spend_tokens(vault, total)`.

Every other client on the network approves unlimited. Verified directly in the
vendored sources:

- `evmlib-0.9.0/src/wallet.rs:421` — `U256::MAX,` in the `approve_to_spend_tokens`
  call, under the comment *"Approve the contract to spend all the client's tokens."*
- `ant-core-0.5.0/src/data/client/payment.rs:130` — *"Approves `U256::MAX`
  (unlimited) spending."*

**The consequence is public and permanent.** Because the antseal allowance is
*exact*, it is consumed by the very payment it was raised for, so the
short-circuit almost never fires: an antseal user emits a fresh
`approve(vault, <non-round exact amount>)` before essentially **every seal**,
while a stock ant-core user emits one `approve(vault, 2^256-1)` once per
address, ever. Both the calldata and the ERC-20 `Approval` event log are
public.

This was chosen *for* wallet hygiene — it avoids leaving an unlimited standing
allowance — and it is defensible on that ground. But it also **reduces the
anonymity set**: it separates antseal payers from the general Autonomi payer
population without any marker being intended. It is documented nowhere as an
observability property, nothing pins it, and a refactor would silently destroy
it. §7 carries it as owed work; `docs/threat-model.md:447` already scopes the
question it answers — *"what an observer learns from the chain without any
bundle at all"* — and the answer, today, is **"that this address is running
antseal, or a tool with identical hygiene."**

*(Note for anyone tempted to build the method back on top of this: it would
mean the metric's validity rested on an undocumented implementation detail of a
private function that nobody has committed to keeping. §3.5.2 kills it anyway.)*

### 3.6 Facilitated sessions as the primary instrument — measures a different question

The register's first arm (`tasks/Q.md:1031`). A facilitated session — the
maintainer present while a participant and their chosen verifier run the chain
— is the **only** method that genuinely evidences leg 3, because the maintainer
is a witness. That is a real strength and this record does not discard it.

But it is the wrong instrument for *this* number, for a reason that is not
about cost:

**A facilitated session measures whether the product *can* be completed. The
metric asks whether it *was* completed, by ten people we were not sitting
with.** Those are different questions with different answers, and the whole
point of "external users" is that they are external — unaided, working from
`Q22`'s docs, in their own environment, with a verifier of their own choosing.
Ten facilitated completions would demonstrate that the software works and
would tell us almost nothing the metric asked. Folding them into one total
reports the second question while having answered the first.

**Not refused — reclassified.** §4 R9: facilitated sessions are a **usability
instrument**, always marked, and **never counted into the number the spec
metric is read against.**

### 3.7 Asking participants for receipt-bearing bundles — refused, and the instruction must say the opposite

Worth stating because it is the tempting "more evidence is better" move, and it
is the most harmful idea in the space.

`--include-receipt` is **off by default** (`MVP-SPEC.md:36`; `tasks/R.md:202`
— *"omitted by default"*), and the CLI's own consent prompt warns about it
(`tasks/U.md:497` — *"add a warning that the receipt exposes the paying wallet
and links the user's seals"*). Q21's `Do` states the chain the receipt closes
(`tasks/Q.md:419`): *"receipt links every seal to one wallet and that wallet to
a KYC identity"*.

**Asking a participant to include the receipt is asking them to hand the
project a KYC-linkable identifier, in exchange for helping us hit a number.**
It would also make the project's own metric process the single largest
counter-example to its own documentation. §4 R6 rules the instruction and what
happens if one arrives anyway.

### 3.8 Release download counts — not a user count, and must never be quoted as one

GitHub's release asset download counter exists without any telemetry we build,
so it will be available and it will be tempting. **A download is not a seal, a
seal is not a reveal, and none of them is leg 3.** It is a recruitment-funnel
number. §4 R7 gives it a column, in the funnel table, clearly not in the metric.

---

## 4. The ruling

### R1 — The metric is reported as two numbers and a date, never as one number

`docs/success-metric.md` carries, as its first three lines and nowhere else:

- **`n_evidenced`** — external sealers for whom **legs 1 and 2 are
  cryptographically verified** by the maintainer, offline, from a submitted
  bundle, and for whom no falsifier in R5 fired.
- **`n_claimed`** — of those, how many **assert** that an independent third
  party verified their bundle on `https://antseal.org/`. **Leg 3 is asserted,
  never verified.**
- **`read_on`** — the date the numbers were read (R8).

**`MVP-SPEC.md:157` is read against `n_claimed`, and `n_claimed ≤ n_evidenced`
always.** A row may not enter `n_claimed` without being in `n_evidenced`: an
assertion about leg 3 from someone whose seal we could not verify is not a
completion of anything.

The file may never print a single combined figure, and no README, release note
or post may quote a number this file does not carry.

### R2 — The evidence is the `.sealproof` bundle. Transport is free; evidence is not

A participant completes a row by **sending the bundle** — the file
`antseal-reveal-<work-id>.sealproof` that `reveal` already wrote for them
(D68), the same file they gave their third party.

**The transport is deliberately unruled**: email, a GitHub issue attachment if
Q65 makes one available, a link, a chat message, a USB stick at a meetup. Q35
picks whatever is available at the time. This record fixes only *what counts as
evidence*, so that a change of channel — including Q65 landing or not landing —
never reopens the decision.

**The maintainer verifies it offline**, with the released, signature-checked
binary, on a machine with no network need: `antseal verify <bundle>`. The row
records the date, the binary version, and that the check was offline.

### R3 — "External" — four tests, and only one of them is mechanical

In order, all four required:

1. **Not the maintainer, not an agent, not CI.** The sealer is a human who
   holds a vault whose passphrase the maintainer has never held.
2. **Their own work** (`tasks/Q.md:571`). Content the participant chose — not
   project-supplied test material, not a golden vector, not `testdata/`.
   *Clarifying, because it will be asked:* a participant who does not wish to
   disclose anything sensitive may seal content they are comfortable handing
   over. Choosing safe content is still choosing; **"their own work" means work
   they selected, not work of a particular importance.**
3. **Their own decision.** A person paid, employed, or directed by the project
   to complete the chain is recorded and is **not** in `n_evidenced`. They go
   in a separate `directed` column.
4. **Mechanical exclusion:** the bundle's `pubkeys` (registry §7.2 key 5) must
   not appear on a committed exclusion list of maintainer and test-vault public
   keys, seeded at release with every vault used in Q34's gate and the mainnet
   smoke seal.

**Tests 1–3 are maintainer declarations and the file must label them as such.**
Test 4 is the only one a reader can re-run, and R5 X5 is its falsifier.

### R4 — "Complete" — the chain is two people, and a split chain is required, not merely allowed

- Legs 1 and 2 are **the same person and the same vault**: the sealer sealed,
  and the sealer revealed from that seal.
- Leg 3 is **someone else**. Per `MVP-SPEC.md:157` (*third-party*) and
  `tasks/Q.md:571` (*independent third party*), a sealer verifying their own
  bundle on the page has **not** completed the chain, and the row's leg-3 cell
  reads `NOT CLAIMED`.
- **One row per sealer**, counted once, however many third parties verified and
  however many works were sealed. The metric counts people who completed a
  chain, not chains.
- **"Independent"** is not over-engineered here: the third party is a person
  the sealer names as not being themselves and as not having received the
  bundle from the project. It is unevidenced. R1's `n_claimed` label carries
  that, and R7's row shape prints it on every row.

### R5 — The falsifier set: the number's job is to be capable of being wrong

This is the ruling the rest of the record exists for. **Every row must be
capable of being struck, and each striking rule names the field it reads and
the observation that fires it.**

| id | what it reads | what fires it | consequence |
|---|---|---|---|
| **X1** | the bundle, via `antseal verify` | a non-zero verdict class (D69's exit mapping) | legs 1+2 are false — row struck, not counted anywhere |
| **X2** | manifest key 5 `pubkeys` (`docs/format/registry-v1.md:573`) | two rows claimed as distinct participants carry the **same** sealer public key | the two rows are **one vault**. They collapse to one row. |
| **X3** | `work.work_id` from the report | a `work_id` already present in the table | the same work resubmitted — no new row |
| **X4** | the report's headline anchor time | a headline earlier than the release date recorded at the top of the file | a pre-release or maintainer seal, not a post-release external completion |
| **X5** | `pubkeys` against R3's committed exclusion list | a match | not external |
| **X6** | the calendar | R8's read date arrives with `n_claimed < 10` | **the metric is not met**, and that is recorded permanently |
| **X7** | the instrument itself | X2 has never fired | see below — the count may not be declared met |

**On X2, the strongest of them, and its exact logical force.** Distinct
`pubkeys` is an **upper bound** on distinct participants, never a lower one:
*k* distinct keys means *at most k* people (one person can hold many vaults) and
*at least one*. That asymmetry is the point. **X2 can only ever deflate an
inflated count; it can never confirm a real one** — which is precisely the
property a falsifier should have, and precisely what "10 people said they did
it" lacks.

**X7 is the plant-a-fault rule, and it is not optional.** Before the count is
declared met, X2 must have been **run against a deliberately duplicated
submission** — two bundles produced from a single vault, submitted as if from
two participants — and the check must be recorded as having **gone red**. Until
that has happened the falsifier has never been shown capable of firing, and a
check that has never fired is exactly the class `docs/instrument-ledger.md`
exists to catch. The planted run and its red are recorded in the file, dated.

### R6 — Privacy rules on the submission, which bind the project, not the participant

1. **The request must say: reveal *without* `--include-receipt`.** §3.7. The
   instruction is part of the recruitment text, not a footnote.
2. **If a receipt-bearing bundle arrives anyway**, the row is accepted, the
   receipt group is **not read, not recorded and never quoted**, and the bundle
   is destroyed as soon as R5's checks have run.
3. **The participant is told, before sending, what they are sending.** A
   metric submission is an **irreversible disclosure to the maintainer** of
   exactly the units the bundle reveals — the same fact the product's own
   reveal prompt states (`tasks/U.md:497`). We do not get to be quieter about
   it than our own CLI is.
4. **Nothing identifying is committed.** `docs/success-metric.md` carries no
   bundle, no public key, no `work_id`, no wallet address, and no personal name
   unless the participant asks to be named. It carries the two opaque
   fingerprints of R7.
5. **Retention:** bundles are held until `read_on + 30 days` and then
   destroyed. After that the committed file's correspondence to real
   submissions is no longer auditable by anyone, and **the file must say so, in
   the file** (R7).

### R7 — The home, the row shape, and the fingerprints

**Home: `docs/success-metric.md`, committed, single-writer (the maintainer),
created by Q35.** *(This record does not create it — it is outside this lane's
write scope and it is Q35's deliverable.)*

**Header block:** `n_evidenced`, `n_claimed`, `read_on` (R1); the release tag
and release date that X4 compares against; the R3 exclusion-list; the X7
planted-fault record; and the R6.5 retention/auditability statement.

**Row shape:**

| col | values | note |
|---|---|---|
| `id` | `01`, `02`, … | stable, never reused |
| `submitted` | date | |
| `vault_fp` | opaque | R5 X2's distinctness column |
| `work_fp` | opaque | R5 X3's distinctness column |
| `legs_1_2` | `VERIFIED <date>, antseal <version>, offline` \| `FAILED <X1>` | the **only** cell permitted to say VERIFIED |
| `leg_3` | `ASSERTED — NOT VERIFIED` \| `WITNESSED (facilitated, <date>)` \| `NOT CLAIMED` | may **never** say "verified" |
| `mode` | `unaided` \| `guided` \| `facilitated` \| `directed` | R9, R3.3 |
| `struck` | — \| falsifier id + date | |

**The fingerprints.** `vault_fp = SHA-256(salt ‖ pubkeys-bytes)` and
`work_fp = SHA-256(salt ‖ work_id)`, truncated to 16 hex characters, where
`salt` is a single 32-byte random value generated once for the metric, held by
the maintainer and **never committed**.

Three properties, and the trade is deliberate:

- **The distinctness claim is checkable by any reader of the committed file
  alone** — ten distinct strings in a column are ten distinct strings, whether
  or not you can recompute them. That is the only property the count needs.
- **No reader can link a row to a bundle, a key, a work or a person**, because
  the salt is secret. A participant's row is opaque even to someone who
  independently obtains their bundle.
- **The cost, stated:** correspondence between the fingerprints and real
  submissions is a **maintainer declaration**, not a reader-checkable fact, and
  becomes permanently unauditable after R6.5's retention window. The file says
  this about itself. The alternative — a committed salt — would make rows
  re-derivable but would let anyone holding a participant's bundle test whether
  that participant is in our table. **Participant privacy wins; the residual is
  named rather than hidden.**

**Domain separation.** The fingerprint label is `antseal-metric-fp-v1`. It is
**not** a format domain tag, it is **not** registered in the frozen
domain-tag registry, and it must never be — this is project bookkeeping, not
wire format, and adding it to the registry would be a format event for no
reason. The salt is not format salt in the sense of project rule 6 and lives
with the metric material, never in a bundle, a log or a fixture.

### R8 — The count is read on a fixed date, once, and the first reading is never revised

**The single most important clause in this record.**

- The read date is **release + 90 days**, written into `docs/success-metric.md`
  at release as a concrete calendar date, not a relative phrase.
- On that date the numbers are read and recorded **whatever they are**.
- **The first reading is never deleted, revised or replaced.** Later readings
  may be appended, dated, below it. They never overwrite it.

**Why this is the clause that makes the metric falsifiable at all.** A success
metric with no date on which it is read can never be *not met* — there is
always more counting to do, and "we're at 7, still going" is a state that never
resolves into a failure. **The deadline is not administrative tidiness; it is
the only thing that gives X6 anything to fire on.** Without R8 every other
ruling here is decoration on an unfalsifiable claim.

### R9 — Facilitated sessions are a usability instrument and never inflate the metric

Permitted, encouraged, always marked `facilitated` in `mode`, and their leg-3
cell may say `WITNESSED` — they are the only method that genuinely evidences
leg 3 (§3.6).

**And they are excluded from `n_claimed`.** The headline reports
`n_claimed (unaided+guided)` — the number `MVP-SPEC.md:157` is read against —
and `n_total (incl. facilitated, directed)` beside it. **No cap is set**,
because any cap would be arbitrary; the non-arbitrary discipline is that
facilitated completions are counted separately and can never be quietly folded
in.

### R10 — What must not be built, ever, under this metric

1. No beacon, pixel, counter or endpoint in the verifier page (§3.1).
2. No backend on `antseal.org` and no third-party analytics on the Pages site.
3. No table mapping wallet addresses to participants (§3.5).
4. No chain-watching for user counts (§3.5).
5. No download count quoted as a user count (§3.8).
6. No verdict screenshot or pasted verdict string treated as evidence (§3.2).
7. No request for `--include-receipt` bundles (§3.7).

### R11 — Q35's plan is the M4 deliverable; the number is not a release gate, and the spec is not softened

Q35's own Notes: *"Execution is post-release/continuous; the plan is the M4
deliverable."* This record does not change that: **the plan gates the release,
the number does not.** Q34 ships whether or not ten people later complete a
chain.

**What the project does at `n_claimed < 10` on the read date**, stated so that
"the metric is a learning instrument" cannot become a way of never being wrong:

- **The shortfall is recorded, permanently, in the file** (R8), as a number.
- **The funnel stage where it stopped is named**, in four buckets, each with
  its own count: *not reached* → *reached, did not install* → *installed, did
  not seal* → *sealed, no third party verified*. The bucket that ate the
  attrition is the finding, and it is a different finding in each case: a
  recruitment failure, a packaging failure, a UX failure, and a *product-thesis*
  failure respectively. The last one is the one worth having a metric for.
- **The MVP is not retroactively declared a failure**, because `MVP-SPEC.md:157`
  names a success metric, not a ship gate, and the ship already happened at Q34.
- **But the number is not restated as a success.** Release notes, README and
  any public post may quote only what the file carries (R1), and the file
  carries the shortfall.

---

## 5. How this ruling can be wrong — the audit it demands of everything else

Applied to itself, because a record that rules against unfalsifiable
instruments and then contains one is worse than useless.

| ruling | what would show it wrong |
|---|---|
| R1 (two numbers) | a reader who cannot tell from the file which leg was verified and which was asserted — check by handing the file to someone who has not read this record |
| R2 (bundle is the evidence) | a submitted bundle that verifies but is later shown to have come from someone other than the claimed participant. **This is possible and R2 does not prevent it** — see below. |
| R3 (external) | tests 1–3 are declarations. Only test 4 can be re-run. If the file's counts and its declarations ever diverge, the declarations are the weak half and this record says so in advance. |
| R5 X2 | fails to fire on the R5 X7 planted duplicate → the whole distinctness column is decoration |
| R7 fingerprints | two rows with equal `vault_fp` present in a table that still claims two participants → the check exists but nobody runs it |
| R8 (read date) | the read date passes and no reading is recorded → **the metric has silently reverted to unfalsifiable**, which is the failure this record most expects |
| R9 | a public statement quoting `n_total` where `n_claimed` was meant |

**The honest hole in R2, named rather than papered over.** A bundle proves a
seal and a reveal happened; it does **not** prove *who* sent it to us. A
participant could forward someone else's bundle. Nothing in this design
detects that, and adding a challenge-response (asking the participant to sign a
nonce with their vault key) would evidence key possession — but no such CLI
surface exists, it is not worth building for this, and it still would not
evidence leg 3. **The count is therefore: cryptographically evidenced that
*a* seal and reveal happened, declared by the maintainer that it was this
participant's, and asserted by the participant that a third party verified
it.** Three different epistemic grades in one row, and R7's column labels keep
them apart. That is the most this method can honestly claim, and claiming
exactly that is the point of the record.

---

## 6. What this record does NOT decide

1. **Recruitment.** Channels, outreach copy, batch sizes, cadence — Q35's, per
   its own `Do`. This record fixes only what counts once someone arrives.
2. **The transport channel.** Deliberately unruled (R2), so that Q65 landing or
   not landing never reopens this.
3. **Whether the repository goes public.** Q65, open and deferred. §3.3 records
   only the *measured consequence today*, not a recommendation.
4. **The contents of `docs/success-metric.md`.** Q35 creates it; R1/R7 fix its
   header, its columns and its vocabulary, not its prose.
5. **Threat-model §2.3's text.** Q21 writes it. §3.5.3's objection — what an
   observer learns from the chain without a bundle — is that section's own
   scope line, and this record hands the finding over rather than pre-empting
   the section.
6. **What to DO about the exact-allowance fingerprint.** §3.5.4 establishes
   that it exists and is undocumented; it does **not** rule whether the
   behaviour should change, be pinned by a test, be documented as a trade, or
   be left exactly as it is. That is a wallet-hygiene and threat-model
   judgment with its own arms (unlimited-approve costs a standing allowance;
   exact-approve costs anonymity; a rounded-up approve might cost neither), it
   belongs to Q21/Q25, and a metric record has no business settling it in
   passing. §7 item 3 is a **finding and a proposed row, not a ruling.**
7. **Any CLI or format change.** R5 X2 needs read access to `pubkeys`, which no
   command prints today — §7 records it as owed work, and it is a *tooling*
   question, not a format one. D29's report is frozen and this record proposes
   no change to it.
8. **What happens after the first reading.** R8 fixes that there is one and
   that it stands. Whether the project keeps counting afterwards is Q35's.

---

## 7. What this ruling owes

1. **Q35's `Do` needs amending in three places.** *(Registrar's edit, not this
   lane's — `tasks/` is outside the write scope.)* Its *"optional shared verdict
   screenshots"* is refused by §3.2 and must be struck rather than left as an
   option a later reader picks up. Its *"self-report form"* must become
   *"self-report plus the submitted bundle"*. Its *"tracking sheet"* becomes
   `docs/success-metric.md` with R7's shape. Q35's Accept row
   *"completion definition matches the spec metric verbatim"* is satisfied by
   §1 and R4.
2. **No CLI surface prints the sealer's `pubkeys`.** `ManifestBody::pubkeys()`
   exists (`crates/antseal-core/src/manifest/body.rs:1213`) and the value is in
   every bundle, but `show` prints `work_id` and not the keys
   (`crates/antseal-cli/src/show.rs:536`), and `VerificationReport` carries
   `signature_scheme` but no key bytes
   (`crates/antseal-core/src/verify/report.rs:283`). **R5 X2 cannot be run with
   the shipped binaries.** A small maintainer-side tool over the library
   accessor is enough; a `show --json` field would also do but touches a
   stability surface (D65) for a use case that is not a user's. **This is real
   work and deserves a row** — describe it as *"a maintainer-side distinctness
   tool that extracts `pubkeys` from a submitted bundle for D73 §4 R5 X2"*, M4,
   before Q35's first submission.
3. **The exact-allowance on-chain fingerprint — the largest thing this record
   found, and it is not about the metric.** §3.5.4:
   `crates/antseal-net/src/ant_backend.rs:437-455` approves the **exact quoted
   total**, where `evmlib-0.9.0/src/wallet.rs:421` and
   `ant-core-0.5.0/src/data/client/payment.rs:130` both approve `U256::MAX`.
   Because the exact allowance is consumed by its own payment, an antseal user
   emits a fresh `approve` before essentially every seal while every other
   client emits one, ever. **That separates antseal payers from the general
   Autonomi payer population, publicly and permanently, and nothing in the
   repository records it as an observability property.** It was chosen for
   hygiene and is defensible; it is also an anonymity-set reduction, and the
   trade has never been written down or weighed. **This deserves a row** —
   describe it as *"record and weigh the exact-allowance approve as an on-chain
   fingerprint: document the trade in Q21 §2.3 and Q25, and decide whether
   anything pins the behaviour"*. It is **not** this record's to rule: it is a
   threat-model and wallet-hygiene question that the metric investigation
   merely walked into.
4. **Q21 (threat model §2.3)** gains three items from this record: item 3
   above; the answer to its own scope line *"what an observer learns from the
   chain without any bundle at all"* (`docs/threat-model.md:447`), which today
   is **"that this address is running antseal, or a tool with identical
   hygiene"**; and the fact that the project's *own* metric process is a place
   where wallet linkability could have been introduced and deliberately was not
   (R6, R10.3).
5. **Q22's docs** are the participant's on-ramp and must carry R6.3's
   disclosure warning wherever the metric asks for a bundle.
6. **The R5 X7 planted-fault run** is a concrete pre-condition of declaring the
   count met, and it has an owner (Q35) and no evidence yet. It is the one
   clause in this record most likely to be skipped, because it costs an hour and
   produces a red on purpose.
7. **Nothing here has been run.** This is a planning record: no bundle has been
   submitted, no fingerprint computed, no falsifier fired, and there is no
   release for R8's date to hang off. Every number in `docs/success-metric.md`
   is, today, zero — and the file does not exist. **The first thing this ruling
   owes is its own instrument, and until R5 X7 has gone red, none of the
   falsifiers above is more than a plan.**
