# D146 — The dry-run shortfall screen: the emit is ruled in, but the lean's literal instruction prints the screen TWICE — and the page that documents the divergence ships a sample no build of antseal can produce

- **Status: RESOLVED. The lean's DIRECTION survives on measurement; its
  INSTRUCTION is overturned twice, and a third defect nobody had named is
  ruled in the same act.** The lean was *"Implement the emit — render the
  report before `preflight()?` in the `DryRun` arm, mirroring
  `seal_consent.rs:441`."*
  - **The emit is ruled IN.** Measured on the wire, the same wallet state
    produces **1 064 bytes / 18 lines / 2 `** SHORT by **` markers** on the
    real-seal path and **0 bytes on both streams** on the dry-run path
    (§1.1). D49 §3's sentence is unimplemented exactly as U79 states.
  - **"Render before `preflight()?`" is WRONG AS WRITTEN and must not be
    implemented literally.** `seal_consent.rs`'s emit sits inside
    `confirm`, whose caller renders nothing; `seal_run.rs`'s `DryRun` arm
    returns a value that `commands.rs:423-425` renders **unconditionally on
    every `Ok`**. A mirror of `:441` — an emit before the `?` — therefore
    prints the complete rehearsal screen **twice** on the success path,
    which is every dry run by a funded user. The emit must be **conditional
    on the preflight refusing**, and that asymmetry is the ruling's whole
    substance (§2 R1, R2).
  - **The lines to emit are NOT `ConsentReport::render()`.** A literal
    mirror emits the gate's screen, which lacks the dry-run trailer
    (`seal_run.rs:284-289`) — the sentence that tells a user who has just
    been shown a scary shortfall that **nothing was paid and the vault was
    not touched**. The emitted document must be
    `SealCommandResult::DryRun(..).render()`, so the shortfall screen and
    the funded screen are byte-identical up to the numbers (§2 R1).
  - **What the lean's premise 1 asked, answered NO.** `preflight()` takes
    `&self` and delegates to a pure function of `(balances, quote)`
    (`backend.rs:79-102`) — it populates and mutates nothing the renderer
    reads, so the report is complete before it runs and "render first"
    prints the same document D49 promises (§1.2). The lean does not die
    there; it dies on the caller.
  - **A defect the row never named, found in a live product page.**
    `docs/user/funding-your-wallet.md:54-63` shows a `--dry-run` report
    carrying `** SHORT by <N> **`. That output is **unreachable in every
    build**: the marker and the preflight read the same two comparisons with
    the same sense, so a report that renders never carries a marker and a
    report that would carry one never renders (§1.4). The page contradicts
    itself twenty lines later at `:77-83`, where it documents the divergence
    as behaviour. Both halves are repaired by this ruling — one by the code,
    one by an edit supplied verbatim (§2 R5).
  - **The D69 third arm was considered and REFUSED**, and it had to be
    considered: D49 resolved 2026-08-01, and on 2026-08-12 a maintainer
    choice created an arm that did not exist when §3 was written — `ok`
    means *"a result document is present"*, not *"the exit code is 0"*
    (`lib.rs:147-176`, D69 §3 R1). It loses because it would delete the
    machine-readable class from the one document a funding script reads
    (§3.2).
- **Date: 2026-08-18**
- **Owning tasks:** U79 (`tasks/U.md:1118-1136`, `TODO.md:845`). Amends
  **D49 §3** by dated addendum (§2 R4). Touches U14/U16 (the report and the
  rehearsal), U2/D69 (codes and the third arm), D65/U3 (the `--json`
  envelope), D51 (stream routing). Adjacent: **U80**, which edits the same
  product page in the same tranche (§2 R7).

---

## 1. The measurement

Every command below was run from `/home/deb/Documents/code0` with
`REAL_EXIT=` captured into a file and read back, per the wave rule. No
`--self-test`, no gate, no writes outside this record.

### 1.1 The two paths, byte for byte, on the same wallet state

The suite's `SealContext` sets `to_stderr: true` (`seal_command.rs:78-90`),
so both paths' human copy lands on stderr where `--nocapture` can be
captured.

```
$ cargo test -p antseal-cli --test seal_command -- --exact \
    the_two_shortfalls_are_distinct_and_nothing_is_paid --nocapture
REAL_EXIT=0        # ok. 1 passed
```

stderr, with the three cargo lines stripped: **18 lines, 1 064 bytes, two
`** SHORT by **` markers** — the complete consent report, twice (once per
shortfall case). One case verbatim:

```
Sealing 1 file(s), 7 byte(s):
    a.txt  (7 bytes)
  Upload:      2 blob(s) — every encrypted unit plus the encrypted manifest
  Cost: 18489 atto-ANT storage, plus about 23000 wei of gas
  Wallet:      0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
               0 atto-ANT  ** SHORT by 18489 **
               18446744073709551615 wei
  WARNING: upload is permanent, public, and irreversible.
  Anyone who later holds this vault or its passphrase can decrypt these ciphertexts, and nothing on the network can be deleted or rotated.
```

```
$ cargo test -p antseal-cli --test seal_command -- --exact \
    a_dry_run_with_a_drained_wallet_exits_with_the_real_shortfall_code --nocapture
REAL_EXIT=0        # ok. 1 passed
```

stderr, same stripping: **0 lines, 0 bytes.** stdout: nothing but the
harness's own lines. The identical wallet state, over the identical file,
through the same `ConsentReport` type:

| path | human bytes on shortfall | markers | exit |
|---|---|---|---|
| real seal (`confirm`) | **1 064** (18 lines, 2 cases) | 2 | 20 / 21 |
| `--dry-run` | **0** | 0 | 20 / 21 |

That is U79's finding, measured on the wire rather than read off the source,
and it is the whole of the case for implementing.

### 1.2 The lean's premise 1: does `preflight()` change the document?

No. `ConsentReport::preflight(&self)` (`seal_consent.rs:110-113`) delegates
to `antseal_net::preflight(&self.balances, &self.quote)`
(`backend.rs:79-102`), which constructs a local `PreflightReport`, compares
two pairs of integers, and returns. It takes shared references, mutates
nothing, performs no I/O, and its `Ok` value is **dropped** at both call
sites. `ConsentReport::render()` reads `files`, `total_input_bytes`,
`warnings`, `blob_count`, `quote`, `balances`, `prior`, `proofs_expired`,
`dry_run` — and computes the shortfall markers itself through the local
`shortfall()` helper (`:236-242`). It never reads a `PreflightReport`.

So "render before preflight" prints exactly the document D49 promises. The
lean survives its own first test. It fails the second one, below.

### 1.3 The caller renders every `Ok` — so a literal mirror double-prints

`run_seal` emits **nothing** on either dry-run path today. Measured:

```
$ cargo test -p antseal-cli --test seal_command -- --exact \
    a_dry_run_quotes_reports_and_mutates_nothing --nocapture
REAL_EXIT=0        # ok. 1 passed;  stdout/stderr from run_seal: 0 bytes
```

The successful dry run's screen reaches the user from
`commands.rs:423-425`:

```rust
    for line in result.render() {
        ui.line(&line);
    }
    Ok(Outcome::value(result.json()))
```

That loop is unconditional on the `Ok` value and is preceded by the `?` at
`commands.rs:421` that swallows every `Err` before it. `seal_run.rs` has
exactly one emitter (`SealContext::emit`, `:586-594`) with exactly one call
site (`:365`, D45's resume notice), and that notice is **not** part of
`result.render()`, which is why it does not double today.

Compose the two measurements: `run_seal` prints 0 bytes on the dry-run
success path, and the handler prints the screen once. Add an unconditional
emit in the `DryRun` arm — the literal instruction — and the funded user
gets the whole rehearsal screen **twice**, from two different emitters, with
no test in the tree able to see it (§1.6). The instruction is wrong, and the
correction is one word: **conditional**.

### 1.4 `** SHORT by **` is unreachable in a `--dry-run` report, in every build

`shortfall(available, required)` returns `""` when `available >= required`
and `"  ** SHORT by {required - available} **"` otherwise
(`seal_consent.rs:236-242`). `preflight` returns `Err` when
`available_ant < required_ant`, else `Err` when
`available_gas < required_gas` (`backend.rs:89-100`). The same two field
pairs, the same predicate, opposite branches. A dry-run report reaches
`render()` only from the `Ok` value (`seal_run.rs:520` → `commands.rs:423`),
which requires `preflight()` to pass, which requires **both** markers to be
empty.

Therefore, today: **no `--dry-run` invocation of any build can print
`** SHORT by `.** And `docs/user/funding-your-wallet.md:54-63` prints it as
the dry run's own output, under the heading *"Find out what it costs before
you fund"*, citing `seal_consent.rs:139-158, :236-242`. The citation is
correct about the renderer and wrong about reachability, which is exactly
how this class of defect survives review.

### 1.5 The claim's readers, and the reader it fails hardest

D49 §3's *"documented CI gate"* sentence has **no automated reader** —
`rg -- "--dry-run" scripts/ .github/` returns only `cargo publish --dry-run`
and `cargo update --dry-run`, unrelated. It has **two documentation
readers**, both live product copy:

1. `docs/user/funding-your-wallet.md:73-75` — *"`--dry-run` also exits with
   the same shortfall codes a real seal would, so it works as a scripted
   check for 'could this machine seal this work right now'"*, citing
   `D49:98-105`. **True today.** Followed at `:77-83` by a paragraph that
   documents the divergence as shipped behaviour — accurate prose about an
   inaccurate product, which is what U79 is for.
2. `docs/user/wallet-hygiene.md:310-313` — *"Fund close to when you seal and
   keep balances small — `antseal seal --dry-run` will tell you what a work
   costs before you move anything."*

Reader 2 is where the divergence actually bites, and no row had named it. A
user who has **not yet funded** holds 0 ANT. 0 ANT is short of any non-zero
quote. So the documented "find out the cost before you fund" route returns
the typed error and no report **precisely for the reader it is written for**
— the pre-funding one. The error string carries `required_atto` and
`available_atto`, so the ANT figure survives; the **gas** figure does not,
because `preflight` short-circuits on ANT first (`backend.rs:89-94`, pinned
by `preflight_splits_the_two_shortfalls_ant_first` and by
`seal_consent.rs:770-791`'s *"ANT first (S8's fixed order), even when both
are short"*). A freshly `init`ed wallet — 0 ANT **and** 0 ETH, the default
`--wallet generate` branch — therefore learns the storage price and **never
learns that it also needs gas**, from the command the docs point it at.

The rendered report, by contrast, marks **both** lines independently
(`:149-158`): one screen, both requirements, both shortfalls. That is the
product gain this ruling buys, and it is larger than "the report prints".

### 1.6 What can and cannot be observed by a test in this workspace

Both routes to observing emitted bytes are closed, measured:

- **The binary route.** `seal` in the default build never reaches a wallet
  at all: the registered envelope fixture
  (`tests/snapshots/json-envelopes.txt:3-4`) is
  `{"command":"seal","error":{"class":"network-failure","exit_code":23,
  "message":"… this build has no storage backend compiled in (the
  `ant-backend` feature is off by default) …"}}`. The spawned-binary harness
  can never reach the preflight; with `--features ant-backend` it would need
  a live network and a funded-then-drained wallet.
- **The in-process route.** The emitters are `println!`/`eprintln!`, and the
  crate cannot read its own process streams "without an unstable API or a
  `libc` dependency (and no new dependencies, U29)" — the house's own
  finding, recorded at `tests/reveal_consent.rs:513-524` for the identical
  question about `reveal`'s screen.

Consequence, and it is a **correction to U79's Accept row 2**: "the test
asserts the report's presence … on the shortfall path" cannot mean *presence
on a file descriptor*. The strongest instrument available is the one the
real path already uses — `SealConsent::rendered`
(`seal_consent.rs:349`), read by `machine_mode_without_yes_declines_and_never_prompts`
as `assert_eq!(gate.rendered.borrow().len(), 1)` (`:832`) with the comment
*"The report still rendered — a script's log says what it refused"*, and by
`tests/reveal_consent.rs:476, :510`. §2 R2 puts the dry-run path on that same
instrument, in both directions, and §6 states plainly what it does not prove.

### 1.7 Why the existing test could not see it, stated precisely

`a_dry_run_with_a_drained_wallet_exits_with_the_real_shortfall_code`
(`seal_command.rs:813-858`) asserts `err.class()`, `err.exit_code()`,
`calls(Pay) == 0`, `calls(FinalizeBatch) == 0`. It passed at **0 emitted
bytes** (§1.1) and every one of those four assertions is a property of the
returned `Err` and of the mock's counters — none is a function of anything
`run_seal` writes to a stream. It would pass identically at 1 064 emitted
bytes. It is not a weak test of the emit; it is not a test of the emit.

### 1.8 The codes are distinct today, and nothing else reaches this path

- `ErrorClass::InsufficientAntToken => 20`, `InsufficientEthGas => 21`
  (`error.rs:381-382`), names `insufficient-ant-token` /
  `insufficient-eth-gas` (`:451-452`), pinned by `tests/exit_codes.rs:64-68`.
  `cargo test -p antseal-net --lib preflight` → **2 passed, `REAL_EXIT=0`**;
  `cargo test -p antseal-cli --lib seal_consent` → **11 passed,
  `REAL_EXIT=0`** (including
  `a_shortfall_is_visible_in_the_report_and_typed_in_the_error`).
- `ConsentReport::preflight`'s error set is **exactly two members**:
  `antseal_net::preflight` has two `Err` arms, and `storage_to_cli`
  (`pipeline/error.rs:304-319`) maps them one-to-one. **This dissolves one of
  the three arms the brief asked me to weigh** — "render only on the two
  shortfall classes vs on every preflight failure" is not a choice, because
  the two sets are equal by construction. Any third class arriving here in
  future is a `CliError` that `preflight` cannot produce.
- Production call sites of `ConsentReport::preflight`: exactly two,
  `seal_consent.rs:444` and `seal_run.rs:519`. No other subcommand, no
  script, no CI lane reaches it.

---

## 2. The ruling

### R1 — The emit lands in `seal_run.rs`, conditional on refusal, over the DryRun screen

Replace the body of the `SealResult::DryRun(dry)` arm
(`crates/antseal-cli/src/seal_run.rs:505-521`) with a delegation to a new
`pub fn` in the same file, so the rule lives in one testable place:

```rust
/// D49 §3, as D146 R1 sharpens it: on a shortfall the rehearsal screen is
/// shown **before** the typed error, exactly as the real gate does
/// (`seal_consent.rs:441-444`) — and **only** when the preflight refuses.
///
/// The asymmetry with the gate is deliberate and is the finding D146 exists
/// for. `ConsentHook::confirm` emits unconditionally because nothing
/// downstream of it renders; this arm returns a value that
/// `commands.rs:423-425` renders on **every** `Ok`, so an unconditional
/// emit here would print the whole screen twice for every funded dry run.
/// Measured before the change: `run_seal` emitted 0 bytes on both dry-run
/// paths (D146 §1.1, §1.3).
///
/// The lines are `SealCommandResult::render()`'s, never
/// `ConsentReport::render()`'s: the trailer at `:284-289` is the sentence
/// that tells a user staring at a shortfall that nothing was paid and the
/// vault was not touched, and the shortfall screen must be the funded
/// screen with different numbers.
pub fn dry_run_outcome<P: crate::seal_consent::ConsentPrompt>(
    consent: &crate::seal_consent::SealConsent<'_, P>,
    dry: &crate::pipeline::DryRunReport,
    ctx: &SealContext,
) -> Result<SealCommandResult, CliError> {
    let request = crate::pipeline::ConsentRequest {
        seal_id: SealId::from_bytes([0; 16]),
        quote: &dry.quote,
        blob_count: dry.blob_count,
        prior: None,
        resume: false,
        proofs_expired: false,
    };
    let mut report = consent.report_for(&request);
    report.dry_run = true;
    // Pure over the report's own fields (`antseal_net::preflight`,
    // backend.rs:79-102), so computing it here changes nothing the
    // renderer reads (D146 §1.2).
    if let Err(err) = report.preflight() {
        let screen = SealCommandResult::DryRun(Box::new(report.clone()));
        consent.show(&screen.render(), &report);
        return Err(err);
    }
    Ok(SealCommandResult::DryRun(Box::new(report)))
}
```

and the arm itself becomes `SealResult::DryRun(dry) => dry_run_outcome(&consent, &dry, ctx)`.

`SealConsent` gains the emit-and-record pair, so neither path can emit
without recording or record without emitting
(`crates/antseal-cli/src/seal_consent.rs`, beside `emit` at `:423-431`):

```rust
    /// Show one screen and record it — two acts that must never come apart.
    ///
    /// `ConsentHook::confirm` calls it before the preflight; `--dry-run`
    /// calls it **only** when the preflight refuses, because its `Ok` path
    /// is rendered by the caller (D146 §2 R1).
    pub fn show(&self, lines: &[String], report: &ConsentReport) {
        self.emit(lines);
        self.rendered.borrow_mut().push(report.clone());
    }
```

and `confirm` (`:435-444`) collapses onto it:

```rust
        let report = self.report_for(request);
        self.show(&report.render(), &report);
        report.preflight()?;
```

Behaviour on the real path is unchanged byte for byte: `emit` then push then
preflight, in that order, is what `:441-444` already does.

**Do not** move the preflight out of `run_seal`, **do not** render from
`commands.rs` for the shortfall case, and **do not** make the emit
unconditional. R2's second planted fault exists to catch the last one.

### R2 — The test, in both directions, with the two planted faults named

Add to `crates/antseal-cli/tests/seal_command.rs`, beside the existing D49
block. It calls `dry_run_outcome` directly, because the `SealConsent` that
`run_seal` builds at `:394` is internal and unreachable from a test:

```rust
/// **D49 §3 / D146 R1**: a dry run that finds a shortfall shows the whole
/// rehearsal screen and *then* refuses — the order `seal_consent.rs:441-444`
/// uses on the real path, which the `DryRun` arm inverted until D146.
#[test]
fn a_dry_run_shortfall_shows_the_whole_screen_before_the_typed_error() { … }
```

It must assert, for each of three balance cases (ANT-only short, gas-only
short, **both** short):

1. `Err`, with `class()` and `exit_code()` equal to 20 / 21 (both-short is
   ANT, `backend.rs:89-94`);
2. `consent.rendered.borrow().len() == 1`, with the failure message
   **`"the dry-run shortfall screen never rendered: D49 §3 requires the complete report before the typed error, and D146 §1.1 measured this path at 0 emitted bytes"`**;
3. over `SealCommandResult::DryRun(Box::new(recorded)).render().join("\n")`:
   the file list line, `"Cost (indicative):"`, `PERMANENCE_WARNING`, the
   trailer `"Dry run: nothing was"`, and the exact
   `format!("** SHORT by {n} **")` for each short asset — **two markers in
   the both-short case**, with a message saying that this is the screen's
   whole advantage over the error, which can name only the first asset.

And the anti-double-print direction, in the **same** test file, over a
funded gate:

```rust
/// **D146 R1's other half**: on the success path this arm emits nothing,
/// because `commands.rs:423-425` renders every `Ok`. An unconditional emit
/// — the literal reading of U79's `Do` line — prints the screen twice.
#[test]
fn a_funded_dry_run_leaves_the_screen_to_its_caller() { … }
```

asserting `Ok(..)` **and** `consent.rendered.borrow().is_empty()`, with the
message
**`"the rehearsal screen was emitted here AND by the caller: commands.rs:423-425 renders every Ok, so a funded dry run would print it twice"`**.

**The two planted faults, each watched red by its message, not by exit
code** (`${PIPESTATUS[0]}` into a file, read back):

- **F1** — delete the `consent.show(...)` line from the refusing branch.
  Expected: `a_dry_run_shortfall_shows_the_whole_screen_before_the_typed_error`
  fails on assertion 2 with the message above. This is the regression the
  row was minted for; if F1 does not redden, the test is the same shape as
  the one it replaces.
- **F2** — hoist `consent.show(...)` above the `if let Err`, i.e. implement
  U79's `Do` line literally. Expected:
  `a_funded_dry_run_leaves_the_screen_to_its_caller` fails with the
  double-print message. F2 must be run: it is the only instrument that
  distinguishes this ruling from the lean.

Leave `a_dry_run_with_a_drained_wallet_exits_with_the_real_shortfall_code`
(`:813-858`) as it is, and add one comment line to it naming the new test as
where the screen is asserted and saying why it cannot be asserted there
(the gate is internal — §1.6).

### R3 — `--json` on the shortfall path: no result document. Ruled, not inferred

On a dry-run shortfall, in **both** modes, the invocation ends in
`Err(CliError)` and reaches `main_entry`'s `fail` (`lib.rs:114-120`).
Therefore:

- **stdout carries exactly one document and it is the error envelope**:
  `{"v":1,"command":"seal","network":…,"ok":false,"error":{"class":"insufficient-ant-token"|"insufficient-eth-gas","exit_code":20|21,"message":…}}`.
  **There is no `result` document, and a script must not wait for one.**
- **the rehearsal screen goes to the human channel** — stderr under
  `--json`, stdout in plain mode — because `ctx.to_stderr` is `globals.json`
  (`commands.rs:391`) and `SealConsent::emit` routes on it
  (`seal_consent.rs:425-429`). Identical to the real seal's shortfall, which
  is the point.
- **no new registered fixture, no `ENVELOPE_VERSION` move, no snapshot
  bless.** The two registered dry-run `result` documents
  (`json-envelopes.txt:35-38`) are unaffected: they are success documents
  and this path produces none.
- **The error object stays `{class, exit_code, message}`.** It is D65 tier B
  and `docs/testing/error-code-contract.md`'s property; the required and
  available figures ride in `message` for the **first** short asset only.
  A script that needs both assets' figures reads the human channel or funds
  the first asset and re-runs. Say this in the addendum rather than leaving
  a consumer to discover it.

### R4 — D49 gains a dated addendum. Verbatim text

Append to `docs/decisions/D49-dry-run-network-semantics.md`, after the
`## Residual risk` section, without editing a single existing line
(D117's form: history is not rewritten):

```markdown
## Addendum — 2026-08-18 (D146, U79)

**§3's first sentence was never implemented, and is now.** From
2026-08-01 to this addendum, a dry run that failed the S8 preflight
returned the typed error and printed **nothing**: `seal_run.rs`'s `DryRun`
arm ran `report.preflight()?` and the `?` preempted the render, which
happens only from the `Ok` value. Measured on the wire (D146 §1.1): the
same wallet state produced 1 064 bytes of report on the real-seal path and
0 bytes on the dry-run path. D146 §2 R1 implements the emit.

**Three clauses §3 lacked, ruled by D146 and binding here:**

1. **The emit is conditional on the preflight refusing.** On the success
   path the caller renders the same screen (`commands.rs:423-425`), so an
   unconditional emit — a literal mirror of the gate at
   `seal_consent.rs:441` — prints it twice. §3's "still prints the complete
   report" describes the *shortfall* path only.
2. **Channel and mode.** The complete report goes to the human channel
   (stdout in plain mode, stderr under `--json`, D51 invariant 2), and under
   `--json` stdout carries **exactly one document: the error envelope**.
   **There is no `result` document on the shortfall path** — §3's
   "single `--json` result document" clause describes success only, and a
   script must gate on the exit code and on `error.class`, not on `result`.
   The error names required and available for the **first** short asset
   only (ANT before gas, `backend.rs:89-100`); the report names both.
3. **The D69 third arm is refused here.** D69 §3 R1 (2026-08-12, after this
   record resolved) made `ok` mean "a result document is present" rather
   than "the exit code is 0", so a dry-run shortfall *could* now emit
   `ok:true` + `result` at exit 20/21. It does not: the real seal reports
   the same condition as `ok:false` + `error`, and D49 §1's prefix
   principle makes dry-run the real pipeline truncated, not a mode with its
   own envelope shape. A funding shortfall is not a verdict.

**§3's "documented CI gate" claim stands, and is now true rather than
aspirational.** The gate is: exit 0 = fundable; 20 = acquire ANT; 21 =
bridge ETH; the screen on the human channel explains it to a person.
```

### R5 — `docs/user/funding-your-wallet.md` loses one paragraph and keeps its sample. Verbatim

The page is COPY_SCAN'd product copy, so the edit lands with the code, in
the same act. **Delete `:77-83` entirely** — the paragraph beginning *"One
difference worth knowing, because it is easy to misread as a broken
command:"* through *"…so you can still work out the shortfall."* — and put
in its place:

```markdown
When a dry run finds you short it prints the whole report first and then
refuses, exactly as a real `seal` does — the file list, the quote, both
balances, and a `** SHORT by <N> **` marker beside every asset you are
short of. The exit code says which remedy you need (20 = acquire ANT,
21 = bridge ETH) and the typed error repeats the figures for the first one
(`crates/antseal-cli/src/seal_run.rs`, the `DryRun` arm;
`docs/decisions/D146-dry-run-shortfall-screen.md`).

Under `--json`, that report goes to stderr and stdout carries one error
envelope with `ok: false` and the class — there is **no** `result` document
on the shortfall path, so gate a script on the exit code and on
`error.class`, never on the presence of `result`.
```

`:54-63`'s sample block stays exactly as it is: this ruling is what makes
it reachable for the first time (§1.4). `docs/user/wallet-hygiene.md:312`
needs **no edit** and becomes true for the reader it was written for — the
one who has not funded yet (§1.5); re-read it after the change and leave it.

### R6 — `tasks/U.md` U79's `Accept` and `Do` are AMENDED. Replacement text, verbatim

The `Do` line's *"render the report before `preflight()?` in the `DryRun`
arm, mirroring `seal_consent.rs:441`"* is **wrong as written** and must not
survive as an instruction (§1.3). Replace the `Do` bullet with:

```markdown
- Do: **Ruled by D146 (2026-08-18): implement the emit, conditionally.**
  Render the complete `SealCommandResult::DryRun` screen — trailer included
  — **only when `preflight()` refuses**, then return the typed error;
  the success path stays unrendered because `commands.rs:423-425` renders
  every `Ok` and an unconditional mirror of `seal_consent.rs:441` prints
  the screen twice. Amend D49 by dated addendum (D146 §2 R4), delete the
  paragraph at `docs/user/funding-your-wallet.md:77-83` (D146 §2 R5), and
  pin both directions with the two planted faults D146 §2 R2 names.
```

and replace `Accept` rows 2 and 3 with:

```markdown
  - The screen's presence at the moment of refusal is asserted through
    `SealConsent::rendered` — the same instrument the real path uses
    (`seal_consent.rs:832`) — with a planted deletion of the emit watched
    red by its message. **Presence on a file descriptor is not asserted and
    cannot be**: `seal` is unwired in the default build and the crate cannot
    read its own streams without a new dependency (D146 §1.6).
  - The **no-double-print** direction is asserted too: a funded dry run
    leaves `rendered` empty, and hoisting the emit above the branch is
    watched red by its message.
  - `--json` on the shortfall path is stated in D49's addendum and in
    `docs/user/funding-your-wallet.md`: **no `result` document**, one error
    envelope on stdout, the report on the human channel.
```

Accept rows 1 and 4 stand unchanged.

### R7 — Sequencing with U80, which edits the same page

U80 re-blesses `cli-surface.help.txt` and corrects the quotation at
`docs/user/funding-your-wallet.md:49`. U79's edit is at `:77-83`. **They do
not overlap and must not be merged**, but whichever lands second re-reads
the whole page rather than patching by line number — the deletion at `:77-83`
moves every line below it, and D139's twenty-eight dead locators are what
that rule is made of.

### R8 — This record's own index row

`docs/decisions/README.md` gains, in ascending id order after D145's row
(the registrar's act, not this lane's — my write scope is this file alone):

```markdown
| [D146](D146-dry-run-shortfall-screen.md) | U79 — D49 §3's dry-run shortfall render. **The direction survives and the instruction is overturned**: measured, the same wallet state prints 1 064 bytes of report on the real-seal path and **0** on the dry-run path, so the emit is ruled in — but "render before `preflight()?`, mirroring `seal_consent.rs:441`" prints the screen **twice** on the success path, because `commands.rs:423-425` renders every `Ok`, and it emits the wrong document (the gate's screen has no dry-run trailer). The emit is conditional on refusal, over `SealCommandResult::render()`. `preflight` is pure over the report's own fields, so the lean's premise-1 objection fails. **A third defect nobody had named**: `** SHORT by <N> **` is unreachable in a `--dry-run` report in every build — the marker and the preflight read the same comparison with the same sense — and `docs/user/funding-your-wallet.md:54-63` ships it as sample output. `--json` shortfall carries **no `result` document**; the D69 third arm is refused because a funding shortfall is not a verdict | RESOLVED | 2026-08-18 |
```

Until that row exists, `python3 scripts/check-traceability.py` reddens on
`decision-index` — *"D146 has a record and no row in the index"* — which is
the check working, not a defect.

### R9 — What must NOT change

- No new `ErrorClass`, no new exit code, no renumbering: 20 and 21 stay
  distinct and stay where `tests/exit_codes.rs:64-68` pins them.
- No `ENVELOPE_VERSION` move, no new registered `--json` fixture, no
  snapshot re-bless. This ruling adds no document to any surface U32 will
  freeze; it makes an existing one reachable.
- No change to `--dry-run`'s side-effect profile: zero payment, zero
  upload, zero vault mutation, one `quote_batch`. The three assertions in
  `a_dry_run_quotes_reports_and_mutates_nothing` (`:706-716`) must stay
  green untouched.

---

## 3. The arms refused

### 3.1 Amend D49 to "the shortfall path is error-only"

The row's second arm, and it loses on four counts:

1. It contradicts **D49 §1**, the record's own foundation: `--dry-run` is
   "the same code path truncated, never a reimplementation". Refusing
   differently from the real seal on the identical condition makes it a
   parallel mode in the one place a user meets bad news.
2. It leaves the pre-funding reader — the documented one, §1.5 — with the
   ANT figure and no idea gas exists.
3. It does not even save the doc edit: `funding-your-wallet.md:54-63` would
   still be shipping unreachable sample output, so this arm pays the
   documentation cost **and** keeps the worse product.
4. It is more text than the code change. The implementation is one
   conditional and one shared method.

### 3.2 Route the shortfall through D69's third arm (`Ok` + `exit_class`)

Not in the row, and it had to be weighed: D69 §3 R1 (`lib.rs:147-176`,
maintainer-confirmed 2026-08-12) created a real third arm **after** D49
resolved, and it is the only arm under which a test could observe the screen
in the returned value. `verify` uses it; `RestoreOutput::exit_class`
(`restore_out.rs:232-247`) is built for it. Refused:

- **It deletes the machine-readable class from the document a funding script
  reads.** `ok:true` means no `error` object, so `insufficient-ant-token`
  survives only as an integer exit code, while the *real* seal keeps
  `error.class` for the same wallet state. `funding-your-wallet.md:21-22`
  teaches users to tell the two failures apart by class. Two shapes for one
  condition is the hidden-difference trap this project mints rows about
  (U81 is the same principle applied to `StrandedPayment`).
- **A funding shortfall is not a verdict.** Both existing third-arm users
  fold *the command's own product* — a verification verdict, a per-file
  restore outcome — into a rung. A dry run's shortfall is a refusal to
  proceed, which is what `Err` means everywhere else in this CLI.
- **It costs a schema event days before U32's freeze**: a new
  `SealCommandResult` variant, a third registered dry-run fixture, a
  `json-envelopes.txt` re-bless, and a D65 tier-C note — against a
  conditional and a shared method.
- Its one genuine advantage, testability, is worth less than it looks: §2
  R2's `rendered` instrument reddens on both planted faults without it.

### 3.3 Render on "every preflight failure" rather than on the two shortfall classes

**Dissolved, not refused.** `ConsentReport::preflight`'s error set is exactly
`{InsufficientAntToken, InsufficientEthGas}` (§1.8), so the two phrasings
name the same set. Writing a class match into the arm would be an
unreachable branch pretending to be a policy. The brief listed this as a
live third arm; it is not one.

### 3.4 stdout vs stderr as a fresh decision

Refused as already-decided: D51 invariant 2 and `ctx.to_stderr =
globals.json` settle it, and the real path is on the same rule. Re-deciding
it here would give one command two stream policies.

### 3.5 A `preflight()` that returns the report alongside its error

Refused. `CliError` is a flat, `Display`-driven type whose `error_object()`
is D65 tier B; hanging a `ConsentReport` off a variant would put a rendered
screen inside the error type that `exit_codes.rs` enumerates, for the
benefit of one call site. The report is already in the caller's hand.

### 3.6 Emitting from `commands::seal` after `run_seal` returns `Ok` on shortfall

Refused, though it is the tidiest-looking option: it would make `run_seal`
return `Ok` for a wallet that cannot pay, so the library boundary would stop
refusing and the suite's `expect_err` would become a call to `preflight()`
that restates the implementation — an assertion that cannot fail, on the
exact path this row exists to fix.

---

## 4. Falsifiers

- **F1 fails to redden.** If deleting `consent.show(...)` leaves the test
  green, the assertion is reading a neighbouring field and this ruling's
  instrument is the same shape as the one it replaces. Stop and report.
- **F2 fails to redden.** If hoisting the emit above the branch leaves
  `a_funded_dry_run_leaves_the_screen_to_its_caller` green, then the funded
  path is not being exercised through `dry_run_outcome` and §1.3's whole
  finding is unpinned.
- **The screens are not the same document.** Capture the funded dry-run
  screen and the shortfall screen for the same file and diff them: they must
  differ only in the balance figures and the markers. If the shortfall
  screen has lost the trailer, R1's "not `ConsentReport::render()`" clause
  was not implemented.
- **`grep -c "SHORT by"` over a shortfall screen returns 0.** Then §1.4's
  reachability argument is wrong somewhere and `funding-your-wallet.md:54-63`
  is still shipping unreachable copy.
- **A second document appears on stdout under `--json`.** R3 is violated;
  `machine_mode.rs`'s one-document harness owns that property.

---

## 5. Defects found that are not this decision's subject

1. **Three implementations of one stream rule.** `Ui::line`
   (`commands.rs:110-116`), `SealConsent::emit` (`seal_consent.rs:423-431`)
   and `SealContext::emit` (`seal_run.rs:586-594`) each re-implement
   "stdout in plain mode, stderr under `--json`". Identical bodies, three
   authors. This ruling adds no fourth, and deliberately routes the new emit
   through `SealConsent`'s so the seal's human copy has one emitter — but
   the collapse of the remaining two is instrument-class and belongs in the
   ledger, not here.
2. **`SealContext::emit`'s only other call site is unpinned.** D45's resume
   notice (`seal_run.rs:364-366`) is emitted with no test observing that it
   *is* emitted — the same blind spot U79 names, one arm over. Its lines are
   pinned as a value (`seal_resume.rs:581-589`); its emission is not.
3. **`funding-your-wallet.md:49` quotes the phrase D49 §4 refused** — that
   is U80's row, named here only because R7 sequences the two edits.
4. **`restore`'s exit-35 fixture has no reachable producer**: the handler is
   `Err(unavailable("restore"))` (`commands.rs:602-612`) and passes no
   `exit_class`, so `RestoreOutput::exit_class` has no production caller in
   this build. Not a defect in the fixture — U20's live wiring is
   outstanding — but a reader who cites `restore` as a live D69 third-arm
   consumer (as I nearly did in §3.2) is citing a prepared one. `verify` is
   the only live one.

---

## 6. What this record does NOT cover

- **It does not prove any byte reached a file descriptor.** §2 R2's
  instrument is `SealConsent::rendered` — the recorder written on the line
  beside the emit, under one comment, inside one four-line method that both
  paths call. That the recorded screen was also *written* to a stream is
  guaranteed by that method's body and by nothing a test in this workspace
  can observe (§1.6). This is the same honesty
  `tests/reveal_consent.rs:513-524` states for `reveal`'s stream routing,
  and the same limitation the real-seal path has always had.
- **It does not touch the resume dry run.** `SealCommandResult::ResumePlan`
  returns at `seal_run.rs:382-384`, before any balance read, so D45 §5's
  rehearsal has no preflight and no screen to withhold. Unchanged.
- **It does not rule on the anchor-gate abort, the consent classes, or any
  other pre-payment refusal.** Only `preflight`'s two classes are in scope
  (§1.8), and only in the `--dry-run` arm.
- **It does not add structured shortfall fields to any `--json` document**,
  in either mode. R3 rules the error object untouched; whether a future
  envelope should carry required/available as typed fields is D65's and
  `docs/testing/error-code-contract.md`'s question, not this row's.
- **It does not re-open D49 §4's indicative-cost wording** (U80) or D49 §1,
  §2, §5, which are re-read and left standing.
- **It measured nothing against a live network.** Every figure here comes
  from `MockBackend` through the committed suites; the `ant-backend` build
  and a real Arbitrum wallet are out of scope and out of reach (§1.6).
- **It does not run the gate.** `scripts/local-gate.sh` and every
  `--self-test` are forbidden mid-wave with sibling lanes in the tree; the
  implementation lane runs them.
