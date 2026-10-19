# D199 — `verify --live` reports a storage client that **never connected** as **not connected** and **fetches nothing**: the host reads the degrade **by type**, the live section takes a closed `not-connected` state with one R18 line and no rows, and the refusal's reason goes to stderr as a note outside the verdict document

- **Status: RESOLVED. H5, for `R98`, fared (b): its direction — a section-level answer rather
  than a new `FetchFailureClass` value, and a naming in `--json` — survived, and its premises
  fell.**
  - **H5 — *a section-level line ("no connection to the Autonomi network was made: <reason>")
    on human output and a field in `--json`, NOT a new closed `FetchFailureClass` value — the
    kind is not a type at the net boundary*.** (b):
    - **"The kind is not a type at the net boundary" is true but not decisive.** The degrade
      **is** a type at the host: `ReadOnlySource::Unreachable`, read through
      `ReadOnlyBackend::degraded()` (`crates/antseal-cli/src/backend.rs:664-669`), and the host
      is where the live inputs are built. A closed state needs no message parsing (§1.2). What
      rules out a `FetchFailureClass` value is that no fetch is made, that
      `fetch_failure_class` is the one converter (`crates/antseal-net/src/live.rs:153-155`),
      and the five count pins a third class would move (§1.4).
    - **"A section-level line (…: <reason>)" falls.** The reason is not antseal-authored
      text: K4 is upstream's own `AntError` text, and K1 and K2 embed configuration and
      environment values (D191 §1.2). It cannot sit in R18-frozen verdict wording (`R79`;
      `R98`'s own Spec line; `crates/antseal-cli/src/verify_out.rs:334-353`). The section line
      is closed; the reason is a CLI diagnostic on stderr (§2 R2, R3).
    - **"A field in `--json`" survives as a closed value**, `live.verdict: "not-connected"`
      with `"rows": []`, not as a free-form field. The planner's question (P3 §5) is ruled:
      the closed value is the naming `R98`'s Accept asks for (§2 R3).
  - **Found with it: an in-process test already pins today's classification, and the
    narrowed bound breaks three more calls in the same file.**
    `crates/antseal-cli/tests/verify_command.rs:765` drives a degraded client through
    `run_verify_live` and asserts `Inconclusive` (§1.3). The planning report did not find it
    (§0), and no lane's write scope names the file (§5).
- **Date: 2026-10-19**
- Owner row: **`R98`** (§2 R1–R5).
- Related:
  - **D170** §2 R2 (the degrade; *"`verify --live` renders its offline verdict with an
    **Inconclusive** live section"*, D170:140-143), which takes a dated addendum (§2 R4);
  - **D191** (the kind-neutral prefix and the five kinds) and **D190**: each record's §4
    `R98` bullet is answered here and takes a dated addendum;
  - **D65** §3 tier C (D65:457, *"DECLARED UNSTABLE until U32"*), §6 rider 2 (D65:645-648, a
    widened enum is additive) and rider 4 (D65:654-658, *"Meaning counts"*);
  - **D134** §2 R3 (2) (tier C becomes stable-additive at `U32`);
  - **D69** §3 R6 (D69:535: `--live` never moves the exit code);
  - **D147** §2 R11 (D147:672: *"Do not reword `StorageError`'s own `Display` strings"*);
  - **`R79`** (antseal-authored text only in verdict wording), **`R18`** (the frozen wording
    snapshot), **`R11`** (the live verdict's precedence), **`S47`** (this wave, ruled without
    a record; it lands first, in the same file), **`U32`**.

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). The tree was clean when planning began.

Planning lane P3 (wave 39, 2026-10-19) worked read-only and built nothing: every claim it made
comes from reading code, tests and records, and every rendered output below is derived from
code and says so. Lane PS (the availability survey) found the collision with `S47` at
`degrade`, so `S47` lands first.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 07a170c:<path>`, because round-1 lanes were already editing the shared tree. Most
figures held. Three did not, and the measured figures are the ones written below:
- **`degraded()`'s readers.** P3 counted three (`backend.rs:2376`, `:2439`, `:2464`).
  `git grep -n '\.degraded()' -- crates` finds six: those three, inside the test module that
  opens at `backend.rs:1865`, and `crates/antseal-cli/tests/restore_output.rs:763`, `:768` and
  `:997`. All six are tests, so P3's conclusion — no production reader — holds.
- **In-process callers of `run_verify_live`.** P3 wrote that it has no in-process caller in
  any test and that no existing test drives a refused client through `verify --live`.
  Measured: `crates/antseal-cli/tests/verify_command.rs` calls it in-process five times
  (`:619`, `:670`, `:702`, `:775`, `:793`), and one of those tests drives a degraded client and
  asserts *Inconclusive* (§1.3).
- P3's `SCAN_ROOT` is `SCAN_ROOTS` (`crates/antseal-core/tests/verdict_wording.rs:984`).

## 1. What was measured

### 1.1 The path a refused client takes (read, not run)

1. **The handler.** `crates/antseal-cli/src/commands.rs:1036-1049`, the `ant-backend` arm:
   `rt.block_on(crate::verify_host::run_verify_live(&bytes, &options, modes, host,
   crate::backend::connect_read_only("verify", &network)))` (`:1040-1046`). The connection is
   a lazy future (D170 §2 R6). The handler then only renders `run.render()` (`:1051-1053`); it
   never holds the backend.
2. **The connection.** `connect_read_only` (`crates/antseal-cli/src/backend.rs:1557-1560`,
   inside the `ant-backend`-only `mod ant` at `:1164-1165`) hands its outcome to `degrade`
   (`:1594`) and returns `ReadOnlyBackend<AntCoreReader>`.
3. **The degrade.** `degrade` (`backend.rs:758-790`) is compiled in both builds. On `Err` it
   builds `UnreachableBackend::new(format!("no connection to the Autonomi network was made:
   {detail}"))` (`:785-787`) and emits a `tracing::warn!` (`:778-783`).
4. **The live run.** `run_verify_live` (`crates/antseal-cli/src/verify_host.rs:464-489`) is
   generic — `B: StorageBackend, C: core::future::Future<Output = B>` (`:471-473`) — so it
   cannot ask the backend whether it degraded. It awaits the connection (`:485`) and calls
   `collect_live(&decoded, &backend)` (`:486`).
5. **The classification.** Every fetch on the degraded backend fails at once with
   `StorageError::Network { reason }` (`UnreachableBackend::fail`, `backend.rs:577-583`; the
   delegation, `:705-707`), and `crates/antseal-net/src/live.rs:168` maps it:
   `StorageError::Network { .. } => Some(FetchFailureClass::Transport),`.

### 1.2 The degrade is a type at the host; its reason is not a value there

- `ReadOnlyBackend::degraded()` (`backend.rs:664-669`) returns `Some(&UnreachableBackend)`
  exactly for `ReadOnlySource::Unreachable`. That is a fact about the type, so a host that
  holds the concrete `ReadOnlyBackend<R>` can branch on it without reading any message. No
  production code reads it today: all six callers are tests (§0).
- `UnreachableBackend`'s `reason` is a private field (`backend.rs:555`), and its impl
  (`:560-584`) offers `new`, `calls` and `fail`, with no accessor. The handler cannot read
  the reason as a value today.
- The type's instrument exists for exactly the distinction this record needs: `calls()`
  (`:570-574`) counts every seam call, so a test can tell *"restored from verified copies
  after the network was asked and failed"* from *"restored without the network being asked at
  all"* (`:543-548`).

### 1.3 What a refused client prints today, and the test that pins it

Derived from code (P3 §2a):
- **stdout**, under the storage layer: *"live check: inconclusive — N fetch(es) failed and
  nothing negative was established"* (`crates/antseal-core/src/verify/wording.rs:725-730`,
  frozen at `crates/antseal-core/tests/snapshots/verdict-wording.txt:97`), then one row per
  subject, *"unit K: fetch failed (transport failure) — nothing established either way"*
  (frozen at `:101`).
- **stderr**: nothing. `degrade`'s warning is filtered out unless `RUST_LOG` is set
  (`crates/antseal-cli/src/lib.rs:207-211`, `EnvFilter::from_default_env()`).
- **`--json`**: `result.live` carries `"verdict":"inconclusive"` and one
  `{"fetch-failed":{"class":"transport"}}` outcome per row.
- **The refusal's reason renders nowhere.** Through the binary, K1 (when the gate is armed),
  K2, K4 and K5 reach this path; K3 is refused earlier, as usage (D191 §6).

**The in-process pin.** `crates/antseal-cli/tests/verify_command.rs:765`,
`live_over_an_unreachable_network_is_inconclusive_and_exits_with_the_evidence_verdict`, runs
two shapes through `run_verify_live`:
- **connect-failed** hands over `degrade("verify", Err::<SharedMock, _>(StorageError::Network {
  reason: "fixture: no bootstrap peer answered".to_owned() }))` (`:780-787`) and asserts
  `LiveLayerVerdict::Inconclusive` (`:828-833`), `counts.checked == subjects` (`:834-838`),
  every row a fetch failure (`:839-843`), zero calls reaching the network below (`:845-849`)
  and the rendered `live_inconclusive_line(subjects)` (`:861-867`);
- **every-fetch-fails** hands over a *connected* reader,
  `degrade("verify", Ok(SharedMock(..)))`, over a network holding every blob with one
  `Fault::NetworkOn(Method::GetData)` armed per subject (`:790-799`).

The connect-failed shape is today's classification, asserted in-process. Under §2 it reddens on
its verdict and its counts; the every-fetch-fails shape is already the connected control §3
needs.

**Three more calls in the same file stop compiling under §2 R1.** `:619-628`, `:670-679` and
`:702-708` pass a connection future whose output is a bare `SharedMock`, not a
`ReadOnlyBackend`. Under §2 R1's bound each needs `degrade("verify", Ok(..))` around its
output, as `:798` already has.

### 1.4 What a third `FetchFailureClass` would cost

- **antseal-net is the one classifier.** `crates/antseal-net/src/live.rs:153-155`: *"This
  function is the whole of `antseal-net`'s share: it converts **once**, at the boundary, and
  nothing downstream re-spells the result."*
- **It is buildable only three ways, each refused.** (i) A new `StorageError` variant: the
  taxonomy event D191 §2 R1 refused, touching every wildcard-free match over the type
  (`live.rs:164-176`, `storage_to_cli`). (ii) Parsing the reason's prefix in production, also
  refused by D191 §2 R1. (iii) A host-side remap of `Transport` after the fact, which is the
  downstream re-spelling `live.rs:153-155` forbids.
- **Five count pins move.** Each asserts `FetchFailureClass::ALL.len()` against 2:
  `crates/antseal-core/tests/r89_live_outcome_json.rs:72` and `:173`,
  `crates/antseal-core/tests/verdict_wording.rs:290`, and
  `crates/antseal-net/tests/live_display_channel.rs:300` and `:327`. D190 R4's cross-class
  sweep moves with them.
- **Every row would still read *"fetch failed (…)"*** for a fetch that never left the
  machine, once per subject.

### 1.5 What the ruling must honour

- **`R79`, and `R98`'s own Spec line** (`tasks/R.md:1261`: *"R79 (antseal-authored text only
  in verdict wording)"*). `crates/antseal-cli/src/verify_out.rs:334-353` renders the live
  section without an escape because both of a row's authored parts are closed sets: *"If a
  future row ever renders a value from outside those two vocabularies, this is the site that
  must gain the escape"* (`:351-353`). The degrade reason is not antseal-authored throughout.
- **D170 §2 R2** (D170:140-143) is a ruled sentence: a ruling that stops a degraded client
  rendering *Inconclusive* takes a dated addendum.
- **D65.** Tier C is *"DECLARED UNSTABLE until U32"* (D65:457). §6 rider 2: *"Widening an
  enum-valued key is ADDITIVE; narrowing it is BREAKING"* (D65:645). Rider 4, *"Meaning
  counts"* (D65:654-658): a degraded client's verdict changing from `inconclusive` to anything
  else is a change of meaning — free before `U32`, breaking after it (D134 §2 R3 (2)). That is
  why `R98` is before `U32`.
- **The verdict enum.** `LiveLayerVerdict` (`crates/antseal-core/src/verify/orchestration.rs:726-739`)
  derives `PartialOrd, Ord` and serializes kebab-case. Two exhaustive matches cover it:
  `LiveSection::new`'s `verdict_line` match (`:826-838`) and `live_verdict`'s filter closure
  (`:879-885`, `LiveLayerVerdict::NothingChecked => false`). P3 found no document that
  enumerates its spellings outside tests (`git grep -E
  'nothing-checked|some-missing|all-persisted' -- docs crates ':!docs/decisions'`: 0 hits
  outside tests; positive control, 5 hits in three test files).
- **The frozen wording has no sweep over the enum.** Section 9 of
  `crates/antseal-core/tests/verdict_wording.rs` lists each verdict line by hand (`:273-277`),
  so a new line that is not added there ships unfrozen.
- **`single_sourced()`** (`verdict_wording.rs:742`) scans `crates/antseal-cli/src`
  (`SCAN_ROOTS`, `:984`), where `degrade` spells *"no connection to the Autonomi network was
  made"* (`backend.rs:785-787`). A needle for that clause would report the CLI's own prefix as
  a renderer copy.
- **The reason can be made one line.** `escape_for_terminal`
  (`crates/antseal-cli/src/preview.rs:337-367`) escapes LF, CR, tab, C0, DEL, C1 and the bidi
  controls as visible text, so its output is one line.

### 1.6 The sentences that become false

- `crates/antseal-cli/src/verify_host.rs:449-453`: *"A backend that cannot reach the network —
  [`crate::backend::UnreachableBackend`], which a failed connection degrades to, or a connected
  reader whose every fetch fails in the network class — fails each fetch, R11 reports the
  section *Inconclusive*, and the run exits with its evidence verdict's code."* It is already
  false once since D191 (the type stands for a connection not made, `backend.rs:515-518`).
- `backend.rs:530-532`: *"…its offline verdict renders in full and each live row is a fetch
  failure, which R11 reports as *Inconclusive*."*
- `backend.rs:724-726`: *"`verify --live` renders its offline verdict with an *Inconclusive*
  live section."*
- `commands.rs:945-948`: *"…and `collect_live` re-fetch every blob the bundle embeds, the
  encrypted manifest included (R81)."* By contrast `commands.rs:950-951`, *"An unreachable
  network makes the section *Inconclusive*"*, stays true: a dead bootstrap connects (D170 §2
  R2).
- `crates/antseal-net/src/error.rs:140-142`, the doc comment on `StorageError::Network`:
  *"Transport-class failure: the operation could not get an answer from the network
  (timeouts, unreachable peers, RPC transport errors). Retryable by nature."* It is silent on
  the refusals that travel in this variant by recorded design (D173 §2 R9, D178 R1, D191
  §1.2), and *"Retryable by nature"* is false for them: a storage-gate refusal or an `S42`
  refusal recurs until its cause changes. The `#[error("network error: {reason}")]` at `:143`
  is not a sentence this record may move (D147 §2 R11).
- `docs/drills/clean-machine-verify.md:645-653` tells the operator to expect a
  *"`live check: inconclusive — …`"* line with the adapter detached, and that *"A live line
  saying anything other than inconclusive is a finding to record"*. With the adapter detached
  the connection may wait out the 60-second bound (K5, `:650-651`).
- `docs/threat-model.md:2352-2356` describes a **connected** network (*"is silent, times out,
  or serves bad bytes"* → *inconclusive*) and stays true.

## 2. RULING

### §2 R1 — Type, not text

`run_verify_live`'s connection future yields the concrete `crate::backend::ReadOnlyBackend<R>`
(`C: Future<Output = ReadOnlyBackend<R>>`, `R: StorageBackend`). When `backend.degraded()` is
`Some`, **nothing is fetched**: every fetch would fail by construction (`backend.rs:577-583`).
`commands.rs` compiles unchanged on that point, because its one production caller already
passes exactly that type (`commands.rs:1045` → `backend.rs:1557-1560`).

*Why:* the degrade is a type at the host (§1.2), so reading it needs no message parsing and no
new `StorageError` variant (§1.4). Fetching from a backend that fails every call by
construction reports N failures of an act that never happened.

The narrowed bound reaches the tests: `crates/antseal-cli/tests/verify_command.rs`'s three
calls that pass a bare `SharedMock` (`:619-628`, `:670-679`, `:702-708`) take
`degrade("verify", Ok(..))` around their output (§1.3). That file is in no lane's write scope
at dispatch (§5).

### §2 R2 — A closed section state in core

- `LiveLayerVerdict` gains `NotConnected`, wire `not-connected`: an added enum value, additive
  under D65 §6 rider 2. The inputs set it; `live_verdict`'s fold never produces it, and its doc
  says where it sits in the declared order (the enum derives `Ord`, §1.5).
- `LiveInputs` gains a not-connected constructor. `Default` stays connected (`LiveInputs`
  derives `Default`, `orchestration.rs:375`).
- `LiveSection::new` renders the state with **no rows**, zero counts and **one new R18
  line**: *"live check: not performed — no connection to the Autonomi network was made, so
  nothing was fetched and nothing is established either way"*. The lane may tighten the words;
  every clause must stay true. Neither *"transport failure"* nor *"fetch failed"* appears.
- The two exhaustive matches over the enum gain their arms, compile-forced: the
  `verdict_line` match (`orchestration.rs:826-838`) and `live_verdict`'s filter (`:879-885`).
- Section 9 of `crates/antseal-core/tests/verdict_wording.rs` gains the line **by hand**,
  because it lists each verdict line explicitly (§1.5). That is a second pin, not a
  formality. `verdict-wording.txt` is re-blessed with one line more; every line after `:97`
  shifts by one, so the living docs' `verdict-wording.txt:` citations are grepped at the act.

The wire after: `"live":{…,"verdict":"not-connected","verdict_line":"live check: not performed —
…","rows":[],"counts":{…}}`, every count 0.

*Why:* a closed state keeps `R79`'s discipline. The section line is antseal's own words, and
the live section's rendered parts stay closed sets, so `verify_out.rs:334-353`'s no-escape
ruling stays true (§1.5). One line says what happened — nothing was fetched — where N rows
said something that did not.

### §2 R3 — The reason is a CLI diagnostic, outside the verdict document

- `UnreachableBackend` gains an accessor for its carried reason (`backend.rs:550-584`), so the
  host can hand the reason out with the run.
- The CLI prints `` note: `verify --live` checked nothing — {reason} `` on **stderr**, in both
  modes. `{reason}` is the carried text — D191's kind-neutral words, then the attempt's own
  reason — passed through `escape_for_terminal`. It is never part of `run.render()`'s verdict
  document.
- In `--json`, the closed `live.verdict: "not-connected"` with `"rows": []` **is** the naming
  `R98`'s Accept asks for. The free-form reason is not a JSON key (ruled; P3 §5's question).

*Why:* the reason is not antseal-authored throughout (§1.5), so it cannot enter R18-frozen
verdict wording; stderr already carries the CLI's diagnostics; and a closed value is what a
script can branch on. Refused: the alternative P3 costed for a literal reading of the Accept, a
CLI-owned top-level `result` key holding the reason (`null` otherwise, D65 §7). It would carry
upstream text into the document as a new tier-C member and move `json-envelopes.txt:43-44`'s
`[verify] result` document by one key.

### §2 R4 — Records

- **D170 §2 R2** takes a dated addendum: a connection that was **not made** renders
  `not-connected`; a connected network whose fetches fail still renders *Inconclusive*. D170's
  measured point — a dead bootstrap connects — is untouched.
- **D191 §4** and **D190 §4** each carry an `R98` bullet that this record answers; each takes a
  dated addendum.

### §2 R5 — The stale sentences are rewritten

- `verify_host.rs:447-455`, `backend.rs:530-532` and `:724-726`, and `commands.rs:945-947`
  (§1.6) state R1–R3's behaviour. P3's proposal for `verify_host.rs`, which the lane may
  tighten: *"A connection that was not made — [`UnreachableBackend`], to which every refused,
  failed or timed-out attempt degrades (D191) — is never fetched from: the section reports
  `not-connected` (R98) and the reason is handed back for a stderr note. A connected reader
  whose every fetch fails in the network class fails each fetch, and R11 reports the section
  *Inconclusive*. Either way the run exits with its evidence verdict's code."*
- `crates/antseal-net/src/error.rs:140-142` names what travels in `Network` by recorded design
  — the refusals antseal makes before a storage client starts (the storage gate, upstream's
  state directory, a bootstrap set no transport can dial) and upstream's own client-start
  failure — and limits *"Retryable"* to transport failures: a refusal recurs until its cause
  changes. The `#[error]` at `:143` is untouched.
- Docs: `docs/drills/clean-machine-verify.md:646-653` expects *inconclusive* **or** *not
  performed — no connection …*; `crates/antseal-cli/src/machine.rs`'s tier-C subsection
  (`:164-184`) gains one sentence, *`rows` is empty when `verdict` is `not-connected`*;
  optionally, `docs/threat-model.md:2352-2356`'s table gains a not-connected row.

### What must NOT be done

- **Do not add the new line's *"no connection to the Autonomi network was made"* clause to
  `single_sourced()`.** The CLI spells that clause in `degrade` (§1.5), so the scan would
  report the CLI's own prefix as a renderer copy. A needle, if one is wanted, is *"live check:
  not performed"*.
- **Do not reword `StorageError::Network`'s `Display`** (D147 §2 R11).
- **Do not move the exit code.** The run exits with its evidence verdict's code, connected or
  not (D69 §3 R6).

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half.** In-process, default build, no network, no binary: `degrade`
and `run_verify_live` are compiled in both builds, and K1 and K2 have pure producers
(`antseal_net::network::{storage_gate, upstream_state}`, which `backend.rs:2297-2330` already
uses).
- **K1** (the storage gate's verdict over the RFC 5737 address `192.0.2.10`), **K2**
  (`upstream_state`'s verdict with no variables) and **K5** (the bound's sentence), each as
  `run_verify_live(bundle, options, modes, CollectedInputs::none(), async {
  degrade::<MockBackend>("verify", Err(StorageError::Network { reason })) })`:
  - `section.verdict == LiveLayerVerdict::NotConnected`, `rows.is_empty()`,
    `counts.checked == 0`;
  - the rendered lines contain the new verdict line and contain neither *"transport
    failure"* nor *"fetch failed"*;
  - the JSON `live` member contains `"verdict":"not-connected"`;
  - the run carries the reason `no connection to the Autonomi network was made: {reason}`,
    and its `escape_for_terminal` rendering is exactly one line;
  - the run's exit code equals the offline run's;
  - the degraded backend saw zero seam calls (`calls() == 0`, §1.2). The backend is moved
    into `run_verify_live` inside the connection future, so how the test reads the count
    afterwards is the lane's choice; P3 left it open.
- **The control, keyed on the type and not on failures.** A *connected*
  `degrade::<MockBackend>("verify", Ok(mock))` with `arm_fault(Fault::DuringGetData)` (the
  pattern at `verify_command.rs:467-468`) never renders `not-connected`, and its failed row
  still says *"transport failure"*.
- **The moved pin** (§1.3). `verify_command.rs:765`'s connect-failed shape asserts
  `NotConnected`, no rows, zero counts, nothing reaching the network below, and the new line.
  On today's tree that assertion is red — it is the Accept's red baseline. Its
  every-fetch-fails shape stays *Inconclusive*: a second connected control.
- **Unchanged greens.** `verify_command.rs:464`
  (`a_live_check_with_no_reachable_network_is_inconclusive_and_moves_nothing`); the
  `ant-backend` `live_in_a_build_with_a_backend_verifies_first_and_never_moves_the_exit_code`
  (`:2193`; a dead loopback set connects, so it stays *inconclusive*); `e2e_restore.rs`'s
  dead-devnet control (`:1205-1235`); `backend.rs`'s D191 degrade tests (`:2297`, `:2414`);
  `r89_live_outcome_json` (no class added); `verdict_wording`'s snapshot, re-blessed with one
  line; the `antseal-core` wasm32 check.

**Red — each watched red by its message.**

| Plant | Must redden |
|---|---|
| P1 (the Accept's own): ignore `degraded()` and collect as today | the K rows (*"transport failure"*; `inconclusive` ≠ `not-connected`) and the moved pin |
| P2: key the branch on "every fetch failed" instead of `degraded()` | the connected control (it renders `not-connected`) |
| P3: drop the stderr note | the reason needle |
| P4: omit the new line from `verdict_wording.rs`'s section 9 | the snapshot or a presence check: the line is missing from the rendered set |
| P5: fetch anyway in the degraded branch | `calls() == 0` |

Venue: `cargo test -p antseal-cli --test <the new file>` and the named `verify_command`
tests; `cargo test -p antseal-core --test verdict_wording --lib verify::orchestration`;
`cargo check -p antseal-core --target wasm32-unknown-unknown`. The wording snapshot is product
copy under `scripts/check-copy-style.py`'s `COPY_SCAN` (`crates/antseal-core/tests/snapshots/`,
`check-copy-style.py:73-98`), so the re-bless is followed by that check. `verify_command.rs` also spawns
the binary (`spawn::antseal()` at `:1054` and `:2156`), so a whole-file run goes under a
private `CARGO_TARGET_DIR`. The close gate runs with `ANTSEAL_GATE_HEAVY=1
ANTSEAL_GATE_E2E=1` (the read-only storage backend and `commands.rs` move); the devnet E2E
re-proves the touched path (`e2e_restore.rs:1150-1235`: all-persisted, then the dead-bootstrap
*Inconclusive* control).

## 4. What this record does NOT decide

- **`restore` and `reveal` are untouched.** D170 §2 R2's per-fetch degrade exists so that D43
  §5's verified-cache fallback runs per unit; a `restore` whose connection was not made must
  still reach it. Only `verify --live`, which has no fallback, stops fetching.
- **The reason's text as a `--json` key.** Refused for now (§2 R3). Adding one later is
  additive under D65 §6 and would be argued as such.
- **A not-connected row in `docs/threat-model.md:2352-2356`.** Optional (§2 R5); the table
  stays true without it, because it describes a connected network.
- **A spawned K2 `verify --live` row through the `ant-backend` binary** (`S42`'s no-`HOME`
  recipe from `tests/upstream_state.rs`). Not required by the Accept; it would need the
  `ant-backend` binary under a private `CARGO_TARGET_DIR`, a cold build of about 100 minutes
  on this host by P3's estimate. Not ruled.
- **The spelling difference between the crates' variants** (antseal-net's `fetch-error`
  against core's `fetch-failed`) is not a casing question and is not this record's; D200
  records it as a residual.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-VOCAB2 (round 2 — after L-NET2's `backend.rs` edits for `S47` and after L-CFG2)

- `crates/antseal-core/src/verify/orchestration.rs` — `LiveLayerVerdict`, `LiveInputs`,
  `LiveSection::new` and the two exhaustive matches (§2 R2).
- `crates/antseal-core/src/verify/wording.rs` — the new line beside
  `live_inconclusive_line` (§2 R2).
- `crates/antseal-core/src/verify/orchestration/tests.rs` — the verdict table gains the
  not-connected case.
- `crates/antseal-core/tests/verdict_wording.rs` and
  `crates/antseal-core/tests/snapshots/verdict-wording.txt` — section 9 by hand, and the
  re-bless (§2 R2).
- `crates/antseal-cli/src/backend.rs` — **only** `UnreachableBackend` (`~:550-584`) and the
  docs at `~:530-532` and `~:724-726` (§2 R3, R5). Not `degrade`'s body.
- `crates/antseal-cli/src/verify_host.rs` — **only** `run_verify_live` and its doc
  (`~:418-489`) (§2 R1, R5).
- `crates/antseal-cli/src/verify_out.rs` — the reason on the run, if it rides there (§2 R3).
- `crates/antseal-cli/src/commands.rs` — **only** the stderr note after `run.render()` and the
  doc at `~:945-947` (§2 R3, R5).
- `crates/antseal-net/src/error.rs` — **only** the doc at `~:140-142` (§2 R5).
- A new test file, for example `crates/antseal-cli/tests/verify_live_not_connected.rs` (§3).
- `crates/antseal-cli/src/machine.rs` — **only** the tier-C subsection's doc (§2 R5).
- `docs/drills/clean-machine-verify.md` — **only** `~:646-653` (§2 R5).
- The close gate runs with `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`.

### Orchestrator — a scope grant, then `TODO.md`, `tasks/R.md`, `docs/decisions/README.md`

- **A grant this record needs before round 2.** `crates/antseal-cli/tests/verify_command.rs`
  is in no lane's write scope at dispatch, and §2 R1 moves it: the three connection futures at
  `:619-628`, `:670-679` and `:702-708` stop compiling under the narrowed bound, and the
  connect-failed shape of `:765-869` turns red under §2 R2 (§1.3). L-VOCAB2 needs those
  regions.
- The optional threat-model row (§2 R5, §4) is in no lane's scope either; L-LOC re-points
  citations only.
- The living docs' `verdict-wording.txt:` citations shift by one line after `:97`; L-VOCAB2
  greps them at the re-bless, and L-LOC re-points them in round 3.
- `R98` is ticked when the lane's greens and plants are in its report; the index row and the
  register row.

### RECORDS-C — dated addenda

D170 §2 R2; D191 §4's `R98` bullet; D190 §4's `R98` bullet (§2 R4).

## 6. As built — wave 39, lane L-VOCAB2 (recorded in place before this record was first committed)

This was the lane's round 2. Every verdict below was read from an exit file, per the lane's
report, and every red was judged by its message. `backend.rs` was held until L-NET2's hunks had
landed. The orchestrator granted the
`tests/verify_command.rs` regions (§5) and `verify_host.rs`'s module doc (L-CFG2's hand-off).
Plants ran in a shadow synced to the current tree, with a private target.

- **§2 R1 (`R98`).** When `backend.degraded()` is `Some`, `run_verify_live` fetches nothing
  (`crates/antseal-cli/src/verify_host.rs:540-551`). It verifies with `LiveInputs::not_connected()`
  and attaches the backend's reason to the run. Otherwise `collect_live` runs as before. The three
  bare-`SharedMock` futures in `tests/verify_command.rs` (`:626`, `:677`, `:707`) are wrapped in
  `degrade("verify", Ok(..))`.
  - **Deviation: the bound admits a borrow** (`verify_host.rs:516-527`):
    `R: StorageBackend, B: Borrow<ReadOnlyBackend<R>>, C: Future<Output = B>`.
    - The handler passes an owned backend, and a test passes a borrowed one, so that it can read
      `UnreachableBackend::calls()` after the run. §3 left "how the test reads the count" to the
      lane, and P5 below shows that this read is load-bearing.
    - The default build proves the owned shape through `verify_command.rs`'s three call sites.
    - The `ant-backend` arm (`crates/antseal-cli/src/commands.rs:1038-1050`) has the same shape,
      but no default build compiles it. The lane stopped its `ant-backend` check under host I/O
      pressure, so that arm was not compiled in the lane.
- **§2 R2.** `LiveLayerVerdict::NotConnected` is declared after `NothingChecked`
  (`crates/antseal-core/src/verify/orchestration.rs:759`). The enum's doc says that the fold
  never produces it.
  - `LiveSection::new` sets it from the inputs instead of folding (`:856-857`).
  - The two compile-forced arms are `verdict_line` (`:862`) and `live_verdict`'s filter
    (`NothingChecked | NotConnected => false`, `:922`).
  - `LiveInputs::not_connected()` (`:407`) sets a private flag, `connection_not_made` (`:376`).
    `Default`, `none()` and `from_rows()` leave it false.
  - The line is `LIVE_NOT_CONNECTED_LINE` (`crates/antseal-core/src/verify/wording.rs:737`), in
    the ruled words, untightened: *"live check: not performed — no connection to the Autonomi
    network was made, so nothing was fetched and nothing is established either way"*.
  - Section 9 of `tests/verdict_wording.rs` pushes the line by hand (`:281`).
    `verdict-wording.txt` was re-blessed: the diff is `97a98`, one line, 153 → 154 lines. Before
    the bless, the suite was red with *"9 passed; 2 failed"*: *"the snapshot is missing the live
    not-connected row: …"*, and *"the rendered wording set differs from the committed snapshot …
    The set is FROZEN (R18) …"*. The six living-doc citations into that file all point at `:74`
    or above, so none moves.
  - **Deviation: the private flag is named `connection_not_made`, not `not_connected`.** The
    constructor `LiveInputs::not_connected()` is then the only `not_connected`, and every doc link
    names it unambiguously.
  - **Deviation: "the verdict table gains the not-connected case" became a sibling test**,
    `a_host_that_made_no_connection_reports_not_connected_with_no_rows`
    (`orchestration/tests.rs:1069`). The table's tuples carry row outcomes, and "no connection" is
    an input state, not a row.
- **§2 R3.** The reason travels in three steps:
  - `UnreachableBackend::reason(&self) -> &str` (`crates/antseal-cli/src/backend.rs:585`) reads it
    without a seam call.
  - The run carries it in `VerifyRun::live_refusal` (`crates/antseal-cli/src/verify_out.rs:111`).
    `live_note()` (`:129-136`) returns `` note: `verify --live` checked nothing — {reason} ``,
    with the reason passed through `escape_for_terminal`. Neither `render()` nor `json()` includes
    it.
  - `commands.rs:1059-1061` prints it with `eprintln!`, in both modes.

  No JSON key was added.
  - **Deviation: `live_note()` builds the whole escaped line**, so an in-process test asserts the
    exact stderr text. Only reading the code, or a spawned `ant-backend` binary, witnesses the
    three-line print in `commands.rs`. The lane did not run that binary, and the Accept does not
    need it.
- **§2 R4.** The records half is RECORDS-C's. D170, D190 and D191 each carry a dated addendum.
- **§2 R5.** The stale sentences are rewritten:
  - `run_verify_live`'s doc, in the ruled text, tightened;
  - `UnreachableBackend`'s and `degrade`'s docs (`backend.rs:530-535`, `:735-740`);
  - `commands.rs`'s step 3 (`:943-948`).

  `StorageError::Network`'s doc (`crates/antseal-net/src/error.rs:146-153`) names the refusals
  that travel in that variant by recorded design. It ends *"Retryable only in the first sense: a
  refusal recurs until its cause changes."* The `#[error]` (`:154`) is untouched.
  `crates/antseal-cli/src/machine.rs:179-181` gains the ruled sentence. Step 10 of
  `docs/drills/clean-machine-verify.md` names both possible live lines and the stderr note
  (`:651`, `:658`).
  - **Left as ruled:** `commands.rs`'s step 4 (D199 §1.6 rules it true), and no `single_sourced()`
    needle, whose measured yield was 0. The optional `threat-model.md` row is in no lane's scope
    and was not added.
- **§3, the green tests.** A new file, `crates/antseal-cli/tests/verify_live_not_connected.rs`,
  holds three tests:
  - `a_client_that_never_connected_is_reported_not_connected_and_nothing_is_fetched` (`:141`)
    covers K1, K2 and K5, with the count of 3 asserted. Each row asserts:
    - `NotConnected`, no rows, zero counts and the new line;
    - neither *"transport failure"* nor *"fetch failed"*;
    - `UnreachableBackend::calls() == 0`, read through a borrowed backend;
    - that the reason appears in neither `render()` nor `json()`;
    - `"verdict":"not-connected"` and `"rows":[]`;
    - a one-line escaped note;
    - an exit code equal to the offline run's.
  - **Deviation: two extra pins.** The hostile-reason test (`:282`) feeds a reason with LF, a
    forged verdict line, U+202E and CR. The note must stay one escaped line, and the verdict
    document must contain none of it. The presence check
    `the_snapshot_covers_every_element_the_accept_row_names` now lists the new line
    (`verdict_wording.rs:607`). It reads the committed file, so a re-bless that drops the line
    reddens.
  - The connected control (`:333`) arms one transport fault per subject. It expects
    *Inconclusive*, every row `FetchFailed{Transport}`, and no not-connected line or note.
  - **The moved pin** is `verify_command.rs:771`. Its connect-failed shape now asserts
    `NotConnected`; its every-fetch-fails shape stays *Inconclusive*.
  - **Deviation: the moved pin was renamed**
    `live_over_an_unreachable_network_exits_with_the_evidence_verdict_and_says_whether_it_connected`,
    because one of its two shapes is no longer inconclusive. Only this record's §1.3 cites the old
    name.
- **Plants: five, every one red by message.**
  - **R98-P1, today's classification** (`degraded()` ignored). This is the Accept's red baseline.
    It reddened the K rows (*"K1, the storage gate: LiveCounts { … fetch_failed: 7, checked: 7 } —
    left: Inconclusive, right: NotConnected"*) and the moved pin (*"connect-failed: … left:
    Inconclusive, right: NotConnected"*).
  - **R98-P2** keys the branch on "every fetch failed". It reddened the connected control and the
    every-fetch-fails shape (*"left: NotConnected, right: Inconclusive"*).
  - **R98-P3** drops the reason: *"K1, the storage gate: a connection not made carries a stderr
    note"*.
  - **R98-P4** leaves the line out of section 9: *"the rendered wording set differs from the
    committed snapshot …"*.
  - **R98-P5** fetches anyway and discards the result: *"the degraded backend was fetched from —
    left: 7, right: 0"*. The verdict assertions above it passed; only the backend's own counter
    saw the fetch.
  - Restore: every file's sha256 equals its pre-plant value, and
    `git grep --untracked -n W39-PLANT` exits 1.
- **At the lane's close.**
  - Shadow, on the 17:00 sync: `verify_command` 27 passed (spawned tests included),
    `verify_live_not_connected` 3, `verify_live_manifest` 5, `restore_output` 16 (its three
    `.degraded()` callers), `antseal-cli --lib` 324, `antseal-core --lib` 1189, `verdict_wording`
    11, and `live_section_bridge` 7.
  - Shared tree, on the final bytes: `verify::orchestration` 21, `verdict_wording` 11,
    `verify_live_not_connected` 3, and the four in-process `verify_command` tests 4.
    `cargo check -p antseal-core --target wasm32-unknown-unknown` exited 0.
  - `clippy -- -D warnings` exited 0 for all three crates. The shared tree's `antseal-cli` clippy
    reused another lane's fresh units, so the lane re-ran it in the shadow, as a real check.
  - rustfmt, `check-copy-style`, `check-traceability` (both modes) and `check-personal-data`
    passed.
- **The tree, re-read for this section.** All fourteen round-2 files equal the lane's final hashes.
- **Left open.**
  - **The `ant-backend` arm** (`commands.rs:1038-1050`) and the spawned `verify --live` were not
    built in the lane. The close gate's forced heavy tier compiles that arm, and the devnet E2E
    re-proves the touched path (§3).
  - **`L-LOC` owns the citations.** It owns the lane's census of the lines its hunks moved, and
    `docs/threat-model.md:2066`'s `verify_command.rs:773`, which was off-meaning before this wave.
    `vault-theft.md`'s `backend.rs:699` citations are `L-DOCS`'s.
  - **No product row was minted from this round.**
  - **`R98`'s tick is the orchestrator's (§5).**

## Closing — this record is not consent

It changes code, tests, a frozen wording snapshot and documents in the tree. Nothing in it
authorises a push, a dispatch, a deploy or any other outward act. Its tests open no socket;
the close gate's devnet E2E runs on a local devnet that touches no external service.
