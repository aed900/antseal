# D147 — The stranded payment's sentence was already right and only its class was wrong; the row's second casualty cannot reach the site the row names; and the worst-classified money-moved error is one the row counts among the correctly-handled three

- **Status: RESOLVED. The lean's DIRECTION survives on measurement and is
  sharpened by it. Its numbering guidance and its second subject are both
  overturned, and a third subject the row places on the *correct* side of the
  match is measured to be worse than the one the row is about.** The lean was
  *"Give `StrandedPayment` its own `CliError` variant and its own class in an
  unused appended code outside the 44–49 reservation, and decide `NotFound` in
  the same act."*
  - **The variant, the class and the code survive — at `payment-stranded`,
    code 28, which is not an *appended* code.** The lean's word *appended*
    points past 43; measured, **D69 §1(a) already surveyed this table and
    recorded `28`, `29` as free**, inside the band it labels *"seal/payment/
    resume | 20–27 | in use (8 classes)"*. Two prior mintings settle the rule
    the lean leaves open: `restore-verification-failed` took **35** to sit
    *"beside the other restore classes (30, 31)"* rather than the 40s, and
    `reveal-inputs-unusable` took **36**, *"the first free code after
    restore's band"*. A class takes the first free code **in the band of the
    outcome it names**, not the first free integer above the maximum. For a
    stranded payment that is **28**.
  - **`NotFound` is REFUSED a class, and the row's premise for it is false as
    written.** The row says `NotFound` *"lands there too"* — in
    `storage_to_cli`'s catch-all. Measured, it cannot: `StorageError::NotFound`
    is produced **only by `get_data`** (three sites, all inside a `get_data`
    body), and **every `get_data` caller in `antseal-cli` converts the error to
    a `String` at the call site** through `restore::storage_detail` and wraps it
    in a domain error. The seal/resume pipeline — the only producer of
    `SealError::Storage`, and therefore the only path into `storage_to_cli` —
    **never calls `get_data`**. The variant the row nominates as the second
    casualty is unreachable at the site the row is about.
  - **The arm nobody listed, and the one that decides half this record:
    `ProofsExpired` — which the row counts among the three *matched* variants,
    i.e. on the correct side — is classified worse than `StrandedPayment` is.**
    It maps to `CliError::Usage` → class `usage` → **exit 2**. Measured
    rendering: `usage error: this seal's payment proofs have expired (the ~24 h
    node-side window has passed), so the storers reject them: completing it
    requires a new, separately consented payment — **the already-spent ANT is
    not recoverable**`. The one message in this product that contains the words
    *the already-spent ANT is not recoverable* exits with the code that means
    *you typed the command wrong* — and 2 is also clap's own parse-error code,
    so a wrapper cannot distinguish it from a malformed argv. D37 Decision 6
    demanded *"a distinct, consented error, never silent"* and its Residual
    risk 1 demanded the resume path treat it *"as the distinct stranded state
    **rather than a generic network error**"*. The type is distinct; the class
    is the most generic one in the table. It takes **29**,
    `payment-proofs-expired`.
  - **The row's message requirement is already satisfied by the shipped
    catch-all, and the brief's §2 restates it as if it were missing.** Measured,
    today's rendering is `network failure: payment stranded mid-sequence: 2
    sub-batch transaction(s) landed before the failure; the journaled partial
    receipt is authoritative — resume will not re-pay mapped quotes (…)`. It
    already carries `landed_tx_count`, already names resume, already states that
    mapped quotes are not re-paid. **Only the two-word prefix and the machine
    identity are wrong.** The ruling therefore forbids losing that sentence and
    treats the fix as an identity fix, not a copy fix.
  - **The catch-all is not the defect for four of its six members — and it is
    still replaced.** By their own doc comments `Quote` risks no money,
    `Payment` is defined as *"before any transaction landed"*, `Finalize` is
    *"always retryable with the same journaled receipt"*, and `Network` is
    transport by definition: **retry is the correct response to all four**, so
    23 is right for them. That correctness is contingent on today's variant set
    and nothing holds it. `StorageError` carries **no `#[non_exhaustive]`**, so
    an exhaustive match compiles across the crate boundary — proven here by
    building one, and by deleting one arm and reading `error[E0004]: …
    &StorageError::StrandedPayment { .. } not covered`.
- **Date: 2026-08-18**
- **Owning task: U81** (`tasks/U.md:1150`, `TODO.md:847`). Rulings touch U32
  (the exit-code freeze this must precede), and amend two of U81's five Accept
  rows. Verbatim amendments for the registrar are in §2 R13.
- Related: D69 (the exit-code survey that recorded 28/29 free, the 44–49
  reservation, and the band-placement precedent), D134 §2 R3 (append-only; *do
  not take 44–49*), D37 Decisions 3 and 6 (the mid-sequence split and the
  expired-proof stranded state), D36 (re-quote/re-consent at resume), D45 (there
  is no `resume` command — re-running `seal` **is** the resume), D65 tier B (the
  `--json` `error` object), D48 §6 (restore's severity fold, which owns the
  *other* place `NotFound` is flattened and which this record does not touch),
  Q77 (`tests/namespace_disjointness.rs`, the pinned class count this ruling
  moves).
- Method: read-only measurement plus three scratch binaries compiled against the
  workspace's built rlibs (`rustc -L dependency=target/debug/deps --extern …`),
  outside the repository tree. No file in the repository was written except this
  record. `scripts/local-gate.sh` and every `--self-test` mode were avoided:
  sibling planning lanes shared the working tree. Line numbers are snapshots of
  the tree at this record's date.

---

## 1. What was measured

### 1.1 All nine variants, driven — not read — through the public boundary

`storage_to_cli` is private, but the route into it is public: `impl
From<SealError> for CliError` (`crates/antseal-cli/src/pipeline/error.rs:287`)
and `CliError::class()` (`crates/antseal-cli/src/error.rs:849`). A scratch
binary built against the workspace rlibs constructs all nine variants and prints
where each one lands:

```
variants=9
             Quote -> class=network-failure        code=23
           Payment -> class=network-failure        code=23
   InsufficientAnt -> class=insufficient-ant-token code=20
   InsufficientGas -> class=insufficient-eth-gas   code=21
          Finalize -> class=network-failure        code=23
   StrandedPayment -> class=network-failure        code=23
     ProofsExpired -> class=usage                  code=2
          NotFound -> class=network-failure        code=23
           Network -> class=network-failure        code=23
--- ErrorClass::ALL len = 33 ---
assigned codes: [1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                 23, 24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 40, 41, 42, 43]
unassigned below 60: [5, 6, 7, 8, 9, 28, 29, 37, 38, 39, 44, 45, 46, 47, 48, 49,
                      50, 51, 52, 53, 54, 55, 56, 57, 58, 59]
REAL_EXIT=0
```

**Both of the row's counts are confirmed, and one of its implications is not.**
Six variants reach `network-failure`/23 (`Quote`, `Payment`, `Finalize`,
`StrandedPayment`, `NotFound`, `Network`) and three are matched explicitly — but
only **two** of the three matched variants receive a storage-specific class.
`ProofsExpired`, the third, receives `usage`/**2**. The row's framing (*"matches
only `InsufficientAnt`, `InsufficientGas` and `ProofsExpired`"*) is literally
true and reads as though all three are handled; they are not.

`storage_to_cli` verbatim, `crates/antseal-cli/src/pipeline/error.rs:304-327` —
the row's locators are exact, checked line by line:

```
304: fn storage_to_cli(err: StorageError) -> CliError {
305:     match err {
306:         StorageError::InsufficientAnt { … } => CliError::InsufficientAntToken { … },
313:         StorageError::InsufficientGas { … } => CliError::InsufficientEthGas { … },
320:         StorageError::ProofsExpired => CliError::Usage {
321:             message: SealError::ProofsExpired.to_string(),
322:         },
323:         other => CliError::NetworkFailure {
324:             detail: other.to_string(),
325:         },
327: }
```

Every other locator in the row and the brief was checked at its own line:
`crates/antseal-cli/src/error.rs:384` is `ErrorClass::NetworkFailure => 23`,
`:454` is `=> "network-failure"`, `crates/antseal-net/src/error.rs:91` is
`StrandedPayment {`, `:127` is `NotFound {`. **The row is accurate on all four.**

### 1.2 `StrandedPayment` is reachable in production — three sites, all behind `ant-backend`

Every construction site in the repository, classified:

| site | kind |
|---|---|
| `crates/antseal-net/src/ant_backend.rs:781` | **production** — RPC accepted the tx, landing unobserved |
| `crates/antseal-net/src/ant_backend.rs:822` | **production** — a `payForQuotes` sub-batch reverted on-chain |
| `crates/antseal-net/src/ant_backend.rs:1198` | **production** — `stranded_or_payment()`, the `landed > 0` arm |
| `crates/antseal-net/src/test_util/mock.rs:458`, `:524` | `Fault::AfterSubBatches(k)` / `Fault::AfterPayBeforeStore` |
| `crates/antseal-cli/src/pipeline/resume.rs:735` | inside `#[cfg(test)] mod tests` (opens at `:629`) |
| `crates/antseal-cli/tests/seal_matrix.rs:170` | the `CapturingBackend` double |
| `crates/antseal-net/tests/live_display_channel.rs:127` | test |

All three production sites sit in `ant_backend.rs`, compiled only under the
non-default `ant-backend` feature — which is what a **release binary** is built
with (`docs/user/funding-your-wallet.md:194-195`: *"Release binaries are built
with the backend"*). This is not the U67/U71/U75 shape: the error is
constructed, and by the code path a paying user runs.

**What no test does today is carry it to an exit code.** The two existing
assertions stop one layer short: `seal_matrix.rs:637` and `resume.rs:876` both
assert `SealError::Storage(StorageError::StrandedPayment { .. })` and neither
converts to `CliError`. That is precisely why exit 23 survived.

### 1.3 `NotFound` cannot reach `storage_to_cli` — the row's second casualty is at the wrong address

Producers of `StorageError::NotFound`, all three inside a `get_data` body:

- `crates/antseal-net/src/ant_backend.rs:970` (in `async fn get_data`, `:963`)
- `crates/antseal-net/src/test_util/mock.rs:629` (in `get_data`)
- `crates/antseal-net/src/backend.rs:294` (the trait-doc example impl)

Consumers of `get_data` in `antseal-cli/src`, all three converting to text at
the call site:

- `pipeline/restore.rs:875` → `storage_detail(&err)` → `FetchFailure::Unavailable { detail }`
- `pipeline/reveal.rs:827` → `storage_detail(&err)` → `RevealError::ManifestUnfetchable { detail }`
- `pipeline/reveal.rs:870` → `storage_detail(&err)` → `RevealError::Unfetchable { unit_id, detail }`

The only route into `storage_to_cli` is `SealError::Storage(#[from]
StorageError)` (`pipeline/error.rs:236`, `:287`), produced by the seal/resume
pipeline's `?` on `quote_batch`, `balances`, `pay` and `finalize_batch`. **The
seal/resume pipeline never calls `get_data`.** So no `NotFound` value can arrive
at the catch-all.

Two further facts that finish the disposition:

- Upstream's own not-found is deliberately **not** mapped to this variant:
  `ant_backend.rs:1295` maps `AntError::NotFound(detail)` to
  `StorageError::Network`, with a comment explaining that `chunk_get` signals
  absence through `Ok(None)`, so an `Error::NotFound` from any operation is *"a
  network-shaped surprise, not the typed NotFound"*.
- Where `NotFound` **is** flattened onto 23, it is by a *ruled* wildcard-free
  map elsewhere: `restore_out.rs:238` sends `FileStatus::FetchFailed` to
  `ErrorClass::NetworkFailure` under D48 §6's severity fold, and
  `restore_out.rs:229` states the map is wildcard-free on purpose. That is a
  restore-surface question with its own decision behind it. §5 records it as not
  covered.

### 1.4 The human sentence is already right; only the identity is wrong

A second scratch binary printed the full rendering and the `--json` error object
for the two money-moved errors:

```
[StrandedPayment] class=network-failure code=23
  network failure: payment stranded mid-sequence: 2 sub-batch transaction(s) landed before the failure; the journaled partial receipt is authoritative — resume will not re-pay mapped quotes (a payment sub-batch transaction reverted on-chain)
  json={"class":"network-failure","exit_code":23,"message":"network failure: payment stranded mid-sequence: 2 sub-batch transaction(s) landed …"}

[ProofsExpired] class=usage code=2
  usage error: this seal's payment proofs have expired (the ~24 h node-side window has passed), so the storers reject them: completing it requires a new, separately consented payment — the already-spent ANT is not recoverable
  json={"class":"usage","exit_code":2,"message":"usage error: this seal's payment proofs have expired …"}
REAL_EXIT=0
```

The catch-all's `detail: other.to_string()` (`:324`) forwards
`StorageError::StrandedPayment`'s own `Display`
(`crates/antseal-net/src/error.rs:86-90`), which already carries the count, the
recovery and the no-re-pay guarantee. **`CliError::NetworkFailure`'s
`#[error("network failure: {detail}")]` (`crates/antseal-cli/src/error.rs:643`)
contributes exactly one wrong clause: the two words in front.**

The consequence for the ruling is direct: the risk in this change is *losing* a
sentence that is already correct, not writing one that is missing. R2 pins the
three properties the new text must keep.

### 1.5 The 44–49 reservation is real, and D69 already recorded 28 and 29 free

D134 §2 R3's prose is a claim about `tests/exit_codes.rs`. Read at the file
(`crates/antseal-cli/tests/exit_codes.rs:135-160`), the claim is **true**:

```rust
assert!(
    !(44..=49).contains(&code),
    "{}: 44–49 stay reserved (D69 §3 R9)",
    class.name()
);
if (40..=43).contains(&code) {
    assert!(class.name().starts_with("verify-"), …);
}
```

D69 §1(a) is the survey this record inherits rather than repeats
(`docs/decisions/D69-verify-exit-code-mapping.md:71-83`):

| band | codes | status |
|---|---|---|
| general | `1`–`4` | in use |
| — | `5`–`9` | **free** |
| consent/vault | `10`–`19` | in use |
| **seal/payment/resume** | **`20`–`27`** | in use (8 classes) |
| — | **`28`, `29`** | **free** |
| restore/vault-file | `30`–`35` | in use |
| — | `36`–`39` | **free** |
| verdict | `40`–`49` | 40–43 minted, **44–49 RESERVED** |

§1.1's live probe reproduces it exactly: `28` and `29` are unassigned today.
D69's own governing precedent for *where* rather than *whether*, quoted at its
`:97`, is U2's sentence *"restore's verification class can live at 35 without
disturbing the 40–49 band"* — placement follows the outcome's band.

Name-space check, because a class name and an error code are two frozen
kebab namespaces this project keeps disjoint (`docs/testing/error-code-contract.md`
§2; `crates/antseal-cli/tests/namespace_disjointness.rs`): in
`testdata/error-codes/v1/CODES.txt` the substrings `payment`, `strand` and
`expired` occur **0, 0 and 0** times. No collision, and no new reservation is
needed either — §2 of the contract rules that the S domain *"would be a
namespace with no possible member"*, so a `payment-` code cannot be minted on
the other side. The contract's own principle (*"a reservation protecting nothing
should be retired deliberately"*) forbids minting one here.

### 1.6 The exhaustive match compiles across the crate boundary — and its fault was planted

`StorageError` carries no `#[non_exhaustive]` (`crates/antseal-net/src/error.rs:28-29`
is `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]` then `pub enum
StorageError {`; a sweep for `non_exhaustive` across `crates/` returns 41 hits
and none of them is this type). A scratch binary **outside** `antseal-net` with a
wildcard-free nine-arm match over it compiles and runs: `REAL_EXIT=0`, output
`proofs`.

Planted fault — one arm deleted, nothing else changed:

```
REAL_EXIT=1
error[E0004]: non-exhaustive patterns: `&StorageError::StrandedPayment { .. }` not covered
 --> …/exh_fault.rs:4:11
note: `StorageError` defined here
 --> /home/deb/Documents/code0/crates/antseal-net/src/error.rs:29:1
```

**Red by its message, naming the missing variant.** So the compile-time guard is
available here, and there is house precedent for exactly this at the same enum:
`crates/antseal-net/src/live.rs:164-177`'s `fetch_failure_class` is
wildcard-free with a doc comment reading *"a new `StorageError` variant fails to
compile here rather than falling into a catch-all — which is exactly how the
free-form channel this class replaces was opened, one layer up, by
`map_ant_error`'s `other =>` arm."* `storage_to_cli` is the last classification
site over this enum still written the old way.

The **shape R5 mandates** was compiled too, not just designed: a nine-arm match
in which the five transport members are written `e @ StorageError::Quote { .. }
=> e.to_string()` builds cleanly by value (`COMPILE_EXIT=0`) and renders
`quote collection failed: r` and `no chunk found at address aaaa…` — byte-equal
to what the catch-all's `other.to_string()` produces today. The obvious
alternative spelling, `StorageError::Quote { reason } => … detail: reason`,
compiles just as happily and **silently drops each variant's `#[error(...)]`
prefix** in four shipped messages; R5 forbids it and names the snapshot diff
that catches it.

### 1.7 Every instrument a new class moves, enumerated by reading each one

| instrument | what moves | why it cannot be skipped |
|---|---|---|
| `crates/antseal-cli/src/error.rs:13-49` module-doc table | +2 rows | the committed table; `tests/exit_codes.rs` compares against it |
| `ErrorClass` enum + `ALL` (`:327-361`) | +2 | `ALL.len()` is asserted equal to `TABLE.len()` |
| `exit_code()` (`:365-410`), `name()` (`:435-476`) | +2 arms each | wildcard-free already |
| `class_index()` (`crates/antseal-cli/src/error.rs`, test mod) | +2 arms | its own doc: *"adding an `ErrorClass` variant fails this match at compile time, forcing `ALL` …, the module-doc table, and `tests/exit_codes.rs::TABLE` to be updated in the same change"* |
| `CliError::class()` (`:849-891`) | +2 arms | wildcard-free |
| `crates/antseal-cli/tests/exit_codes.rs` `TABLE` | +2 rows | pins code and name literally |
| `crates/antseal-cli/tests/exit_codes.rs` `exemplars()` | +2 entries | drives the Display snapshot and the JSON-object test |
| `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` | +2 blocks, blessed | `ANTSEAL_BLESS=1`; the file is also in `check-copy-style.py`'s `COPY_SCAN` |
| `crates/antseal-cli/tests/namespace_disjointness.rs` `PINNED_CLASS_COUNT` | `33` → `35` | **the brief did not list this.** It is a second, independent statement of the class count whose own comment says a *"disjointness test over a shrunken set is a test that passes more easily"* |
| `docs/testing/error-code-contract.md:348-350` | +2 in the S-outcomes sentence | it names which S failures wear U's identity |
| `docs/user/funding-your-wallet.md` | +1 short section | its *"Nothing was spent"* bullet is true of 20/21 and a reader generalises it |

`codes_are_nonzero_distinct_and_avoid_reserved_ranges` needs **no** change: 28
and 29 are outside 40–43 and outside 44–49, so both assertions stay as written.

The exemplar list is **append-ordered, not code-ordered** — measured in the
committed snapshot, where `insufficient-*` (45, 47) precede
`vault-keyfile-missing` (49) and `reveal-inputs-unusable` (87) follows
`verify-bundle-rejected` (85). New exemplars therefore go at the **end** of the
`exemplars()` vector, so the blessed diff is two appended blocks and nothing
else moves.

### 1.8 The `--json` surface needs no envelope event, and carries the class for free

`CliError::error_object()` (`crates/antseal-cli/src/error.rs:906-912`) builds
`{class, exit_code, message}` from `self.class()`, and
`machine::error_envelope` embeds it verbatim (asserted at
`tests/exit_codes.rs:619-638`). D65 tier B (`crates/antseal-cli/src/machine.rs`,
the tier table) freezes the **keys** — *"no key is renamed, removed, retyped, or
moved … without an `ENVELOPE_VERSION` bump"* — and a new class is a new
**value** of an existing key. No `ENVELOPE_VERSION` bump, no
`json-envelopes.txt` row (that fixture is one per command, not one per class).
The §1.4 probe confirms the JSON object already carries whatever `class()`
returns.

### 1.9 There is no `resume` command, so *"point at resume"* cannot be executed literally

`rg -i resume crates/antseal-cli/src/cli.rs` returns **zero** hits, and the
frozen help snapshot contains the word `resume` **zero** times.
`crates/antseal-cli/src/seal_resume.rs:7-11` states the model: *"There is no
`--resume` flag and no interactive picker … Re-running the same command
resumes; that is the entire user model."*

The house copy idiom for this already exists and is committed:
`list-report.txt:12` prints `resume with: antseal seal big.bin --title '…'`, and
`cli-errors.display.txt:64` says *"re-run with exactly the original path list to
resume it … `antseal list` shows the incomplete seal and the exact command that
finishes it (D45)"*. R2's text follows that idiom rather than inventing a verb.

### 1.10 `SealError::ProofsExpired` is constructed nowhere, and a `# Errors` doc says otherwise

Every occurrence of `SealError::ProofsExpired` in `crates/antseal-cli/src`:
`pipeline/error.rs:207` (the definition), `:279` (a **pattern** in the `From`
arm), `:321` (`.to_string()` — borrowed purely for its text), `:378` (a test
exemplar), and `pipeline/resume.rs:136` (a doc comment). **Zero constructions.**

`resume.rs:136` reads *"[`SealError::ProofsExpired`] when re-payment is
refused"*. Measured at the field that carries that claim: a refusal at
re-payment returns `SealError::ConsentDeclined` (`pipeline/resume.rs:457`:
`ConsentDecision::Declined(reason) => return Err(SealError::ConsentDeclined(reason))`).
The sentence is false, and it is the U82 shape — a doc comment describing a
behaviour as fact.

The reachable path to exit 2 is `StorageError::ProofsExpired` from
`finalize_batch` (`ant_backend.rs:518`, `:1343` via `classify_put_error`), which
`resume.rs:274` intercepts **once** to re-quote and re-consent; a second
expiry after the re-payment propagates through `resume.rs:284`'s `?`, and the
fresh-seal path propagates directly. Narrow, and live in a release build.

---

## 2. THE RULING

### R1 — Mint two classes, in the seal/payment band, with these exact strings and numbers

| `ErrorClass` variant | class name | exit code |
|---|---|---|
| `ErrorClass::PaymentStranded` | `payment-stranded` | **28** |
| `ErrorClass::PaymentProofsExpired` | `payment-proofs-expired` | **29** |

Evidence they are unused: §1.1's live probe (`unassigned below 60` contains 28
and 29) and D69 §1(a)'s own survey, which recorded both free. Evidence the names
are free in the *other* frozen kebab namespace: `payment`, `strand` and
`expired` occur zero times in `testdata/error-codes/v1/CODES.txt` (§1.5). **No
assigned code is renumbered, reused or repurposed, and 44–49 is untouched** —
D134 §2 R3 satisfied.

### R2 — `CliError::PaymentStranded`, with this exact message

```rust
/// **D147**: a payment failed mid-sequence with money already moved. Never
/// the transient network class — a caller retrying this the way it retries a
/// peer timeout spends against a wallet that has already paid.
#[error(
    "payment stranded mid-sequence: {landed_tx_count} sub-batch transaction(s) landed \
     before the failure and the journaled partial receipt is authoritative — this is not \
     a transient network failure and money has already moved: re-run `antseal seal` with \
     the same files and the same seal-shaping flags to finish it, which re-pays no quote \
     the receipt already maps; `antseal list` prints the exact command ({detail})"
)]
PaymentStranded {
    /// Sub-batch txs that landed (and were journaled) before the failure.
    landed_tx_count: usize,
    /// The storage layer's own diagnostic rendering (already redacted at
    /// `ant_backend.rs`'s `redact_evm_error`).
    detail: String,
},
```

Three properties this text must keep, because §1.4 measured that the shipped
sentence already had all three and the risk in this change is losing them: it
carries **`landed_tx_count`**; it names the recovery **as it actually exists**
(re-running `seal` — §1.9: there is no `resume` command); and it states that
mapped quotes are **not re-paid**. It is single-line and placeholder-free
(`display_output_is_single_line_and_fully_rendered` asserts both). It carries no
tx hash, no quote hash and no key material — `landed_tx_count` is a count and
`detail` arrives pre-redacted (project rule 6).

The mapping arm:

```rust
StorageError::StrandedPayment { landed_tx_count, reason } =>
    CliError::PaymentStranded { landed_tx_count, detail: reason },
```

### R3 — `CliError::PaymentProofsExpired`, carrying `SealError::ProofsExpired`'s existing sentence unchanged

Move the string, do not rewrite it — it is already reviewed, already frozen in
the display snapshot, and its wording is not what is wrong:

```rust
/// **D147**: D37 Decision 6's expired-proof stranded state. Its own text says
/// "the already-spent ANT is not recoverable"; it exited 2 — clap's parse-error
/// code — until this class existed.
#[error(
    "this seal's payment proofs have expired (the ~24 h node-side window has passed), so \
     the storers reject them: completing it requires a new, separately consented payment — \
     the already-spent ANT is not recoverable"
)]
PaymentProofsExpired,
```

and the arm becomes `StorageError::ProofsExpired => CliError::PaymentProofsExpired`,
deleting the borrowed-`to_string()` hack at `pipeline/error.rs:321`.

### R4 — Delete `SealError::ProofsExpired` and repair the doc comment that describes it

Once R3 moves the string, the variant has no remaining job and **nothing
constructs it** (§1.10). The precedent is this crate's own, in a comment that
still stands at `crates/antseal-cli/src/error.rs:508-515` about the removed
`AnchorStageUnavailable`: *"Removed rather than left unconstructed: an error
nothing can produce is a claim about the product that no test can falsify."*

Before deleting, re-run the confirming sweep and require exactly the five hits
§1.10 lists:

```
rg -n 'SealError::ProofsExpired' crates/ --glob '!target'
```

If a sixth appears, keep the variant and record the site in `tasks/U.md`'s U81
Notes instead of deleting.

Then correct `crates/antseal-cli/src/pipeline/resume.rs:136`. Replace
*"[`SealError::ProofsExpired`] when re-payment is refused;"* with:

> `[`SealError::ConsentDeclined`] when the re-consented re-payment D36 requires
> is refused (`:457`); `[`SealError::Storage`]`(`StorageError::ProofsExpired`)
> only if the *replacement* proofs expire in turn — the first expiry is handled
> here (`:274`) and never reaches the caller;

### R5 — Make `storage_to_cli` wildcard-free, and give the five transport members an arm each

Replace `other =>` with five named arms. The catch-all goes; the *behaviour* for
these five does not change:

```rust
// D147: wildcard-free, the discipline `antseal_net::live::fetch_failure_class`
// already applies to this enum. `StorageError` is not `#[non_exhaustive]`, so a
// tenth variant is `error[E0004]` here rather than a silent exit 23 — which is
// how `StrandedPayment` came to share a code with a peer timeout.
//
// Every arm below binds the WHOLE error and renders it with `to_string()`,
// exactly as the catch-all did. Destructuring to `{ reason }` and forwarding
// `reason` alone would look equivalent and is not: it drops each variant's own
// `#[error(...)]` prefix, so "quote collection failed: <r>" would silently
// become "<r>" in four shipped messages.
err @ StorageError::Quote { .. } => CliError::NetworkFailure { detail: err.to_string() },
    // quoting precedes consent and payment: no money is at risk, retry is right.
err @ StorageError::Payment { .. } => CliError::NetworkFailure { detail: err.to_string() },
    // by its own definition, "before any transaction landed" — nothing moved.
err @ StorageError::Finalize { .. } => CliError::NetworkFailure { detail: err.to_string() },
    // finalize issues no payment and is idempotent with the journaled receipt.
err @ StorageError::Network { .. } => CliError::NetworkFailure { detail: err.to_string() },
    // transport by definition; this is the class 23 is named for.
err @ StorageError::NotFound { .. } => CliError::NetworkFailure { detail: err.to_string() },
    // D147 §1.3: unreachable from this pipeline — `NotFound` is produced only
    // by `get_data`, which the seal/resume pipeline never calls, and whose three
    // callers stringify at the call site. Written out rather than left to a
    // wildcard so the day someone wires a fetch into this pipeline is a
    // deliberate review, not a silent inheritance. Rendered through
    // `to_string()` like the rest, so the address text has exactly one spelling.
```

**Every one of these five arms must render byte-identically to today.** The
check is the blessed snapshot: after `ANTSEAL_BLESS=1`, `git diff` on
`crates/antseal-cli/tests/snapshots/cli-errors.display.txt` must show **two
appended blocks and no modified line**. A modified `[network-failure]` block
means an arm dropped a prefix.

### R6 — Every catch-all variant's disposition, recorded so the sweep is not re-derived

| variant | ruling | reason |
|---|---|---|
| `Quote` | stays `network-failure` / 23 | *"no money at risk: quoting precedes consent and payment"* (its own doc, `net/error.rs:30-31`) |
| `Payment` | stays `network-failure` / 23 | *"failed **before any transaction landed** (no money moved)"* — retry is the correct response, and this is the half of D37's split that 23 was always right for |
| `Finalize` | stays `network-failure` / 23 | *"idempotent and issues no payment, so this error is always retryable with the same journaled receipt"* |
| `Network` | stays `network-failure` / 23 | the definitional member of the class |
| `NotFound` | **refused a class**; explicit arm at 23 | unreachable from this pipeline (§1.3). Its doc's *"distinct from transport failure"* is a statement about the **storage taxonomy**, which is true and unchanged; it is not a claim about this mapping |
| `StrandedPayment` | **`payment-stranded` / 28** | money moved |
| `ProofsExpired` | **`payment-proofs-expired` / 29** | money moved; D37 Decision 6 required *"a distinct, consented error"* and Residual risk 1 required it *"rather than a generic network error"* |
| `InsufficientAnt` / `InsufficientGas` | unchanged, 20 / 21 | already distinct by spec |

### R7 — The test to add, with its planted fault and the message that fault must print

Add to `crates/antseal-cli/tests/seal_matrix.rs`, beside
`a_kill_between_sub_batch_txs_pays_each_sub_batch_exactly_once` (`:618`), which
already builds every fixture this needs:

```rust
/// D147: a stranded payment must never wear the transient network class. The
/// existing rows stop at `SealError`; this one carries it to the exit code,
/// which is where a retry loop reads it.
#[test]
fn a_stranded_payment_exits_with_its_own_class_and_never_the_network_code() {
    // …the CapturingBackend::crashing_after fixture of `:618`…
    let err = /* the SealError from the killed resume */;
    let cli: CliError = err.into();
    assert_eq!(
        cli.class().name(),
        "payment-stranded",
        "a stranded payment must not wear the transient network class: money has \
         moved, and a caller retrying exit 23 the way it retries a peer timeout \
         spends against a wallet that has already paid"
    );
    assert_eq!(cli.exit_code(), 28);
    assert_ne!(cli.exit_code(), 23, "23 is the retry-me code");
    let msg = cli.to_string();
    assert!(msg.contains(" 1 sub-batch transaction(s) landed"), "{msg}");
    assert!(msg.contains("antseal seal"), "{msg}");
    assert!(msg.contains("re-pays no quote the receipt already maps"), "{msg}");
    assert!(!msg.starts_with("network failure:"), "{msg}");
}
```

Add the sibling for `payment-proofs-expired` over a two-line `StorageBackend`
double whose `finalize_batch` returns `StorageError::ProofsExpired` — `MockBackend`
has **no** fault for it (its `Fault` enum is `AfterQuote`, `AfterPayBeforeStore`,
`AfterSubBatches(k)`, `AfterStoringK(k)`, `DuringGetData`, `NetworkOn(Method)`),
so the hand-rolled double is the only route and it is the idiom `resume.rs`'s
`CrashesBetweenSubBatches` already uses. Assert class `payment-proofs-expired`,
code 29, and `assert_ne!(cli.exit_code(), 2)` with the message *"2 is clap's own
parse-error code: a wrapper cannot tell this from a typo"*.

**Planted fault 1 (the substantive one).** Restore `storage_to_cli`'s catch-all
by deleting the `StrandedPayment` arm and re-adding `other => CliError::NetworkFailure { detail: other.to_string() }`.
Required red, by message:

```
assertion `left == right` failed: a stranded payment must not wear the
transient network class: money has moved, and a caller retrying exit 23 the way
it retries a peer timeout spends against a wallet that has already paid
  left: "network-failure"
 right: "payment-stranded"
```

Record `REAL_EXIT=${PIPESTATUS[0]}` to a file and read it back — a compile
failure also exits nonzero, and this fault must fail as an **assertion**, not as
a build error.

**Planted fault 2 (the structural one).** Add a tenth variant to
`StorageError` on a scratch copy. Required red, at compile time, before any test
runs:

```
error[E0004]: non-exhaustive patterns: `StorageError::<NewVariant>` not covered
```

measured in §1.6 in exactly this form. Revert the scratch variant; it is a proof,
not a change.

### R8 — Every documentation and instrument edit site

1. `crates/antseal-cli/src/error.rs` — the module-doc table: two rows after `27`,
   and the reader-facing note that `28`/`29` are the money-moved pair, minted
   from the seal/payment band D69 recorded free rather than appended past 43.
2. `crates/antseal-cli/src/error.rs` — `ErrorClass` (+2), `ALL` (+2),
   `exit_code()` (+2), `name()` (+2), `class()` (+2), `class_index()` (+2).
3. `crates/antseal-cli/src/pipeline/error.rs` — `storage_to_cli`'s doc comment at
   `:300-303` currently says only *"The two shortfalls stay distinct all the way
   to the exit code"*; it must state the four-way distinction (two shortfalls,
   two money-moved classes) and name D147.
4. `crates/antseal-cli/tests/exit_codes.rs` — `TABLE` (+2 rows), `exemplars()`
   (+2 entries, **appended at the end**, §1.7).
5. `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` — re-blessed with
   `ANTSEAL_BLESS=1`. The diff must be **two appended blocks and nothing else**.
6. `crates/antseal-cli/tests/namespace_disjointness.rs` — `PINNED_CLASS_COUNT`
   `33` → `35`, with a dated comment in the file's existing idiom (*"33 → 35 at
   U81 (2026-08-…): D147 minted `payment-stranded` (28) and
   `payment-proofs-expired` (29) … re-measured at the new size: still empty"*).
7. `docs/testing/error-code-contract.md:348-350` — the sentence *"`network-failure`
   (23), `insufficient-ant-token` (20) and `insufficient-eth-gas` (21) are S
   outcomes wearing U's identity"* gains `payment-stranded` (28) and
   `payment-proofs-expired` (29).
8. `docs/user/funding-your-wallet.md` — a short section after *"The two funding
   failures, told apart"*. Its third bullet (`:187`), *"**Nothing was spent.** … Re-running
   after you fund the wallet is safe and costs nothing extra"*, is true of 20 and
   21 and a reader generalises it to every payment error. State that 28 and 29 are
   the two codes that mean the opposite, that 28's recovery is re-running `antseal
   seal` with the same files and flags (`antseal list` prints the command), and
   that 29 costs a second payment.
9. `tasks/U.md` §U81 and `TODO.md:847` — the registrar's, per R13.

### R9 — Gates the implementer must run, and the one that is not optional

- `cargo test -p antseal-cli` (the class table, the snapshot, the two new rows).
- `cargo test -p antseal-cli --test namespace_disjointness` — this is the one a
  reader is most likely to skip, because nothing in the row or the brief names
  it, and it fails on the pinned count with a message about a *shrunken set*.
- `python3 scripts/check-copy-style.py` (flagless — **not** `--self-test`, which
  stages a full tree copy): `crates/antseal-cli/tests/snapshots/` is a
  `COPY_SCAN` directory entry, so both new messages are scanned as product copy
  the moment they are blessed.
- `python3 scripts/check-traceability.py` (flagless — that **is** its check).

### R10 — Ordering

This lands **before U32**. The whole reason is measured, not asserted: after the
freeze, moving `ProofsExpired` off code 2 is a break, and 2 is the only code in
the table that is also clap's parse-error code, so it is the one an error can
hide in permanently.

### R11 — What must NOT be done

- **Do not renumber, reuse or repurpose any assigned code**, and do not take
  44–49 (D134 §2 R3; the assertion at `exit_codes.rs:151-155` reddens).
- **Do not touch `restore_out.rs:238`.** Flattening restore's per-file
  `FetchFailed` onto 23 is D48 §6's ruled severity fold over a wildcard-free
  map, and re-opening it is a restore-surface event with its own record.
- **Do not bump `ENVELOPE_VERSION`.** A new class is a new *value* of an
  existing tier-B key (§1.8).
- **Do not reword `StorageError`'s own `Display` strings.** The storage taxonomy
  is correct; only the CLI mapping was wrong.

### R12 — A residual this record deliberately leaves open, named so it is not lost

`docs/testing/error-code-contract.md`'s last dated census says the universe *"stays
246"*, while `grep -vcE '^\s*(#|$)' testdata/error-codes/v1/CODES.txt` returns
**248** today. This record did **not** determine whether the two extra lines are
codes or file structure, and it is not U81's subject — the additions-only
mechanism at `crates/antseal-core/src/error_universe.rs` is what enforces the
contract, and a census sentence is prose. Recorded here so the next reader of
that file measures rather than assumes.

### R13 — `tasks/U.md`'s U81 Accept rows: three survive, two are amended (verbatim, for the registrar)

Accept rows 1, 3 and 5 survive as written. Rows 2 and 4 are replaced:

> - The new codes are appended, never reused, and are outside the 44–49
>   reservation — **28 `payment-stranded` and 29 `payment-proofs-expired`, the
>   first two free codes of the seal/payment/resume band D69 §1(a) surveyed and
>   recorded free, not codes appended past 43**;
>   `tests/exit_codes.rs`, `docs/testing/error-code-contract.md` **and
>   `tests/namespace_disjointness.rs`'s `PINNED_CLASS_COUNT` (33 → 35)** all
>   carry them.

> - `NotFound`'s disposition is recorded either way, so the next reader does not
>   re-derive the same catch-all sweep — **and D147 §1.3 records it as
>   *unreachable at this site*, not as a second misclassification: `NotFound` is
>   produced only by `get_data`, whose three CLI callers stringify at the call
>   site, and the seal/resume pipeline that feeds `storage_to_cli` never calls
>   `get_data`. Every one of the other five catch-all members is ruled in D147
>   §2 R6 as well, and `ProofsExpired` — which this row counts among the three
>   correctly-matched variants — is ruled a second money-moved class because it
>   exits 2.**

The row's Notes should also gain the correction its own premise needs:

> **Correction, D147:** the row's `Do` says *"The message must carry
> `landed_tx_count` and point at resume"*. Measured, the shipped catch-all
> already does both, because `detail: other.to_string()` forwards
> `StorageError::StrandedPayment`'s own `Display`; the only wrong clause in the
> rendered line is the `network failure: ` prefix and the machine identity
> behind it. And *"point at resume"* cannot be executed as written — there is no
> `resume` command and no `--resume` flag (`seal_resume.rs:7-11`); re-running
> `seal` **is** the resume.

---

## 3. The arms refused, and why each lost

### 3.1 *"Append past 43 — take 50, or the next free integer"* (the lean's own wording)

Refused. The lean says *"an unused appended code outside the 44–49
reservation"*, which reads as *above the maximum*. Two prior mintings decided
this question the other way and left their reasoning in the source:
`RestoreVerificationFailed` took **35** because *"it is a restore outcome rather
than a bundle verdict, so it sits beside the other restore classes (30, 31)"*,
and `RevealInputsUnusable` took **36**, *"the first free code after restore's
band"*. D69 §1(a) then wrote the bands down explicitly and marked 28 and 29
free. Taking 50 would leave the two most payment-shaped outcomes in the product
sitting eight codes away from `insufficient-ant-token` and
`insufficient-eth-gas`, in a stretch of table with no other member — a table
that is about to be frozen for the life of v1.

### 3.2 *"Reuse `resume-safety-abort` (24), or `anchor-gate-abort` (22)"*

Refused on D134 §2 R3's *"no assigned code is … repurposed"*, and on meaning: 24
is *"never re-encrypts, this seal is abandoned"* — the opposite outcome, since a
stranded payment is precisely the case that **is** resumable and whose partial
receipt is authoritative.

### 3.3 *"Give `NotFound` a class in the same act"* (the lean's second half)

Refused on reachability (§1.3), which is the check this project asks for before
ruling on how an error is classified. Minting a class no code path can produce
is the `AnchorStageUnavailable` failure the crate already removed once, with the
reason written at `error.rs:508-515`. The `NotFound` question that **is** real
lives in restore/reveal, behind D48 §6, and §5 hands it on rather than deciding
it here.

### 3.4 *"Keep the catch-all; a wildcard is fine when the default is the safe class"*

Refused, and this is the arm the brief flagged as possibly decisive. It is the
strongest losing case, so it is stated in full: four of the six catch-all
members are genuinely retryable transport-class outcomes (§1's table), the
default is therefore *right* for the majority, and an exhaustive match is churn
that buys nothing today.

It loses on one measurement. That correctness is a property of **today's**
variant set, held by nothing. `StorageError` gained `StrandedPayment` and
`ProofsExpired` as D37's two new slots, and both inherited 23 and 2 silently —
this row exists because that happened. §1.6 proves the guard is available
(cross-crate exhaustive match compiles; a dropped arm is `E0004` naming the
variant), and `antseal-net`'s own `fetch_failure_class` already applies it to
this exact enum, with a doc comment naming the catch-all as *"exactly how the
free-form channel this class replaces was opened"*. The next variant should cost
a compile error and one decision, not a second U81.

### 3.5 *"Rule only `StrandedPayment`; `ProofsExpired` is a different row"*

Refused, though it is the arm with the best scope argument. Three things beat
it: D37 Decision 6 already demanded *"a distinct, consented error, never
silent"* and *"rather than a generic network error"*, and `usage` is the most
generic class in the table; the window closes at U32, after which 2 → 29 is a
break; and U81's own Accept row 4 exists to stop the next reader re-deriving
this sweep, which ruling one of the two money-moved errors would guarantee.

### 3.6 *"Rewrite the stranded message from scratch"*

Refused. §1.4 measured that the shipped sentence already carries all three
properties the row demands. The change is an identity fix; R2 keeps the
substance and the snapshot diff stays reviewable.

---

## 4. Corrections this record makes

1. **To the brief.** Its §2 requires *"the exact message text (it must carry
   `landed_tx_count` and name the recovery — resume — and state that mapped
   quotes are not re-paid)"* as though none of that is present. All three are
   present today (§1.4). And *"name the recovery — resume"* cannot be executed
   literally: there is no `resume` command (§1.9).
2. **To the brief.** Its edit-site list names `docs/testing/error-code-contract.md`
   and *"any user-facing doc that lists codes"*, and misses
   `crates/antseal-cli/tests/namespace_disjointness.rs`'s `PINNED_CLASS_COUNT`,
   which is a hard-pinned second statement of the class count and reddens on a
   new class.
3. **To the row (`tasks/U.md:1157`, `TODO.md:847`).** *"`NotFound` … lands there
   too"* is false: it cannot reach `storage_to_cli` (§1.3). The row's own
   *"correction to the brief"* — that `StrandedPayment` is not the sole
   casualty — is right in spirit and wrong in its example; the second casualty
   is `ProofsExpired`, which the row places on the correct side.
4. **To the row.** Its counts are **confirmed**: six of nine in the catch-all,
   three matched. What the count hides is that only two of the three matched
   variants receive a storage-specific class.
5. **To a shipped source.** `crates/antseal-cli/src/pipeline/resume.rs:136`
   claims `SealError::ProofsExpired` is returned *"when re-payment is refused"*.
   Refusal returns `SealError::ConsentDeclined` (`:457`), and
   `SealError::ProofsExpired` is constructed nowhere at all (§1.10). R4 fixes
   both halves.
6. **To this record's own scope, stated rather than hidden.** The claim in §1.2
   that the release binary carries `ant-backend` is taken from
   `docs/user/funding-your-wallet.md:194-195` and `Cargo.toml`'s feature
   comments, not from a release build performed here; no release artefact was
   built or inspected.

---

## 5. What this record does NOT cover

- **It did not run the test suite.** No `cargo test`, no `cargo clippy`, no
  `cargo fmt`, no gate. Sibling planning lanes shared the working tree and every
  `--self-test` mode stages a full tree copy. Everything in §1 was measured by
  reading, by `rg`, and by three scratch binaries compiled outside the
  repository against the already-built rlibs in `target/debug/deps`. The two
  planted faults in R7 are **specified, not executed** — the implementer owes
  both, and owes reading `REAL_EXIT` back out of a file for each.
- **It did not exercise a live or devnet payment.** The stranded state was
  reproduced only through the type system and the existing doubles; no
  `ant-backend` build was compiled and no devnet was started.
- **It does not touch restore's or reveal's fetch-failure classification.**
  `restore_out.rs:238` (`FetchFailed` → `network-failure`) and
  `reveal.rs`'s `Unfetchable`/`ManifestUnfetchable` are where a `NotFound`
  genuinely *is* flattened onto 23. That is D48 §6's ruled severity fold and
  D69 §5's reveal band; changing it is a restore/reveal surface event and needs
  its own row.
- **It does not rule the six remaining free low codes** (5–9, 37–39) or reserve
  anything. Nothing here forecloses a later band decision.
- **It does not settle the `--json` `result` interior** for any command, or any
  tier-C question; only the tier-B `error` object is in scope, and it needs no
  change (§1.8).
- **It does not audit `StorageError`'s taxonomy.** Whether nine variants are the
  right nine, and whether `map_ant_error`'s `other =>` arm
  (`ant_backend.rs:1318`) should itself be wildcard-free over the upstream enum,
  are S-domain questions this record deliberately leaves alone.
- **It does not resolve the 246-vs-248 census reading** in
  `docs/testing/error-code-contract.md` (R12). It records the measurement and
  the command, and rules nothing.
- **It does not amend `TODO.md`, `tasks/U.md` or `docs/decisions/README.md`.**
  R13 supplies the verbatim text; the wave registrar applies it.
