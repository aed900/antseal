# D206 — `WalletOpsError::KeyGenerationFailed` is **the machine's fault**: `init` maps it with `EntropySource` to D201's random-source variant (*"the wallet key"* / *"no vault was created"*), so its message makes one claim and no longer calls itself a bug in antseal, and D201's *"unavailable"* is read as *"cannot supply usable randomness"*

- **Status: RESOLVED. H7 fell (b): its direction survived, and its premise fell on D201's own
  words.**
  - **H7** — *"KeyGenerationFailed is a random-source failure: route it through D201's
    RandomSourceUnavailable (class internal, exit 1, machine-blaming words, no "bug in
    antseal")."*
  - **What survives: the direction, whole.** At any tested build the machine is the only cause
    (§1.2, §1.3). The ruled message is class `internal`, exit 1, blames the machine, and does not
    say that antseal has a bug (§2 R1).
  - **The premise falls: *"KeyGenerationFailed is an unavailable source"*.** The source answered
    `Ok` 64 times (§1.1), and D201 §4 says of this very variant *"It names the entropy source but
    is not an unavailable one; §2 R2 maps only `EntropySource`"* (D201:327-329). Routing it
    through D201's variant therefore needs a recorded reading of *"unavailable"* (§2 R2), which
    overturns that sentence and widens §2 R2's *"only"* for this one site. D201 takes a dated
    addendum.
  - **Found with it: the remainder arm is feature-gated.** Without
    `#[cfg(feature = "ant-backend")]` the default build fails `clippy -D warnings`, and without
    the arm the `ant-backend` build is not exhaustive (§1.6, executed on a stand-alone probe).
    Gated, it compiles only under `ant-backend`, in a file the gate's heavy trigger does not list
    (§1.7, §4).
- **Date: 2026-10-20**
- Owner row: **`U106`** (§2 R1–R5). This record mints no row.
- Related:
  - **D201** §1.4 (D201:144-146), §2 R2 (D201:207-232) and §4 (D201:327-329); takes a dated
    addendum;
  - **`U104`** (D201's `CliError::RandomSourceUnavailable`, which this record reuses);
  - **D44** (the one acceptance gate a generated key and an imported key both pass,
    `crates/antseal-net/src/wallet.rs:120`);
  - **D170** §2 R11 (a CLI source carrying `cfg(feature = "ant-backend")` belongs on the heavy
    trigger list: the `Q112` class).

## 0. What was measured against

`HEAD` `6e1cab3` (local `main`; `origin/main` is `ab640ae`, one records commit behind). The tree
was clean when planning began, 2026-10-20.

Planning lane P2 (wave 40) worked read-only on the repository. It ran
`cargo test --offline -p antseal-cli --lib -- init::tests` in the shared target (exit 0,
6 passed, no rebuild), compiled a stand-alone probe with rustc 1.92.0 outside the repository
(its Log 7), and computed the probabilities in python3 with exact integers (its Log 4).

Before this record was written, the records lane re-read the load-bearing lines through
`git show 6e1cab3:<path>`, because round-1 lanes were editing the shared tree, `init.rs` among
them, and recomputed the probabilities, which agree to the printed digits. These figures did not
hold as P2 or the rulings gave them, and are given below as measured:
- the probability slip is `crates/antseal-net/src/wallet.rs:70-71` (P2 and the rulings:
  `:69-70`);
- `wallet_generation_error` is `crates/antseal-cli/src/init.rs:677-687` (P2: `:677-689`), and
  the built Display's text is `crates/antseal-cli/src/error.rs:1090-1092`, inside the attribute
  at `:1089-1093` (P2: `:1088-1092`);
- the shared wording *"random source is unavailable"* is on 8 lines in 8 files under `crates/`
  (seven sources and the snapshot), 9 lines in 9 files with D201's `:392`, and 11 lines in 10
  files with `TODO.md`'s two (`git grep -n 'random source is unavailable' 6e1cab3`). P2 counted
  *"9 pins in 8 files"*.

## 1. What was measured

### 1.1 One producer, and what the variant means

- `crates/antseal-net/src/wallet.rs:111-128`, `WalletKey::generate()`: a loop of
  `GENERATE_ATTEMPTS` draws (`:74`, `const GENERATE_ATTEMPTS: u32 = 64;`). Each draw is
  `getrandom::fill(&mut raw)`, and an `Err` returns `WalletOpsError::EntropySource` (`:114-116`).
  Each value then meets `parse_scalar` (`:121`; `:311-320`, `k256::SecretKey::from_slice`, which
  rejects zero and anything at or above the group order *n*). After 64 rejected draws, `:127`
  returns `Err(WalletOpsError::KeyGenerationFailed)`.
- **So the variant means one thing: the OS source answered `Ok` 64 times, and every value was
  zero or at least *n*.** Its own doc says so (`:394-395`, *"statistically impossible with a
  working entropy source"*), as does `generate`'s (`:107-110`, *"it means the entropy source is
  returning garbage"*).

### 1.2 How improbable it is from a working source

- Values a draw rejects: (2^256 − *n*) + 1 = `0x14551231950b75fc4402da1732fc9bec0`, a 129-bit
  number. log2 P(one draw) = −127.654; log10 P(64 in a row) = −2459.4 (python3, exact integers;
  P2 Log 4, recomputed by this records lane).
- Only a source that reports success while stuck — on all-zero or all-`0xFF` bytes, say — can
  produce the variant. The converse does not hold: a source stuck on most other constants passes
  the gate and yields a valid, predictable key. That is context, and no row: an operating
  system's random source is not antseal's to test (D201 §1.4).
- `wallet.rs:70-71` says a draw is rejected with *"probability < 2⁻¹²⁸ per draw"*. That is false:
  the probability is above 2^−128 and below 2^−127.

### 1.3 The "bug" reading is false at any tested build

The scalar gate is the one a working source's draws pass in every test that calls `generate()`:
`wallet.rs:557-558` in the default lane, `crates/antseal-net/src/evm.rs:361` and `:391` under
`ant-backend` (`crates/antseal-net/src/lib.rs:95-96` gates the module), and
`crates/antseal-net/tests/devnet_backend.rs:599`, `:648` and `:1410` against a devnet. A gate that
rejected valid scalars would turn them red. So at any tested build, the reading that calls the
variant a bug in antseal is the false one.

### 1.4 One consumer, and the message it renders today

- **The only production call.** `crates/antseal-cli/src/init.rs:539`,
  `WalletSource::Generate => WalletKey::generate().map_err(wallet_generation_error)?,`
  (`git grep -n 'WalletKey::generate()' 6e1cab3` finds no other outside tests). No export,
  wallet-record or payment path reaches the variant.
- **The gated variants never come from `generate()`.** Under `ant-backend` the enum gains
  `Config` and `KeyRejectedByStack` (`wallet.rs:401-409`); both come only from `evm_wallet`
  (`evm.rs:149-154`). So `init`'s remainder arm receives exactly `KeyGenerationFailed`.
- **Today's mapping** (`init.rs:677-687`): `EntropySource => CliError::RandomSourceUnavailable {
  what: "the wallet key", consequence: "no vault was created" }` and `other =>
  CliError::Internal { detail: other.to_string() }`.
- **What a user reads for `KeyGenerationFailed`**, composed from `wallet.rs:396-399` and
  `crates/antseal-cli/src/error.rs:556`: *"internal error: wallet key generation failed
  repeatedly; the system entropy source appears to be returning invalid data (this is a bug in
  antseal — please report it)"*. One message, two claims about whose fault it is.
- **It is pinned green.** `init.rs:913-920` asserts that the message
  `.ends_with("(this is a bug in antseal — please report it)")`; P2 ran
  `cargo test --offline -p antseal-cli --lib -- init::tests`: exit 0, 6 passed. The doc comments
  at `init.rs:676` and `:893` say the variant's mapping is one *"which D201 §4 leaves
  undecided"*.
- **Nothing pins the wallet's own text.** `git grep -n -E 'returning invalid data|failed
  repeatedly|entropy source appears' 6e1cab3` finds `wallet.rs:397-398`, `TODO.md:1101`,
  `tasks/U.md:1532` and D201:327-328 only.

### 1.5 D201's own words

- **§1.4** (D201:144-146): *"An operating system that cannot supply randomness is a fault of the
  machine; no change to antseal cures it, and a report filed on that advice is noise."*
- **§2 R2** (D201:213): *"Every clause must be true **by measurement** at each site that uses
  it."* And (D201:216-217): *"the wallet key (`init.rs`, mapping **only**
  `WalletOpsError::EntropySource`; the other variants keep today's mapping)"*.
- **§4** (D201:327-329): *"It names the entropy source but is not an unavailable one; §2 R2 maps
  only `EntropySource`."*
- **The built variant** (`error.rs:1090-1092`): *"the operating system's random source is
  unavailable, so {what} could not be generated: {consequence}. This is a fault of this machine,
  not a bug in antseal, and antseal has no other source of randomness to fall back on"*. It
  shares `Internal`'s arm in `class()` (`error.rs:1108`), so its class is `internal`, exit 1.

### 1.6 The remainder arm must be feature-gated (P2 Log 7, executed)

- `WalletOpsError` is not `#[non_exhaustive]` (`wallet.rs:389-390`), and it gains its two other
  variants only under `ant-backend` (`wallet.rs:401-409`; `crates/antseal-cli/Cargo.toml:50`,
  `ant-backend = ["antseal-net/ant-backend", "dep:tokio"]`). Today's two arms compile clean in
  both builds.
- P2's stand-alone probe (rustc 1.92.0): an enum with two variants and a third under
  `#[cfg(feature_x)]`, matched as `E::A | E::B => 1` followed by `other => …`. In the default
  build that prints *"warning: unreachable pattern … no value can reach this"*
  (`#[warn(unreachable_patterns)]`), which `clippy -D warnings` turns into a failure. With the
  `other` arm under `#[cfg(feature_x)]`, neither build warns.
- So naming both default variants in one arm needs the remainder arm, and the remainder arm needs
  `#[cfg(feature = "ant-backend")]`: without the arm the `ant-backend` build is not exhaustive,
  and without the `cfg` the default build fails clippy.
- Dropping `KeyGenerationFailed` from the first arm while keeping the gated remainder does not
  compile in the default build (E0004, P2). That is a compile check, not a plant (§3).

### 1.7 Where the gated arm is compiled

- **The local gate's heavy tier is triggered by path.** `HEAVY_TRIGGER_PATHS`
  (`scripts/gate-features.sh:112-121`) names `crates/antseal-net/`, `backend.rs`, `commands.rs`,
  `pipeline/`, `vault/wallet.rs`, the devnet launcher and scripts, `Cargo.toml` and
  `Cargo.lock`. It does not name `init.rs`.
- **The list is meant to cover every CLI source carrying the cfg.** `gate-features.sh:104-111`
  records why `commands.rs` was added (D170 §2 R11): it was *"the only OTHER CLI source file
  carrying `cfg(feature = "ant-backend")`"*, and before the entry *"a change touching only it
  classified light, so its feature-gated code compiled in no tier: the Q112 class"*. At
  `6e1cab3` that census still holds: `git grep -c -E 'cfg\((not\()?feature = "ant-backend"'
  6e1cab3 -- crates/antseal-cli/src` → `backend.rs` 19, `commands.rs` 10. `init.rs` mentions
  `ant-backend` 0 times, against 5 for `WalletOpsError`. (`lib.rs:39` is a `cfg_attr`, a
  different form.)
- **Hosted `ci` does not run the heavy tier.** `.github/workflows/ci.yml:357-360`:
  *"NOT here: `gate-features.sh --heavy` (tier 2) … stays a local, diff-triggered gate"*.
- **So §2 R1 makes `init.rs` a third CLI source carrying the cfg.** This wave's gate still
  compiles the arm: the implementing lane's own edit to `wallet.rs` lies under
  `crates/antseal-net/`, as do `S49`'s and `S50`'s, and the close gate forces the heavy tier
  anyway. A later change touching only `init.rs` would classify light (§4).

### 1.8 The options

| option | the one claim it renders | cost | true? |
|---|---|---|---|
| **(i) route it through `RandomSourceUnavailable`**, sharing `EntropySource`'s arm, `what` and `consequence` | the machine's | XS: `init.rs` only (the arm, its doc, its test), plus the gated remainder arm | the machine claim is true; *"unavailable"* is strained for a source that answered, so it needs the reading §2 R2 records — **taken** |
| (ii) keep `Internal` and word it as the bug it would be | antseal's | XS: the wallet's text and the test | **false at any tested build** (§1.3) |
| (iii) a sibling variant (*"the random source answered, but none of 64 values it returned could be a wallet key …"*) | the machine's | S: a new `CliError` variant and its `class()` arm (`error.rs:1108`), `init.rs`, an exemplar appended to `tests/exit_codes.rs` and a block to `cli-errors.display.txt` (`exit_codes.rs:5-9` promises an exemplar for every variant) | exact — the fallback (§2 R5) |
| (iv) widen the shared first clause (*"is unavailable"* → *"failed"*) | the machine's | S: every pin of the shared words, 8 lines in 8 files under `crates/` (§0), one of them `pipeline/error.rs`, which `S50`'s lane also edits this wave | exact |

## 2. RULING

### §2 R1 — `KeyGenerationFailed` shares `EntropySource`'s classification; `init.rs` stays `cfg`-free

`init`'s wallet-key mapping, `wallet_generation_error` (`init.rs:677-687`), classifies through a
`cfg`-free predicate on the error, `WalletOpsError::is_random_source_failure()` in
`crates/antseal-net/src/wallet.rs`, true of `EntropySource` and `KeyGenerationFailed` only, so
`init.rs` carries no `cfg` and the mapping becomes:

```rust
if err.is_random_source_failure() {
    CliError::RandomSourceUnavailable { what: "the wallet key", consequence: "no vault was created" }
} else {
    CliError::Internal { detail: err.to_string() }
}
```

*Why:*
- Option (i) is the only one whose single claim is true at XS (§1.8).
- **A predicate on the error, not a `cfg` arm** (§1.6, §1.7; amended in place, see the note at the
  end of R1). The first ruling's arm needed `cfg(feature = "ant-backend")` in `init.rs`, a file the
  heavy tier's trigger list does not name; the predicate keeps the feature-dependent variants
  inside `antseal-net`, where they are defined. What it gives up: a new default-build variant
  maps to `Internal` until the predicate names it, instead of failing to compile.
- **The gated variants keep today's mapping.** `Config` and `KeyRejectedByStack` never come from
  `generate()` (§1.4); `KeyRejectedByStack` is by its own doc *"an internal-invariant breach"*
  (`wallet.rs:405-406`).
- **The consequence is true for both variants.** The key is drawn in step 4 (`init.rs:539`),
  before `create_vault_with_wrap` (`:573`), so no vault was created.

*(Amended in place by the orchestrator on 2026-10-20, before this record was first committed: the first ruling's cfg-gated arm would have made `init.rs` a third CLI source carrying that cfg off the heavy-trigger list; see §6.)*

### §2 R2 — D201's *"unavailable"* means *"cannot supply usable randomness"*

The reading recorded here: D201's *"unavailable"* means that the source **cannot supply usable
randomness**, in D201 §1.4's own words — *"an operating system that cannot supply randomness is
a fault of the machine"*. A source that answers `Ok` 64 times with values no working source
produces (log10 P = −2459.4, §1.2) cannot supply usable randomness.

This **overturns** D201 §4's sentence *"It names the entropy source but is not an unavailable
one"* and **widens** §2 R2's *"mapping only `WalletOpsError::EntropySource`"* for this one site.
The rendered message makes **one** claim, the machine's, and does not call itself a bug in
antseal.

*Why:* D201 §2 R2's own test is that *"Every clause must be true by measurement at each site that
uses it"* (D201:213). At this site:
- *"the operating system's random source is unavailable"* is true under the reading;
- *"so the wallet key could not be generated"* is true: no draw passed the gate (§1.1);
- *"no vault was created"* is true (§2 R1);
- *"This is a fault of this machine, not a bug in antseal"* is true at any tested build (§1.3);
- *"antseal has no other source of randomness to fall back on"* is true: `generate()` draws
  only through `getrandom::fill` (`wallet.rs:114`), one of the two production draws outside the
  CLI that D201 §6 counted.

### §2 R3 — The wallet's own Display stays; its doc slip is corrected in passing

`KeyGenerationFailed`'s Display (`wallet.rs:396-399`) reaches no user after R1, and it stays as
it is. The doc slip *"(probability < 2⁻¹²⁸ per draw)"* (`wallet.rs:70-71`; the rulings say
`:69-70`) is corrected in passing, doc lines only: the exact figure is 2^−127.65, which is below
2^−127 (§1.2).

### §2 R4 — Tests

Rewrite `init.rs`'s unit test `only_an_unavailable_random_source_blames_the_machine_for_the_wallet_key`
(`:889-921`, its doc at `:890-893`) so that **both** `EntropySource` and `KeyGenerationFailed`:
- are class `internal`, exit 1;
- contain *"the operating system's random source is unavailable, so the wallet key could not be
  generated: no vault was created."* and *"This is a fault of this machine, not a bug in
  antseal"*;
- contain neither *"this is a bug in antseal"* nor *"returning invalid data"*.

The doc comments at `init.rs:672-676` and `:890-893`, which say D201 §4 *"leaves undecided"*
this variant, become false under R1 and are rewritten with the arm and the test (P2's edit set).
Plants P106-a and P106-b and the build checks are in §3.

### §2 R5 — The fallback is not taken; records

- **Not taken: (iii), a sibling variant** (S, with a new exemplar and snapshot block, §1.8). It
  is exact, and it remains the costed alternative if a later measurement shows that a working
  source can produce `KeyGenerationFailed`.
- **D201** takes a dated addendum: §4's sentence and §2 R2's *"only `EntropySource`"* are
  answered here.

### What no ruling here moves

- **No exit code and no class**: `internal`, exit 1, as today. `PINNED_CLASS_COUNT` stays 36.
- **No frozen surface.** `cli-errors.display.txt`'s `[random-source-unavailable]` exemplar
  (`:97-98`) is the timestamp-nonce site and does not move; no `--json` key changes; the module
  table's row 1 (*"an unavailable OS random source (D201)"*, `error.rs:16`) reads true under §2
  R2.
- **Untouched:** `crates/antseal-cli/src/error.rs` (the variant exists), every snapshot, and
  every storage or payment path.

## 3. Fault plants

The implementing lane owes these. The red baseline comes first, on the unedited code; each plant
is judged by its **message**; every restore is followed by a `touch`. `init.rs` is compiled by
every lane, so plants run in a shadow copy with a private `CARGO_TARGET_DIR`.

**The green test — the load-bearing half**

- **The rewritten unit test** (§2 R4). **Red baseline at `6e1cab3`:** it fails on
  `KeyGenerationFailed`, whose message is today's bug-class text (§1.4), so the required sentence
  is absent.

**The plants — proof that the test can fail**

| Plant | Must redden |
|---|---|
| P106-a: today's two arms, `EntropySource =>` and a plain, un-gated `other =>` (it compiles in both builds) | the rewritten test, on *"this is a bug in antseal"* for `KeyGenerationFailed` |
| P106-b: `consequence: "nothing was created"` | the rewritten test, on the consequence clause |

**Compile checks, which are not plants** (§1.6)

- Dropping `KeyGenerationFailed` from the first arm while keeping the gated remainder: E0004 in
  the default build.
- Naming both default variants and leaving the remainder arm un-gated: an `unreachable_patterns`
  warning in the default build, which `clippy -D warnings` fails.

**Build checks that carry the gated arm**

- The default `cargo clippy -p antseal-cli --all-targets -- -D warnings`: it fails if the arm is
  not gated.
- The `ant-backend` compile of the arm: the orchestrator's checkpoint runs the heavy clippy. The
  lane may prove it early with `cargo check -p antseal-cli --features ant-backend` in a private
  target, which P2 put at about 100 minutes cold.

## 4. What this record does NOT decide

- **The sibling variant (iii).** Not taken (§2 R5).
- **A source stuck on a constant that passes the gate.** It yields a valid, predictable key
  (§1.2). Context only, and no row: an operating system's random source is not antseal's to test
  (D201 §1.4).
- **The gated variants' wording.** `Config` and `KeyRejectedByStack` keep today's mapping
  (§2 R1). Under R1 the gated arm is unreachable from `generate()` (§1.4); they are not reviewed
  here.
- **Whether `init.rs` joins `HEAVY_TRIGGER_PATHS`.** D170 §2 R11's rule puts a CLI source that
  carries `cfg(feature = "ant-backend")` on the list (§1.7). `scripts/gate-features.sh` is in no
  lane's write scope this wave, and its self-test pins `commands.rs`'s classification by name
  (`gate-features.sh:319`). Not ruled here; routed to the orchestrator as a list entry or a row.
- **New rows.** This record mints none.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-INIT (round 1) — `U105` (D205), then this record

- `crates/antseal-cli/src/init.rs`: `wallet_generation_error` (`:677-687`) and its doc
  (`:672-676`) (R1); the unit test (`:889-921`) and its doc (`:890-893`) (R4).
- `crates/antseal-net/src/wallet.rs`: the doc lines `:70-71` only (R3).
- Not this lane's: `crates/antseal-cli/src/error.rs` (the variant exists; if the lane finds it
  must change, it stops and asks), every snapshot, any other source file.
- Greens it reports verbatim: `cargo test -p antseal-cli --lib -- init::`, the default
  `cargo clippy -p antseal-cli --all-targets -- -D warnings`, `cargo test -p antseal-net --lib`
  for the doc edit, and `rustfmt --check` on its files.

### RECORDS-C — a dated addendum

- **D201**: §4's sentence and §2 R2's *"only `EntropySource`"* are answered (R2, R5).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `U106`'s tick against §3, once the checkpoint's heavy clippy has compiled the predicate's
  `ant-backend` test arm in `wallet.rs` (R1 as amended: `init.rs` carries no gated code).
- This record's index row and register row.
- The heavy-trigger question (§4).

## 6. As built — wave 40, lane L-INIT (recorded in place before this record was first committed)

Every verdict below was read from an exit file, and every red was judged by its message: this
records lane read the lane's exit files back, and each matches its report. The plants ran in a
shadow copy with a private target; the in-tree runs went through the shared target under the locks.

- **§2 R1 was amended before it landed. Deviation from the first ruling: `init.rs` has no `cfg`
  arm.**
  - *Why:* RECORDS-C measured that `init.rs` is not on `HEAVY_TRIGGER_PATHS`
    (`scripts/gate-features.sh:112-121`, unchanged this wave). The ruled arm would have made it the
    third CLI source carrying `cfg(feature = "ant-backend")`, after `backend.rs` and `commands.rs`,
    so a later change touching only `init.rs` would have compiled the arm in no tier: D170 §2 R11's
    `Q112` class (§1.7). The lane had logged the same gap before the amendment. The orchestrator
    amended the mechanism and extended the lane's scope to `wallet.rs`. The first version was in
    the tree from 00:39Z to 00:49:01Z, per the lane's report, and its greens are superseded.
  - *A second reason, code-traced by the lane, which cannot arise as built:* a build that enables
    `antseal-net/ant-backend` without `antseal-cli`'s own feature gives `WalletOpsError` four
    variants, while the ruled arm's `cfg` reads `antseal-cli`'s features and drops the arm, so the
    `match` fails with E0004. Only `crates/antseal-cli/Cargo.toml:50` forwards that feature, so
    only a command naming it reaches that build. `matches!` compiles under every combination.
  - **What landed.** `WalletOpsError::is_random_source_failure()` (`#[must_use]`,
    `crates/antseal-net/src/wallet.rs:428-431`) is `matches!(self, Self::EntropySource |
    Self::KeyGenerationFailed)`. Its doc (`:413-427`) cites D201 and D206 and says why it is a
    predicate. `wallet_generation_error` (`crates/antseal-cli/src/init.rs:797-808`) maps `true` to
    `RandomSourceUnavailable { what: "the wallet key", consequence: "no vault was created" }` and
    everything else to `Internal { detail: err.to_string() }`.
  - `init.rs` has 0 `cfg(feature` lines (control: `fn run_init`, 1). Under `crates/antseal-cli/src`
    the `cfg` still sits in `backend.rs` and `commands.rs` only, as at `HEAD`: 14 and 6 lines of
    `cfg(feature = "ant-backend")` (the lane's count), or 19 and 10 with `cfg(not(…))` (§1.7's).
  - **Deviation: R1's compile-time property moved into a test.** R1's *Why* wanted a new
    default-build variant to fail to compile until it is mapped. In the library, `matches!` sends
    such a variant to `Internal` without a compile error. The guard is now the wallet test's
    `side_of_d201_line` (`wallet.rs:696-702`), an exhaustive `match` with no catch-all, so the test
    target fails to compile until a new variant is classified.
  - This records lane rewrote R1's mechanism sentence in place under the amendment, and R1 ends
    with the amendment note. R1's heading and its second *Why* bullet still describe the first
    ruling's gated arm; this section supersedes them.
- **§2 R2, the reading,** has no code of its own. Both variants now render one claim, the
  machine's, in class `internal`, exit 1: *"the operating system's random source is unavailable, so
  the wallet key could not be generated: no vault was created. This is a fault of this machine, not
  a bug in antseal, and antseal has no other source of randomness to fall back on"*. The
  predicate's doc (`wallet.rs:413-421`) and `wallet_generation_error`'s (`init.rs:782-790`) state
  the reading.
- **§2 R3.** `KeyGenerationFailed`'s Display (`wallet.rs:396-399`) is unchanged, and the enum block
  (`:388-410`) is byte-identical to `HEAD`'s. The slip is fixed at `wallet.rs:71`, doc only, by one
  character: *"(probability < 2⁻¹²⁷ per draw)"*. §0's `:70-71` is the sentence; `:71` is the line
  that changed. The lane recomputed log2 P = −127.6543 and log10 P(64 in a row) = −2459.38.
- **§2 R4, the tests.**
  - `init::tests::only_an_unavailable_random_source_blames_the_machine_for_the_wallet_key`
    (`init.rs:1023`, doc `:1011-1021`) is rewritten as ruled. It asserts the variant count (2)
    first. For each variant it asserts class `internal`, exit 1, *"… unavailable, so the wallet key
    could not be generated: no vault was created."* and *"This is a fault of this machine, not a
    bug in antseal"*, and that neither *"this is a bug in antseal"* nor *"returning invalid data"*
    appears. The name is kept: R4 rules a rewrite, not a rename, and `TODO.md:1095` (`U104`'s row)
    cites it.
  - The doc comments R4 named (`init.rs:672-676` and `:890-893` at `HEAD`) are rewritten
    (`:782-796`, `:1011-1021`). *"undecided"* occurs in `init.rs` 0 times, against 2 at `HEAD`.
  - **Added with the amendment:**
    `wallet::tests::random_source_failures_are_exactly_the_two_generate_variants`
    (`wallet.rs:695`). It asserts the count (2) first, then that both default variants are
    random-source failures. Under `ant-backend` it asserts that
    `Config(InvalidRpcUrl { network: Devnet })` and `KeyRejectedByStack` are not.
- **§3, the red-first and the plants**, in the shadow, each restored by cp + `touch` with sha256
  equal.
  - **P106-a, re-derived for the amendment:** the predicate answers `true` for `EntropySource`
    only. That is `HEAD`'s mapping at `init`'s seam, so this run is also `U106`'s red-first.
    `cargo test -p antseal-net -p antseal-cli --lib --no-fail-fast` on the two tests exits 101,
    both red by message. `init.rs:1038`: *"KeyGenerationFailed: internal error: wallet key
    generation failed repeatedly; the system entropy source appears to be returning invalid data
    (this is a bug in antseal — please report it)"*. `wallet.rs:710`: *"KeyGenerationFailed is the
    machine's fault (D206)"*.
  - **P106-b** (`consequence: "nothing was created"`) exits 101, red at `init.rs:1038`:
    *"EntropySource: the operating system's random source is unavailable, so the wallet key could
    not be generated: nothing was created. This is a fault of this machine, …"*.
  - **§3's two compile checks were not run.** Both belonged to the replaced `match` (E0004, and
    `unreachable_patterns`), and `init.rs` no longer matches on the variants.
- **§3, the build checks.**
  - The default `cargo clippy --all-targets -- -D warnings` exits 0 with 0 warning or error lines,
    for `antseal-cli` and `antseal-net`, in the shared tree and in the shadow.
  - **The gated code is now the wallet test's arm**, under `crates/antseal-net/`, a heavy trigger.
    In the shared tree, on the final `wallet.rs`, `cargo test -p antseal-net --offline --locked
    --features ant-backend --lib -- wallet::` exits 0: *"8 passed; 0 failed; 0 ignored; 0
    measured; 138 filtered out"*, with 0 warning or error lines and the gated arm compiled.
  - **Deviation (venue):** that command is a no-binary class which the scopes granted L-NET3. The
    lane ran it, and queued it first on purpose, because the amendment put `cfg`-gated test code
    into `antseal-net`, which L-NET3's `ant-backend` builds compile.
  - Greens on the final files: `antseal-net --lib` 116 passed (shadow and tree); `-- wallet::` 8
    (shadow); `antseal-cli --lib -- init::` 6 (shadow and tree); the whole `antseal-cli` lib 331
    (shadow). `rustfmt --edition 2024 --check` exits 0 on `init.rs` and `wallet.rs`.
- **What no ruling here moves did not move.** `PINNED_CLASS_COUNT` is 36
  (`tests/namespace_disjointness.rs:85`). `cli-errors.display.txt` is untouched, and its
  `[random-source-unavailable]` exemplar (`:97-98`) is still the timestamp-nonce site. The lane
  touched neither `crates/antseal-cli/src/error.rs` nor any snapshot; that file's one hunk this
  wave (`:59-62`) is the orchestrator's D204 act.
- **Left open.**
  - **§4's heavy-trigger question does not arise for `init.rs`,** which carries no `cfg`. The
    general gap is the lane's instrument finding I1: `HEAVY_TRIGGER_PATHS` is a hand list whose
    self-test pins `commands.rs` alone (`gate-features.sh:319`), so a further CLI file that gains
    the `cfg` would classify light without a warning. The lane proposes a self-test arm that
    requires every `crates/antseal-cli/src` file carrying the `cfg` to be on the list, with a plant.
    The orchestrator owns it, for the ledger. The report cites the list at `:94-103`; it is at
    `:112-121`.
  - **The tick.** §5 tied `U106`'s tick to the checkpoint's heavy clippy compiling R1's gated arm.
    No such arm exists now. The gated code is the wallet test's arm, which the lane's `ant-backend`
    `cargo test` compiled and ran, and which no heavy clippy has linted yet. The tick is the
    orchestrator's.

## Closing — this record is not consent

It changes one error mapping, one unit test, one predicate on the error (with its unit test) and one doc line, inside the wave's own commits.
Nothing in it authorises a push, a workflow dispatch, a deploy or any other outward act; each of
those needs the maintainer's express consent naming the action, the destination and the account.
