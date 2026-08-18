# D148 — No outbound wallet-key route is added, and not for the lean's reason: the wallet key is not derivable, the dead end is narrower than the row records, and the upstream mitigation two shipped pages already cite has never existed

- **Status: RESOLVED. The lean's DIRECTION survives on measurement — no key is
  shown at `init`, no consent-gated export is built — and its stated REASON is
  OVERTURNED.** The lean was *"Arm (a): accept the dead end permanently and move
  the mitigation upstream to `init`'s report and
  `docs/user/funding-your-wallet.md`, because arms (b) 'show the key once at
  init' and (c) 'a consent-gated export' both trade a documented dead end for a
  new disclosure surface."*
  - **There is nothing to *move* upstream. The mitigation the lean proposes to
    relocate does not exist anywhere, and two shipped pages already tell the
    reader it does.** `docs/user/vault-theft.md:269-271` asserts *"**This is why
    `funding-your-wallet.md` says to keep the balance small and fund close to
    when you seal** — that advice is the mitigation"*, and
    `docs/user/vault-loss.md:64-67` ends *"losing the vault loses whatever
    balance that address held. See `funding-your-wallet.md`."* Measured (§1.5),
    `funding-your-wallet.md` states the wallet-custody fact **zero** times, and
    the *"keep the balance small and fund close to when you seal"* sentence it
    does carry (`:116-119`) is attached to an entirely different rationale —
    **public linkability**, `wallet-hygiene.md`'s subject. The words are there;
    the reason is not. Two forward references dangle, and this is the same class
    U82 was minted for: **a document describing a neighbour's obligation as
    fact.** The ruling is therefore a *repair*, not a relocation.
  - **The dead end is narrower than the row's headline, and the row's decisive
    sentence is wrong.** The row says the export *"hands the victim no capability
    the attacker lacks"*. Measured (§1.4), `vault import` **reinstalls the wallet
    key** (`crates/antseal-cli/src/vault/export.rs:1104-1106`, verified by
    `post_install_verify`'s `expect_wallet` arm at `:1253-1258`), so a holder of a
    pre-theft backup keeps **full spending capability** — the only capability
    those funds ever had. What is absent is not *use*; it is **sweep**: no route
    moves the balance to an address antseal does not hold. That is a materially
    smaller loss than *"funds they can never sweep from any other wallet"* implies,
    and it is what the copy must say.
  - **The brief's highest-value hypothesis is REFUTED, by an exhaustive
    constructor sweep rather than by inference.** The wallet key is **not**
    derived from the vault seed, `W`, or any paper key: `WalletKey::generate()`
    draws 32 raw bytes from the OS CSPRNG (`getrandom::fill`,
    `crates/antseal-net/src/wallet.rs:102-119`) with no seed input of any kind,
    and the **only** production constructions of wallet-key material in the whole
    workspace are that call, `WalletKey::import`, and `WalletKeyHandle::from_bytes`
    reading a decrypted record (§1.2). The paper-key work is about **locked
    bundles**, is a v1.1 parking-lot item, and ships no code
    (`docs/research/paper-key-transport-design-round.md`). **The fourth arm the
    brief hoped for does not exist.**
  - **Arms (b) and (c) lose on a ground the lean does not give — the spec's
    own.** `MVP-SPEC.md:184` lists *"wallet key inside the vault"* as one of the
    **mitigations** for *"Vault loss AND vault theft"*, alongside *"loud docs for
    both"*; and `MVP-SPEC.md:143` already names the eventual direction, which is
    **not** an export: *"external-signer support may come later"*. So (b)/(c)
    would weaken a spec-listed mitigation in order to pre-empt a spec-named
    future by the one mechanism the spec does not choose. *"Loud docs for both"*
    is the spec-mandated form of the remedy, and it is precisely what is broken.
- **A product defect found on the way, named here and deliberately NOT fixed
  here.** `init`'s own keyfile copy tells a keyfile-wrapped user *"`antseal vault
  export` does NOT contain the keyfile, only the fact that one is required"*
  (`crates/antseal-cli/src/vault/keyfile.rs:286-290`) — but `vault export`
  **refuses outright** for any non-zero wrap mode, before a single record is read
  (`crates/antseal-cli/src/vault/export.rs:744-756`). The test that guards that
  copy asserts the copy against itself and cannot see the refusal
  (`keyfile.rs:404-414`). It is a **new row candidate** (§4.3), not this record's
  edit — but it is why §2 R3's ruled sentence says *"your vault backup"* and never
  *"a `vault export`"*.
- **Date: 2026-08-18**
- **Owning task: U83.** Rulings touch `docs/user/funding-your-wallet.md`,
  `docs/user/vault-theft.md`, `docs/user/vault-loss.md`,
  `crates/antseal-cli/src/init.rs`, and — by exactly one report line — **U78's
  in-flight golden** (§2 R7).
- Related: U10 (the wallet sub-key, and the row that already names *"future
  external-signer support"*), U12/D47 (the export format and its passphrase-alone
  key), D39/D41/D44 (the `init` interaction model, the fd channel, the accepted
  import set), D89 (the wallet light half), U21 (the secret-hygiene harness whose
  coverage this ruling deliberately leaves untouched), U78 (the golden rendering
  of the report this ruling adds one line to), U82 (the same defect class, in
  code comments), Q24/Q25 (the page work that discovered U83).

---

## 1. The measurements

Every figure carries the command that produced it. Read-only throughout: no
push, no `gh` mutation, no network write. Scratch copies live in the session
scratchpad, never in the tree. `${PIPESTATUS[0]}` is read back out of a file for
every exit code quoted, because the harness's own completion notice reports the
last command in the wrapper and not the one measured.

### 1.1 The row's code claims, verified by search over the crate rather than by re-reading the row

Every locator in `TODO.md:849` and `tasks/U.md:1183-1200` was re-derived:

| Row's claim | Measured | Verdict |
| --- | --- | --- |
| nine subcommands, `cli.rs:113` | `enum Command` spans `113..185`; variants `Init 116, Seal 120, List 124, Show 128, Status 136, Restore 148, Reveal 160, Verify 164, Vault 181` — **9** | exact |
| `--wallet` defaults to `generate`, `cli.rs:193` | `:193` is `#[arg(long, value_enum, default_value_t = WalletSource::Generate, …)]` | exact |
| `cli.rs:190-200`, `:253-260` (the flag + the enum) | `pub wallet` `:194`, `pub wallet_key_fd` `:200`; `pub enum WalletSource` `:255` with its doc comment at `:253-254` | exact |
| interactive paste `init.rs:515-517` | the hidden-paste prompt is `:514-518` | off by one at each end; harmless |
| generation `init.rs:497-501` → `wallet.rs:102-119` | `:498-501` is the `Generate` arm; `WalletKey::generate()` is `wallet.rs:102-119` **exactly** | exact |
| `init.rs:523-525` keeps only the address | `:523` `let address = checksummed(wallet_key.address());`, `:524` `handle_from`, `:525` `drop(wallet_key);` | exact |
| `vault import` reinstalls, `export.rs:1104-1106` | `:1104-1106` is `if let Some(wallet) = &payload.wallet { store_wallet_key(&new_vault, wallet, rng)?; }` | exact |
| *"the only reads are"* `commands.rs:381`,`:387` and `export.rs:761` | **INCOMPLETE — see §4.1** | corrected |

The one claim the row states as an absolute — *no outbound route* — was re-derived
rather than accepted, by sweeping every read of the vault's wallet record across
`crates/**/src/**`:

```
$ rg -n --glob 'crates/**/src/**/*.rs' 'load_wallet_key\(|\.secret_bytes\(\)' .
```

Four production sites, and **no fifth**:

- `crates/antseal-cli/src/vault/wallet.rs:117` — the store side (`store_wallet_key`).
- `crates/antseal-cli/src/commands.rs:381` → `:387` — the `seal` pay path.
- `crates/antseal-cli/src/backend.rs:699` → `:717` — the payment-RPC path, `#[cfg(feature = "ant-backend")]` (`backend.rs:85-86`).
- `crates/antseal-cli/src/vault/export.rs:761` → `:301` — the copy into an export payload.

None displays, prints, exports as plaintext, or rotates. **The row's conclusion
holds; its enumeration does not** (§4.1).

### 1.2 The derivability question — the brief's highest-value measurement, and the answer is NO

`crates/antseal-net/src/wallet.rs:102-119`:

```rust
pub fn generate() -> Result<Self, WalletOpsError> {
    for _ in 0..GENERATE_ATTEMPTS {
        let mut raw = [0u8; SCALAR_LEN];
        if getrandom::fill(&mut raw).is_err() { … }
```

No seed parameter, no `W`, no HKDF, no vault input of any kind — 32 bytes from
the OS CSPRNG, gated by the D44 scalar check. The **only** HKDF the wallet
touches is `WALLET_SUBKEY_INFO = b"antseal-cli vault v1: wallet record sub-key"`
(`crates/antseal-cli/src/vault/wallet.rs:56`), which derives the key that
**encrypts the record**, not the key inside it. The complete set of production
constructions of wallet-key material in the workspace is:

```
$ rg -n 'WalletKey::|WalletKeyHandle::from_bytes' crates/ --glob '*.rs' | grep -v tests
```

`WalletKey::generate()` (init), `WalletKey::import()` (init and the backend
re-parse at `backend.rs:609`), and `WalletKeyHandle::from_bytes` fed from the
decrypted vault record (`vault/wallet.rs:156`), the export payload
(`export.rs:402`), or `init`'s own `handle_from` (`init.rs:682`). **Nothing
derives it.**

The paper key was measured, not assumed:
`docs/research/paper-key-transport-design-round.md` is a **design note, not a
decision record**, its subject is *paper-key locked **bundles*** (a v1.1
parking-lot tier), it mentions the wallet exactly once and only to note a
self-selection bias in a user demographic, and a sweep of `crates/` for
`paper_key|paperkey|mnemonic|bip39|seed phrase` finds **only** D44's
*mnemonic-not-supported* rejection class. **There is no paper key in this
product, and therefore no fourth arm through one.**

### 1.3 What the export actually contains, and under what

`crates/antseal-cli/src/vault/export.rs:300-302`:

```rust
if let Some(wallet) = &payload.wallet {
    m.entry(3, |e| e.bytes(wallet.secret_bytes()))?;
}
```

Payload map **key 3 is the raw 32 key bytes**, under **one** AEAD
(XChaCha20-Poly1305) whose key is `KDF(passphrase, fresh salt)` — *"the
passphrase alone"*, the module's own words at `:35-36`, and D47's *"Same vault
passphrase"* (`D47:7`). So the row's *"encrypted under the same passphrase"* is
**exact**. Two things follow that the row does not draw:

1. The export is a **strictly easier** extraction target than the vault
   directory: one KDF and one AEAD, versus the vault key schedule plus the
   `WALLET_SUBKEY_INFO` step.
2. **The payload key numbering is documented only in the source.** D47 gives the
   envelope (`MAGIC ‖ header ‖ ciphertext`) and mentions payload key 1 once in
   its S29 amendment (`D47:226`); it never enumerates the payload map, and
   `docs/format/` covers the bundle registry, not this file. So *"a documented
   external-import procedure with zero new code"* — the brief's item 7 — **is not
   available today**, and §3.4 refuses to create it.

### 1.4 A restored vault pays

`export.rs:1104-1106` calls `store_wallet_key` on the new vault, and
`post_install_verify` (`:1253-1258`) fails the whole import if the wallet record
does not decrypt afterwards. So the claim ruled into copy at §2 R2/R3 — *"a
restored vault pays exactly as the original did"* — is a property the import path
**asserts about itself**, not an inference.

### 1.5 The measurement that decides the record: the mitigation is not where two pages say it is

The claim under test is `vault-theft.md:269-271`'s *"**This is why
`funding-your-wallet.md` says to keep the balance small…**"*. Auditing that by the
neighbouring populated field — *does the advice sentence exist?* — answers a
different question and would have published a confident wrong "all clear". The
field that carries the claim is the funding page's **own stated reason**, and it
reads (`docs/user/funding-your-wallet.md:116-119`, verbatim):

```
116: Keep the balance small and fund close to when you seal. A funding transfer is
117: public and permanent, and it links this wallet to wherever the funds came
118: from — that chain of inference is `wallet-hygiene.md`'s subject, and it is
119: worth reading before your first mainnet transfer rather than after.
```

**Public linkability. Not irrecoverability.** The nearest the page comes to the
custody fact is `:112` — *"Only the vault's own key can spend it"* — which reads
as a warning about sending to the wrong address.

Run over the page, with a positive control and a planted fault, so the negative
result is a measurement and not an assertion:

```
POSITIVE CONTROL  grep -c 'Keep the balance small and fund close to when you seal'  -> 1   REAL_EXIT=0
NEGATIVE          'never leaves the vault'      -> 0
                  'no command displays it'      -> 0
                  'never comes back out'        -> 0
                  'cannot move'                 -> 0
                  'sweep'                       -> 0
PLANTED (scratch copy + one sentence appended)
                  'never leaves the vault'      -> 1   PLANTED_REAL_EXIT=0
UNPLANTED ORIGINAL, same grep
                  'never leaves the vault'      -> 0   ORIG_REAL_EXIT=1
```

The grep can go both ways; the page really is silent. A whole-tree sweep for the
fact (`no command prints or exports|never comes back out|cannot sweep|can never
move`) returns **`docs/user/vault-theft.md:259` and `:261` and nothing else** in
any user-facing file. And `vault-loss.md:64-67` closes its money paragraph with
*"See `funding-your-wallet.md`."* — the **second** dangling reference to the same
absent text.

### 1.6 What `init` prints today

`InitReport::render()` (`crates/antseal-cli/src/init.rs:250-268`) emits, in order:
`Vault created at …` · `Network: …` · blank · `Payment wallet address: <ADDR>` ·
blank · [`placement_guidance` + blank, keyfile vaults only] · `funding_lines(…)` ·
blank · `standing_warnings()`. `standing_warnings()` (`:335-350`) opens *"Two
things to understand before you seal anything:"* and carries `LOSS_WARNING` and
`THEFT_WARNING` by identity from `crates/antseal-cli/src/vault/bookkeeping.rs:68`
and `:74`, plus the possession paragraph. **The wallet key is mentioned nowhere in
the report.** `InitReport` already carries `wallet_source: &'static str` (`:217`,
and in `--json` at `:239`), so a wallet-source-conditional line would have cost no
plumbing — §3.5 refuses it anyway, for a reason that is about U78, not about cost.

### 1.7 The venues are positioning-linted, and the ruled copy is clean — with a positive control

`scripts/check-copy-style.py`'s `COPY_SCAN` carries **`docs/user/`** and
**`crates/antseal-cli/tests/snapshots/`** as directory entries, and
`DOCS_CLASSIFICATION["user/"]` is `PRODUCT`. So both venues §2 touches are Class P,
and the `init` line becomes scanned the moment U78's golden lands. The six needles
were imported from the checker itself and run against the exact ruled string:

```
NOTARY hits=0 · PRIORITY hits=0 · AUTHORSHIP hits=0
RECEIPT_ANCHOR hits=0 · CLAIMED_TIME_ANCHOR hits=0 · PRODUCT_URL hits=0
POSITIVE CONTROL on "antseal is a digital notary and proves authorship and priority."
NOTARY hits=1 ['notary'] · PRIORITY hits=1 ['priority'] · AUTHORSHIP hits=1 ['authorship']
```

The same three regexes that return zero on the ruled copy fire on a string built
to trip them, so the zero is a result.

### 1.8 Tree baseline

`python3 scripts/check-traceability.py` (flagless — that IS its check):
`TRACE_REAL_EXIT=0`, 8 checks green, `[decision-index] ok — 139 index row(s) …
against 139 record(s)`. **This file makes it 140 records against 139 rows**, which
reds `decision-index` until the registrar lands the row — the routine mid-act
window D119 RULING 6 names (§5, item 1).

---

## 2. The ruling

**Owner: U83**

Arm **(a)'s direction** is ruled: **no outbound wallet-key route is created in
v1** — no display at `init`, no export subcommand, no fingerprint command, no new
CLI surface of any kind. Arm (a)'s *reason* is replaced by §1.5: the mitigation is
not relocated, it is **written for the first time**, and the two pages that
already cite it are repaired.

### R1 — Nothing is added to the command surface

No new subcommand, flag, `--json` key, exit code or environment channel. `cli.rs`,
`commands.rs`, `backend.rs`, `vault/wallet.rs` and `vault/export.rs` are **not
edited by this ruling**. Consequences, which are the point:

- **U21's secret-hygiene harness keeps its coverage unchanged.** It already drives
  every implemented command at every verbosity, in plain and `--json` mode, and
  scans stdout, stderr, the JSON document, written files, `/proc/<pid>/cmdline`
  and `/proc/<pid>/environ` for the wallet-key sentinel in raw, lowercase-hex,
  uppercase-hex and base64 form. **A ruling that adds no command needs no new
  hygiene arm**, and the guarantee "no key material reaches a log, an error, a
  fixture or a snapshot" is discharged by a shipped, self-tested instrument
  rather than by a new promise.
- The frozen help surface (`cli-surface.help.txt`, U1) is untouched, so no
  `ANTSEAL_BLESS=1` freeze event is opened by this ruling.

### R2 — `docs/user/funding-your-wallet.md` gains the section two pages already cite

Insert a new section **immediately before** `## Arbitrum One — real funds`
(today line 85) — i.e. before the reader is first told to send real funds:

```markdown
## What this address's key can and cannot do

`init` says this once, next to the address:

    No antseal command displays this address's key, and nothing moves its balance to another wallet: antseal can only spend it on seals. If antseal generated the key, your vault backup is the only copy of it there will ever be. Fund this address like a prepaid meter, not a savings account.

(That is the constant `WALLET_CUSTODY_NOTE` in
`crates/antseal-cli/src/init.rs`, quoted word for word; a test asserts this page
still carries it.)

Unpacked:

- **The key is made inside the vault, and antseal has no command that shows
  it.** `--wallet` defaults to `generate`
  (`crates/antseal-cli/src/cli.rs:193`), and a generated key goes straight into
  the vault's wallet record: `init` keeps the checksummed address and drops the
  key (`crates/antseal-cli/src/init.rs:523-525`). None of the nine subcommands
  prints, exports or rotates it.
- **You can keep spending it; you cannot move it.** A vault backup carries the
  key, and `vault import` reinstalls it
  (`crates/antseal-cli/src/vault/export.rs:1104-1106`), so a restored vault pays
  exactly as the original did. What no antseal command will ever do is hand you
  the key to sweep the balance into a wallet you hold elsewhere.
- **If you imported your own key, none of this binds you.** You still hold it
  outside antseal and can spend or sweep that address from any Arbitrum wallet.
- **This only works in advance.** Nothing here is a step you can take after a
  laptop is stolen or a vault is lost. It is a decision about how much to send,
  taken before you send it — `vault-theft.md` and `vault-loss.md` are what is
  left afterwards.
```

**And** replace the sentence at `:116-119` so the advice carries both of its
reasons instead of one:

```markdown
Keep the balance small and fund close to when you seal — for two independent
reasons. A funding transfer is public and permanent, and it links this wallet to
wherever the funds came from; that chain of inference is `wallet-hygiene.md`'s
subject, and it is worth reading before your first mainnet transfer rather than
after. And whatever sits at this address when the vault is lost or stolen is
bounded by what you put there, because nothing moves it out — see "What this
address's key can and cannot do" above.
```

### R3 — `init`'s report gains exactly ONE line, and here it is verbatim

Add the constant beside `standing_warnings()` — i.e. **below** `funding_lines()`
in `crates/antseal-cli/src/init.rs`, which matters for R6:

```rust
/// The wallet-custody fact `init` states once, beside the address it
/// qualifies (D148 §2 R3). This exact string is what
/// `docs/user/funding-your-wallet.md` carries, so the page and the CLI cannot
/// drift — asserted by `the_funding_page_carries_the_wallet_custody_note`.
///
/// It says "your vault backup", never "a `vault export`", **on purpose**:
/// `vault export` refuses a keyfile-wrapped vault outright
/// (`crate::vault::export`, the wrap-mode refusal), so naming the command
/// would make this line false for exactly the users `vault-theft.md` tells to
/// adopt a keyfile.
pub const WALLET_CUSTODY_NOTE: &str = "  No antseal command displays this address's key, and \
     nothing moves its balance to another wallet: antseal can only spend it on seals. If \
     antseal generated the key, your vault backup is the only copy of it there will ever be. \
     Fund this address like a prepaid meter, not a savings account.";
```

and emit it from `render()` **between** the existing address line and the blank
line that follows it (today `init.rs:256` and `:257`):

```rust
            format!("Payment wallet address: {}", self.address),
            WALLET_CUSTODY_NOTE.to_owned(),
            String::new(),
```

**One `Vec<String>` element. One printed line.** No new blank line; no change to
`funding_lines`, `standing_warnings`, `placement_guidance`, the `--json`
document, `InitReport`'s fields, or any other report text. The line is
**unconditional** — §3.5 records why it is not branched on `wallet_source`, even
though `InitReport` already carries it.

### R4 — `docs/user/vault-theft.md` is corrected, not merely re-read

Two replacements inside item 2 (`:258-271`).

**(a)** Replace `:259-262`'s inbound framing, whose own cited evidence
contradicts it — `cli-surface.help.txt:52-65` prints `[default: generate]` while
the prose names only `--wallet import`:

```markdown
   way to win that race.** No command prints or exports the wallet key on its
   own. The key arrives at `init` — by default **generated there** (`--wallet`
   defaults to `generate`;
   `crates/antseal-cli/tests/snapshots/cli-surface.help.txt:52-65`), or imported
   from a file descriptor or a hidden paste if you asked for that — and it never
   comes back out.
```

**(b)** Replace `:267-271` — the branch statement and the false causal claim:

```markdown
   passphrase. If you supplied the key yourself at `init` you still have it
   elsewhere and can sweep the address from any Arbitrum wallet. If antseal
   generated it, you cannot — but you can still *pay* with it: a backup you made
   before the theft restores into a working vault
   (`crates/antseal-cli/src/vault/export.rs:1104-1106`) and seals exactly as
   before. What you cannot do is move the balance somewhere the thief cannot
   reach, and the thief — holding the vault itself and racing you only for the
   passphrase — is who the small balance is for.
   **`funding-your-wallet.md`'s "What this address's key can and cannot do" is
   the mitigation, and it only works in advance.** That page gives the same
   *keep the balance small* advice for a second, independent reason — public
   linkability, `wallet-hygiene.md`'s subject — and the two reasons point the
   same way.
```

### R5 — `docs/user/vault-loss.md:64-67`'s dangling reference is made to resolve

```markdown
And the money is gone with it, in the case this page opens with — vault **and**
backup. From a surviving backup the address still pays: `vault import` reinstalls
the wallet key (`crates/antseal-cli/src/vault/export.rs:1104-1106`). What no
backup gives you is a way to move the balance to another wallet — see "What this
address's key can and cannot do" in `funding-your-wallet.md`.
```

### R6 — Re-measure the locator this ruling shifts, and do not trust this record's arithmetic

`docs/user/funding-your-wallet.md:98` reads *"(`crates/antseal-cli/src/init.rs:278-295`
— quoted word for word.)"*. R3 inserts one line at `init.rs:257`, which shifts
`funding_lines`'s body down by one; placing the constant **below** `funding_lines`
(R3) keeps the shift at exactly one. Do not write `:279-296` from that arithmetic —
**measure it**:

```
grep -n 'To seal, this address needs two things'          crates/antseal-cli/src/init.rs
grep -n 'network, and a seal is permanent and paid once'  crates/antseal-cli/src/init.rs
```

and write the two measured numbers into `:98`. This is the stale-locator class
this project keeps finding; it is cheap to avoid at the moment of the edit and
invisible afterwards.

### R7 — U78 coordination, stated precisely because a sibling lane depends on it

**`init`'s report gains bytes: exactly one line, `WALLET_CUSTODY_NOTE` (R3),
positioned immediately after `Payment wallet address: <ADDR>` and before the blank
line that follows.** Nothing else in the rendered report changes. U78's golden
must contain that line in that position. If U78's golden lands first, the
implementing lane of this record re-blesses it in the same act that adds the line
and says so in U78's row; if this record's implementation lands first, U78 writes
the golden against the shipped report and nothing is owed. **Either order is
fine; silence is not** — the whole reason this ruling names the byte count is that
U78 cannot discover it from `TODO.md`.

Second, forward-looking: once U78's golden exists under
`crates/antseal-cli/tests/snapshots/`, this line is inside
`check-copy-style.py`'s `COPY_SCAN`. It is clean against all six needles today
(§1.7); re-run `scripts/check-copy-style.py` after the golden lands rather than
relying on that measurement.

### R8 — The tests, and the planted fault each one must survive

Two tests, in `crates/antseal-cli/src/init.rs`'s test module. **They must fail for
different reasons**, which is the property the plants prove.

**T1 — the line is in the report, in the right place.** Deliberately *not* the
shape U78's row condemns (`init_command.rs:698-702` compares `render()`'s output
to `funding_lines()`'s own output and therefore cannot fail): the needle here is a
`const`, independent of `render()`, and the assertion is about **position**, which
a constant-versus-constant comparison could not fake.

```rust
#[test]
fn the_report_states_the_wallet_custody_fact_beside_the_address() {
    let lines = /* the module's existing sample InitReport */ .render();
    let at = lines
        .iter()
        .position(|l| l.starts_with("Payment wallet address: "))
        .expect("the report must carry an address line");
    assert_eq!(
        lines.get(at + 1).map(String::as_str),
        Some(WALLET_CUSTODY_NOTE),
        "D148 §2 R3: the wallet-custody note must be the line immediately after the \
         address it qualifies — a reader who stops at the address must still have met \
         it. Report was: {lines:#?}"
    );
}
```

**T2 — the page has not drifted from the CLI.** The `include_str!` idiom already
used by `crates/antseal-core/src/anchor/caps.rs:284` against
`docs/format/anchor-artifact-limits.md`; whitespace-normalized on both sides
because the CLI holds one long line and the page wraps at ~78 columns.

```rust
#[test]
fn the_funding_page_carries_the_wallet_custody_note() {
    const PAGE: &str = include_str!("../../../docs/user/funding-your-wallet.md");
    let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        squash(PAGE).contains(&squash(WALLET_CUSTODY_NOTE)),
        "docs/user/funding-your-wallet.md no longer carries `init`'s WALLET_CUSTODY_NOTE \
         word for word (whitespace-normalized). D148 §2 R2 makes that page the venue a \
         pre-funding reader meets this in, and vault-theft.md and vault-loss.md both \
         send the reader there — a page that has drifted from the CLI is exactly the \
         defect D148 §1.5 measured."
    );
}
```

**The plants, and the messages they must print.** Run each on a scratch copy;
record `REAL_EXIT=${PIPESTATUS[0]}` into a file and read it back, because a
nonzero exit alone is also what a compile failure gives.

| Plant | Expected red | Expected green | Message that must appear |
| --- | --- | --- | --- |
| **P1** delete `WALLET_CUSTODY_NOTE.to_owned(),` from `render()` | **T1** | **T2** | *"the wallet-custody note must be the line immediately after the address it qualifies"* |
| **P2** change one word inside the quoted block in `docs/user/funding-your-wallet.md` (e.g. `prepaid meter` → `prepaid metre`) | **T2** | **T1** | *"no longer carries `init`'s WALLET_CUSTODY_NOTE word for word"* |

If P1 reddens T2 as well, the tests are not independent and T1 is redundant; if
either plant reddens **neither**, the test cannot fail and must be rebuilt before
U83 is ticked. Both messages, and both `REAL_EXIT` values, go into **U83's Notes
in the act that ticks it** — a measurement that lives only in a transcript is not
evidence.

### R9 — Key-material guarantee, restated as what it rests on

No key bytes, and no value derived from key bytes, enter any file this ruling
touches. `WALLET_CUSTODY_NOTE` is a fixed string with no interpolation; the
`--json` document is unchanged; no fixture, snapshot, log line or error message
gains a wallet value; U21's harness is unmodified and its coverage is unnarrowed
(R1). Project **rule 6** — key-material hygiene, the tree-wide citation, **not**
`TODO.md`'s protocol rule 6 (§4.2) — is satisfied by construction, in the same
form `init.rs:241-242` already uses for the keyfile path.

### R10 — U83's Accept rows: which survive, which is inapplicable, which is amended

**Row 1** (*"The disposition is a recorded decision…"*) — **survives as written**;
this record discharges it.

**Row 2** (*"If any outbound route is added, it is consent-gated, prints a
fingerprint or a path rather than key bytes…"*) — **survives as written and is
INAPPLICABLE, not met.** Its antecedent is false: R1 adds no outbound route. Record
it the way U33's rows 2 and 3 were recorded — a conditional whose condition did
not obtain — never as a satisfied row, because that would assert a consent gate
exists.

**Row 3** (*"The mitigation appears where it can still be acted on: `init`'s report
and `docs/user/funding-your-wallet.md`, not only `docs/user/vault-theft.md`"*) —
**survives as written and becomes the row's core**; R2 and R3 discharge it.

**Row 4** — **AMENDED. Replace verbatim:**

> - `docs/user/vault-theft.md:258-274` is **corrected, not merely re-read**: its
>   inbound-route sentence (`:259-262`) names `--wallet import` as how the key
>   arrives while its own cited evidence
>   (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:52-65`) prints
>   `[default: generate]`, and its causal claim at `:269-271` — *"This is why
>   `funding-your-wallet.md` says to keep the balance small"* — attributes a
>   reason that page does not give (measured 2026-08-18: `:116-119` attributes
>   the same advice to public linkability, `wallet-hygiene.md`'s subject). Both
>   are repaired per D148 §2 R4, and the page is re-read afterwards and left
>   true.

**New row 5 — ADD verbatim:**

> - `docs/user/funding-your-wallet.md` and `init`'s report cannot drift apart:
>   one named constant is the source of both, asserted by a test that reads the
>   page with `include_str!`, with a planted fault red **by message** in each
>   direction (D148 §2 R8).

**New row 6 — ADD verbatim:**

> - `docs/user/vault-loss.md:64-67`'s *"See `funding-your-wallet.md`"* resolves to
>   text that exists, and says what a surviving backup does and does not give
>   you (D148 §2 R5).

---

## 3. The arms refused, and why each lost

### 3.1 Arm (b) — show the generated key (or its export path) once at `init`

Refused on four independent grounds, only the first of which the lean gives.

1. **It contradicts a spec-listed mitigation.** `MVP-SPEC.md:184` names *"wallet
   key inside the vault"* as part of the response to *"Vault loss AND vault
   theft"*. Displaying it at `init` puts a spendable secp256k1 key in a terminal
   scrollback, a `script(1)` capture, a tmux buffer and a CI log at the exact
   moment the user is least prepared to handle one.
2. **It creates a disclosure surface U21 would then have to be taught to
   tolerate.** The harness's central assertion is that no wallet-key sentinel
   appears in any byte the process emits. Arm (b) makes that assertion false by
   design, and the repair is an exemption — a hole in the one instrument that
   proves rule 6 at runtime.
3. **It does not discharge the risk it is offered for.** A key displayed once at
   `init` and not written down is a key not held; a key displayed and written
   down is a second copy in exactly the place — the same laptop — whose theft is
   the scenario.
4. **It buys nothing for the `import` user and nothing for the careful
   `generate` user**, and the careless `generate` user is the one it would harm
   most.

A weaker variant — print the address, a fingerprint or a derivation path rather
than key bytes — was weighed and is **already shipped and insufficient**: `init`
prints the EIP-55 address today (`init.rs:256`), and the address is precisely
what does **not** help; the missing capability is the private scalar. A
fingerprint of a secret you cannot obtain identifies a key you still cannot
spend. **Showing a non-secret does not discharge a secret-custody obligation.**

### 3.2 Arm (c) — a consent-gated maintainer-side wallet-key export

Refused, and the sharpest reason is a **timing** one the lean does not state.

- The spec already names the direction and it is not this: *"external-signer
  support may come later"* (`MVP-SPEC.md:143`), echoed by U10's own `Do` —
  *"future external-signer support can remove it cleanly"* (`tasks/U.md:172`).
  The right end state is **antseal not holding a spendable key**, not antseal
  handing one back.
- A consent-gated export makes the vault *"a single artifact holding both the
  sealing keys and a spendable key in retrievable form"* — the row's own words —
  and the gate protects only against the honest user. The thief who holds the
  vault and the passphrase satisfies every consent prompt antseal can pose.
- It would be **new surface added during a release freeze**: a subcommand, an
  exit-code class, a `--json` contract, a consent flow, U21 arms, a `--help`
  re-bless of a U1-frozen snapshot, and a positioning review — against U32's
  in-flight freeze and while the ship path is already blocked on Q65.
- And the risk it addresses is bounded by R2/R3's copy for anyone who reads it,
  which is a far smaller change with a far smaller blast radius.

### 3.3 Arm (a) as literally written — "accept the dead end permanently"

Refused **as a description**, accepted as a disposition. §1.4 and §1.5 show the
dead end is (i) narrower than the row states — a backup keeps the funds
**spendable**, and only *sweeping* is impossible — and (ii) undocumented where it
counts, with two pages already asserting otherwise. "Accept permanently" would
have licensed doing nothing but adding a sentence; what is actually owed is a
repair of a broken cross-reference plus the honest, narrower statement.

### 3.4 The arm the brief invited and this record refuses to open — a documented external-extraction procedure

The brief asked whether a documented `vault export`-based sweep, executed with an
external tool, could be the answer with zero new code. Measured, the mechanism
exists (§1.3: payload key 3 is the raw 32 bytes under one passphrase-keyed AEAD),
and it is **refused** anyway:

- **It is not zero-cost.** The payload map numbering is documented nowhere outside
  `crates/antseal-cli/src/vault/export.rs`; publishing a procedure means
  publishing that schema as a user-facing contract, which is a D47 format event by
  the back door and makes every later payload key a compatibility question.
- **It cannot be shipped as a script.** A committed tool whose output is a wallet
  private key is a rule-6 hazard in the repository and a `secret-guard` exclusion
  event, and an uncommitted one in a document is a maintenance liability nothing
  tests.
- **It is unavailable to exactly the users the theft page steers toward.**
  `vault export` refuses a keyfile-wrapped vault (`export.rs:744-756`), and
  `vault-theft.md`'s own closing advice is *"treat the keyfile wrap as the default
  this time"*.
- **The honest ratio is bad.** It serves the technical user who both made a backup
  and can run a KDF-plus-AEAD script, and it teaches every reader that the key is
  extractable — which is the disclosure arms (b) and (c) were refused for,
  arriving as prose.

**Recorded so it stays refused deliberately, not forgotten:** the capability is
real, and if a future decision wants it, the shape is *make the export format's
payload a documented contract first*, not *write a recipe against an internal
schema*.

### 3.5 The variant refused inside the winning arm — branching the `init` line on `wallet_source`

`InitReport.wallet_source` exists (`init.rs:217`) and is already in `--json`, so a
two-branch line would have cost no plumbing. Refused anyway:

- **It doubles what U78 must pin.** A conditional block means the golden covers
  one branch and leaves the other unpinned, or U78 grows a second golden — a cost
  imposed on a sibling lane by a lane that could avoid it.
- **The unconditional sentence is true in all four combinations** of
  generate/import × wrap-none/keyfile, and states the `generate`-specific fact
  inside its own prose (*"If antseal generated the key…"*) rather than in a code
  branch. Prose conditionals need no test matrix.
- The `import` user's full position is stated on the page (R2, third bullet) and
  in the theft page (R4b), where a reader who wants the detail is already looking.

---

## 4. Corrections this record makes

### 4.1 To the row and to `docs/user/vault-theft.md` — the read-site enumeration is incomplete

Both the row (`tasks/U.md:1190`) and the page (`vault-theft.md:262-265`) say the
key *"is read only to sign a payment (`commands.rs:381`, `:387`) or to be copied
into a `vault export` (`export.rs:761`)"*. Measured (§1.1), there is a **third**
production read: `crates/antseal-cli/src/backend.rs:699` → `:717`, opening the
payment RPC under `#[cfg(feature = "ant-backend")]` — the feature that every
paying build carries. The **conclusion** (no outbound route) is unaffected: it is
another *use*, not an exit. But the enumeration **is** the evidence for the
absolute claim, and an incomplete enumeration offered as an exhaustive one is this
project's most-found defect. R4 does not require the page to list all three; it
requires the page not to say *"only"* about a set it did not finish counting, and
the R4(b) replacement drops that word.

### 4.2 To this lane's brief — "project rule 6" is not a mis-citation

The brief instructed: *"`TODO.md`'s protocol rule 6 is Milestone fidelity, which
does not fit, so this is likely a mis-citation; if so, name the rule that was
meant and correct the citation."* **The row's citation is correct and the brief's
suspicion is wrong.** `project rule 6` is a tree-wide convention meaning
**key-material hygiene** — *secret material (`W`, unit keys, salts) lives only in
the vault, never in logs, error messages or test fixtures* — and it is cited under
that meaning in at least 39 places, including the wallet module's own heading
(`crates/antseal-net/src/wallet.rs:47`, *"# Key-material hygiene (project rule
6)"*), `D39:48`, `D44:62`, `D10:451`, `D67:154` (*"rule 6's secret class is `W`,
unit keys, salts"*), `D88:262`, `D144:332`, `init.rs:241-242`, and every
`testdata/**` NON-SECRET banner. The two numbering schemes coexist: `TODO.md`'s
numbered list is the **protocol**, and `project rule N` is the **project**
convention. Nothing here needs correcting except the brief.

### 4.3 New row candidate — `init`'s keyfile copy describes an export that will refuse to run

Nominated as a row in the U domain, size XS, in the form D134 §4 used for U77 —
**not** an `**Owner:`-form assignment, because the row does not exist yet and a
ruling owned by an unregistered id reds `decision-owners`.

`crates/antseal-cli/src/vault/keyfile.rs:286-290` — printed by `init` for every
keyfile-wrapped vault — says *"Back it up separately too — `antseal vault export`
does NOT contain the keyfile, only the fact that one is required."* That describes
an export that **runs and omits something**. Measured, `export_vault_impl` refuses
before reading a single record for any non-zero wrap mode
(`crates/antseal-cli/src/vault/export.rs:744-756`), telling the user to *"Back up
the vault directory and the keyfile separately by hand"*. The guarding test
(`keyfile.rs:404-414`) asserts the copy contains *"does NOT contain the keyfile"* —
the copy checked against itself, blind to the refusal. `docs/user/vault-loss.md`
already carries a correct section on this (`:166`, *"If your vault uses a keyfile,
`export` refuses"*), so the docs know and the CLI does not. **A shipped, false,
user-facing sentence is a product defect and mints a row under rule 8, not a
ledger entry.** It is adjacent to U78 (same report) and to this record, and is
deliberately **not** fixed here: it needs its own read of `LOSS_WARNING`, whose
*"Run `antseal vault export` and keep the backup somewhere else"* is arguably
false for the same class of vault and is a **spec-mandated, byte-frozen constant**
(`MVP-SPEC.md:143`, quoted verbatim at `docs/user/vault-loss.md:25`) — which is a
bigger event than one page's sentence and must not be taken as a side effect of a
wallet-custody ruling.

### 4.4 A disambiguation, recorded because greping for it returns the wrong answer

*"External signer"* has two unrelated meanings in this repository, and
`MVP-SPEC.md:143`'s *"external-signer support may come later"* is the **second**:

1. **The ant-core payment flow**, `prepare → pay → finalize`, driven
   programmatically **with the vault-held key** — shipped since S6, and what
   `rg external.signer` overwhelmingly returns (`tasks/S.md:80`, `:95`,
   `docs/research/S1-ant-core-api-survey.md:198-241`,
   `docs/dependency-policy.md:23`).
2. **A user-facing external signer** — a wallet or device that holds the key
   *instead of* the vault. `tasks/S.md:88` states the boundary explicitly:
   *"External-signer API is driven programmatically with the vault key —
   user-facing external-signer wallets stay parked per spec."*

A reader who greps and finds sense (1) everywhere could conclude the parked item
already ships. It does not, and sense (2) is the direction §3.2 defers to.

### 4.5 To the row's own framing

The row's title — *"After vault theft there is no route to the payment wallet"* —
is stronger than the measurement supports and should be read with §1.4 beside it:
there is no route **out**; there is a route **through**, from any backup. The row
does not need rewriting (it is a title, and its body is otherwise accurate to the
locators), but any copy derived from it must not repeat the stronger claim, which
is why R2 and R4 spell out both halves.

---

## 5. What this record does NOT cover

1. **Its own register and index rows.** This file makes `docs/decisions/` 140
   records against 139 index rows and reds `decision-index` until the registrar
   lands both. The registrar owes, in the commit that lands this file: the D148
   row in `docs/decisions/README.md` (ascending id order; status word `RESOLVED`;
   date `2026-08-18`, matching this record's `- **Status`/`- **Date` lines, which
   are the fields `check_decision_index` actually parses), the D148 entry in
   `TODO.md`'s Decision register, and **`D148 §2` written into U83's `TODO.md`
   row** — required, not optional, because §2 carries an `**Owner: U83**`
   assignment and `check_decision_owners` (`scripts/check-traceability.py:1524`)
   reds when the owner's row never names the decision.
2. **The `placement_guidance` / `LOSS_WARNING` versus export-refusal defect**
   (§4.3). Found here, evidenced here, ruled **out of scope** here. It needs its
   own row and its own read of a spec-mandated constant.
3. **U78's golden itself.** R7 states the one line and its position; it does not
   write, bless or review the golden rendering, and it does not touch
   `crates/antseal-cli/tests/snapshots/`.
4. **Any format event.** D47's export format is untouched: no wrap-carrying
   export header (D47 names that a format event), no payload key added, moved or
   published as a contract (§3.4), no `EXPORT_FORMAT_VERSION` change.
5. **Any decision about a user-facing external signer**, which `MVP-SPEC.md:143`
   parks and §3.2 defers to. This record neither schedules it nor rules its shape.
6. **`funding_lines`'s unused `address` parameter** (`init.rs:323`, `let _ =
   address;`). Noticed while measuring §1.6; it is not a user-visible defect and
   is not this record's business.
7. **Any cross-reference to `wallet-hygiene.md:310`'s *"Do not sweep leftovers
   between them"***. It is consistent with this ruling — a sweep route would be
   advised against on privacy grounds even if one existed — but linking the two
   pages is a docs decision nobody has asked for.
8. **Any gate run.** `scripts/local-gate.sh` and every script's `--self-test` mode
   stage a full tree copy and are banned mid-wave with sibling lanes live; no
   `cargo` build or test was run by this lane. `python3
   scripts/check-traceability.py` was run flagless (§1.8) and is the only
   whole-tree instrument this record executed. The implementing lane owes the
   `cargo test -p antseal-cli` runs, both plants (R8), `cargo clippy`, and
   `scripts/check-copy-style.py` after U78's golden exists.
9. **Whether the balance a user should keep is quantifiable.** The ruled copy says
   *"like a prepaid meter, not a savings account"* and deliberately names no
   figure: `docs/user/funding-your-wallet.md:121-124` records that **no Arbitrum
   One price has ever been measured**, and inventing a number here would violate
   that page's own standing refusal.
