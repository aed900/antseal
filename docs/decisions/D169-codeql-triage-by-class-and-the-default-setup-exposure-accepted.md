# D169 — CodeQL's 66 alerts are triaged **by class** into a committed record, with **no secret reaching any sink and no production key literal**, one true finding with no security effect, and a scanner shown **nondeterministic on identical code**; default setup **stays**, with its tag-resolution exposure **accepted for a stated reason rather than declared absent**

- **Status: RESOLVED. The lean's conclusion survived and every one of its
  premises fell; the orchestrator's counter-lean on the setup question was
  half-destroyed in a challenge round and the half that survived is the ruling.**
  - **What held, and the test that could have broken it**: no secret reaches any
    sink, there is no production key or salt literal, and the JavaScript finding
    is not in the verifier page. Checked across all **29** (alert, source) pairs,
    plus four checks CodeQL cannot make: every secret type's `Debug`
    implementation, `tracing` call sites, a scan for key-sized literals, and which
    Cargo features production builds enable. §1.2–§1.4.
  - **Premise 1 falls**: none of the 44 hard-coded values is a label, an HKDF info
    string or a TSA root. Four are zero-initialised output buffers in production
    code, fully overwritten before use; the other forty are test fixtures, thirteen
    of them nonces copied from real TSA captures. **The mint's "20 test / 24
    non-test" split is wrong — measured 40 / 4** — because CodeQL's path heuristic
    does not see `#[cfg(test)]` modules inside `src/`. §1.2.
  - **Premise 2 falls**: the three production cleartext alerts are **not**
    name-driven. They start at real secrets (`collect_passphrase` at seven call
    sites, `obtain_passphrase`, the wallet key's `read_secret_line`, the generated
    keyfile secret) and are false only because taint over-approximates through
    `?`, tuple destructuring and enum construction while the sinks print a count
    and a path. §1.3.
  - **"All false positives" falls by one**: alert #6 is a true no-op in a build
    script. It has no security effect. §1.5.
  - **The alert set is not stable**: two alerts went `fixed` on a commit that
    changed no Rust, with the extractor inputs, CLI version and query packs
    identical. **`fixed` is not a witness.** §1.6.
  - **The setup question**: the planning lane recommended an in-repo advanced-setup
    workflow; the orchestrator's counter-lean argued the exposure was absent.
    **The challenge withdrew the advanced-setup recommendation and destroyed the
    "absent" argument**: default setup resolves action **tags** at run time, which
    is precisely D143's adversary A2, the one pinning defends against. §1.7, §2 R4.
- **Date: 2026-09-13**
- Owner rows: **`Q271`** (stays OPEN on one residue — the consented dismissals,
  §2 R5); **`Q244`** (its reader meets the exemption, §2 R4); **`Q255`** (carries
  the first reopen trigger as an `Accept` term, §2 R4).
- Related: **D129** §7 (bundle-derived content is never written by `innerHTML`),
  **D141**/**D143** (every `uses:` in `.github/workflows/` pinned to a commit;
  D143's adversary table, A1 "GitHub the platform" and A2 "write access to an
  action repository short of A1"), **D73** R7 (the metric vault's salt), **D156**
  §2 R1, **`Q244`**, **`Q255`**.

## 0. What was measured against

`HEAD` `ef5f6d9`. CodeQL default setup's analyses at `cac8e6d`, `4a7f524` and
`ef5f6d9` (SARIF downloaded with read-only GETs), both default-setup job logs, the
alert API, and source reading (planning lane A, wave 35), followed by a challenge
round on the setup question. No alert was dismissed and no setting was changed.
Every per-alert verdict lives in `docs/reviews/codeql-triage-2026-09-13.md`, which
the implementing lane re-verified against source before recording.

## 1. What was measured

### 1.1 The census

66 alerts = 64 open + 2 `fixed`.

| rule | total | classes |
|---|---|---|
| `rust/hard-coded-cryptographic-value` | 44 | H-OUTBUF 4 · H-FIXTURE 27 (25 open + 2 fixed) · H-NONCE 13 |
| `rust/cleartext-logging` | 13 | L-PROD 3 · L-TEST 10 |
| `py/clear-text-logging-sensitive-data` | 5 | P-NAME 5 |
| `rust/weak-sensitive-data-hashing` | 2 | W-PROTOCOL 2 |
| `js/unvalidated-dynamic-method-call` | 1 | J-DRIVER 1 |
| `js/identity-replacement` | 1 | J-TRUE-NOOP 1 |

By verdict: **14 false positive + 49 used in tests + 2 already fixed + 1 true = 66.**

### 1.2 Hard-coded values

- **H-OUTBUF** (#26 `vault/keyfile.rs:261`, #27 `session.rs:160`,
  #35 `metric_vault_fp.rs:414`, #46 `crypto/hkdf.rs:221`): zero buffers fully
  overwritten before use; a failed write returns an error or panics, so an
  all-zero value never escapes.
- **H-FIXTURE**: inside `#[cfg(test)]` modules or `tests/`.
- **H-NONCE** (#52–#64): nonces from committed real TSA captures, compiled only
  through `#[cfg(test)] #[path = …]`.
- The key-sized literals that **do** reach production are public by construction:
  pinned root fingerprints and Ed25519 group constants. Every other literal is
  behind `test-vectors`, which the shipped crates enable only as a
  `[dev-dependencies]` feature under `resolver = "3"`. **Corrected before this
  record landed, by the implementing lane:** `crates/wasm-bitmatch` (a
  `publish = false` harness) enables `test-vectors` under `[dependencies]`, so a
  `--workspace` build unifies the feature in; a `-p antseal-cli` build receives only
  `default` (`cargo tree -e features,normal`), and D72's release build is
  `cargo build --release -p antseal-cli`. The production verdict is unchanged for
  the release binary and holds only for `-p`-scoped builds.

### 1.3 Cleartext logging

- **L-PROD #19**: its sink is `Outcome::raw(`, which has **one** call site, in
  `verify` — a handler that opens no vault and never prompts; every
  passphrase-taking command returns through `Outcome::value`.
- **L-PROD #18, #20**: the printed value is `ImportSummary`, which holds a vault
  directory path, a work count and two booleans.
- The init sources cannot leak: `InitReport` holds no secret field and its JSON
  deliberately omits key material; the wallet-import error is `Copy` and carries
  only a length.
- Every secret type prints redacted (`SecretBuf`, `MasterSecret`, `FileSalt`,
  `KeyfileSecret`, `WalletKey`, and the `Key32`/`Seed32`/`Salt16` macro).
- **The `passphrase_source` closure finding covers only the `vault/export.rs`
  flows in #18/#19/#20**, not the keyfile flows, the init sources or the other six
  `collect_passphrase` sites. The verdicts rest on what each sink prints, never on
  a variable's name.

### 1.4 The rest

- **P-NAME**: the Python source is the `NON_SECRET` disclaimer string and the
  output is a committed public vector document.
- **W-PROTOCOL**: SHA-1 over a public certificate because RFC 2634 §5.4 fixes it
  for ESSCertID v1; compared against the TSA's value, protecting nothing.
- **J-DRIVER #7**: `scripts/verifier-page-browser.mjs` dispatches through a `Map`
  that can only return handlers the script itself registered; a local-only CDP
  driver, not page code.

### 1.5 The one true finding

#6: `scripts/verifier-page-pack.mjs` performs `replace(/'/g, "'")` — a no-op — on
the list of CSP tokens it refuses. It changes no behaviour, and the loop it sits in
had **no planted fault**: nothing proved the packer refuses `'unsafe-inline'` or
`'unsafe-eval'`.

### 1.6 Nondeterminism

#24 and #48 (both at `crypto/hkdf.rs:482`, inside `mod tests`) went `fixed` at
`ef5f6d9`. `git diff --quiet cac8e6d ef5f6d9 -- crates/` exits 0; SARIF at
`cac8e6d` and `4a7f524` is identical (59 results) and `ef5f6d9` lacks exactly those
two, which share one `primaryLocationLineHash`; same CLI 2.27.0, same query packs,
same action commit, 404 extractor inputs both times — and the database relations
shrank from 259.94 to 259.23 MiB. The mechanism is not established.

### 1.7 Default setup

- State: `configured`, query suite `default`, threat model `remote`, schedule
  `weekly`.
- Its job log resolves `actions/checkout@v6` and `github/codeql-action/*@v4` **by
  tag at run time**.
- Its token: `Actions: read, Contents: read, Metadata: read, Packages: read,
  SecurityEvents: write`, plus Actions cache **write**, on push to `main`.
- `scripts/check-action-pins.py` globs `.github/workflows/*.yml` and is
  structurally blind to it.
- GitHub's changelog (2025-11-25): default setup runs even under Actions policies
  restricting workflows, and *"the only actions policy that still affects this
  workflow is `Disable actions`"* — so arming `sha_pinning_required` will neither
  break nor cover it.
- A default-setup configuration file needs a custom repository property; on this
  user-owned repository the properties endpoint answers 404, so no query filter or
  path exclusion is available — and `Q271` bars both anyway.

## 2. RULING

### §2 R1 — Triage is by class, recorded in the repository

The committed record `docs/reviews/codeql-triage-2026-09-13.md` is the evidence
home: a per-class table summing to 66 and a per-alert table. GitHub dismissals
**mirror** it, one reason per class (`false positive` for H-OUTBUF, L-PROD, P-NAME,
J-DRIVER and the production W-PROTOCOL hit; `used in tests` for H-FIXTURE, H-NONCE,
L-TEST and the test W-PROTOCOL hit), and are executed only under the maintainer's
in-the-moment consent. **No rule is disabled and no path is excluded to reduce the
count. An alert that reappears after `fixed` is re-dismissed by its class rule and
is never read as evidence of a regression or of a fix** (§1.6).

### §2 R2 — #6 is fixed and the refusal loop is proven

The no-op is removed, and the packer's self-test gains two arms judged by message —
`'unsafe-inline'` and `'unsafe-eval'` each injected and refused — plus a planted
fault that empties the refused list and must turn the self-test red. No
"fails before, passes after" test exists for a deletion that changes no behaviour,
and that is recorded rather than manufactured.

### §2 R3 — D129 §7 gains an enforcement

`crates/antseal-wasm/tests/page_template.rs` refuses `innerHTML`, `outerHTML`,
`insertAdjacentHTML` and `document.write` in the page template's executable code,
with its treatment of comments stated and its blind spot named. CodeQL's zero
JavaScript alerts on the template are not coverage of bundle handling; this test
is.

### §2 R4 — Default setup stays; the A2 exposure is ACCEPTED, never written as absent

**Scope, conceded to the counter-lean**: D143 §2 R1 and `Q244`'s `Accept` row 1 rule
on *"every `uses:` in `.github/workflows/`"*; nothing in D141, D143 or `Q244`
extends the rule to every action a repository runs. **Exposure, conceded to the
challenge**: default setup resolves tags at run time, so a re-pointed tag in
`actions/checkout` or `github/codeql-action` is adversary **A2**, and the code on
it would hold `SecurityEvents: write` — enough to upload or suppress SARIF and
dismiss alerts, i.e. to falsify the instrument this record relies on — and cache
write on `main`, where `pages.yml` restores a cache inside its write-scope job.
**Accepted, for three reasons**: D143 weights A2 as narrow; a more direct A2 path
(the pinned `upload-pages-artifact` calling `actions/upload-artifact@v4` by tag
inside the write-scope job) stays open until `Q255` lands, so replacing default
setup would not reduce today's worst exposure; and the advanced-setup arm's cost
includes an unestablished question — whether alert numbers and dismissals survive
the switch — that would hold this row's close hostage.
**Where the reader meets it**: `Q244`'s Notes, the header of
`.github/action-pins.tsv`, and a scope sentence in `scripts/check-action-pins.py`
(*workflow files only; GitHub-managed dynamic workflows are out of scope — D169*).
**Reopen triggers**, any one of which returns this to a decision: **(1)** `Q255`
ticks — default setup then becomes the last A2-exposed code on `main` with cache
write, so `Q255`'s `Accept` gains the term *"D169 §2 R4 is re-decided in the act
that ticks this row"*; **(2)** default setup's token gains any further write scope;
**(3)** the first default-setup run after `sha_pinning_required` is armed does not
execute normally; **(4)** an A2 incident is disclosed for either action.

### §2 R5 — `Q271`'s `Accept`, clause by clause

Row 1 (*every alert reaches a state with a reason recorded against its class*):
the reason half is met by §2 R1's record; **the state half needs the consented
dismissals** and is the row's one residue, owned by `Q271`, timing *at the next
consented external act*. Row 2 (the thirteen cleartext paths): met — **29 (alert,
source) pairs**, not 13 paths, and the closure finding cited only for the flows it
covers. Row 3 (a real defect gets a failing-then-passing test): no security defect;
#6 recorded per §2 R2. Row 4 (the pinning question answered in writing, the
exemption where `Q244`'s reader meets it): met by §2 R4.

## 3. Fault plants

The two packer arms and the emptied-list plant (§2 R2); the template guard's
planted `el.innerHTML = x` with the real template as green control (§2 R3). Each
judged by its own message.

## 4. What this record does NOT decide

- **`metric_vault_fp`'s salt reader accepting an all-zero salt.** Observed by the
  planning lane; whether D73 R7 requires refusing it is answered by the implementing
  lane and becomes a row only if it is a product defect.
- Pinning the CodeQL bundle (`tools:`), and whether alert identity survives a setup
  switch — both unestablished, both reopened with §2 R4.
- The dependency graph parsing `requirements-crosscheck.txt` as a pip manifest.

## 5. Edit list — per write scope, with the lane named before this record was written

### W3 (the CodeQL lane)
- `scripts/verifier-page-pack.mjs` per §2 R2.
- `crates/antseal-wasm/tests/page_template.rs` per §2 R3.
- `docs/reviews/codeql-triage-2026-09-13.md` per §2 R1.

### W1 (the CI lane)
- `.github/action-pins.tsv` header and `scripts/check-action-pins.py`'s scope
  sentence per §2 R4.

### Registrar — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`
- `Q271` Notes per §2 R5; `Q244` Notes per §2 R4; `Q255`'s `Accept` gains §2 R4's
  first reopen term; `Q244`'s `Accept` row 2 amendment carried into `tasks/Q.md`,
  where only `TODO.md` holds it.
- `docs/instrument-ledger.md`: CodeQL's nondeterminism on identical code; the
  pin checker's blindness to dynamic workflows; the mint's path-heuristic 20/24
  split.
- Index row and register row for this record.

## Closing — this record is not consent

It dismisses nothing and changes no setting. **Sixty-three** dismissals, one per
alert, each carrying its class reason and citing the committed review record, are
named for the maintainer to consent to — #6 is fixed in code (§2 R2) and #24/#48 are
already `fixed`, so they are not dismissed (the planning lane's 64th call was a
fallback for #6, void once the deletion was taken; corrected before this record
landed). For the three production cleartext alerts, whose identity is their shared
sink, each dismissal comment states the source count it covers (3, 11, 3), because a
dismissal by sink would silently cover a source added later. Until then `Q271` stays
open on that residue alone.
