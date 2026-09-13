# CodeQL triage: 66 alerts, by class, re-verified against source

**Date**: 2026-09-13 · **Tree**: `main` at `ef5f6d9`, the analysed commit · **Ruling**: [D169](../decisions/D169-codeql-triage-by-class-and-the-default-setup-exposure-accepted.md) · **Row**: `Q271`
**Subject**: every code-scanning alert that CodeQL default setup raised in its first three analyses (`cac8e6d`, `4a7f524`, `ef5f6d9`, all 2026-09-12): 66 alerts, six rules, three languages. A fourth language, Actions, raised none.
**Instrument**: the three analyses' SARIF and both Rust job logs, fetched with read-only GETs; the alert API, captured by the wave-35 planning lane and re-read on 2026-09-13T01:41:16Z; source reading; `cargo tree`.
**Scope note**: this record **reports and proposes**. No alert was dismissed and no setting was changed. The code that lands beside it is the #6 fix and a guard for D129 §7 (§5, §6).

## Verdict

**No secret reaches any sink, and no production key or salt is a literal.** 14 false positive, 49 used in tests, 2 already `fixed`, and 1 true finding with no security effect: #6, fixed in the same act.

Three measurements matter more than the count:

- **The mint's "20 test / 24 non-test" split is wrong. Measured, it is 40 / 4.** CodeQL's `test` classification follows file paths and does not see `#[cfg(test)]` modules inside ordinary `src/` files (§3).
- **The alert set does not depend only on the code.** Two alerts went `fixed` on a commit that changed two Markdown files, with the same tool, queries and inputs. `fixed` is not a witness (§4).
- **At a shared sink, a dismissal covers more than what was read.** #19 is one alert carrying eleven sources. Dismissing it records a verdict on those eleven, and the same alert would also hold a twelfth source added later (§8.1).

---

## 1. Scope and method

### 1.1 The subject

| analysed commit | Rust | JavaScript/TypeScript | Python | Actions |
|---|---:|---:|---:|---:|
| `cac8e6d` | 59 | 2 | 5 | 0 |
| `4a7f524` | 59 | 2 | 5 | 0 |
| `ef5f6d9` | 57 | 2 | 5 | 0 |

All three ran CodeQL 2.27.0 under default setup. The alerts are #1 to #66: 64 are open, with their most recent instance at `ef5f6d9`, and 2 are `fixed`, last seen at `4a7f524`. A GET on the day returned 66 alerts (64 open, 2 fixed, 0 dismissed), with **no difference** from the planning lane's capture in number, state, rule, path, line, commit or dismissal reason.

### 1.2 How a verdict was reached

- **Rust code outside tests (8 alerts: #18 to #21, #26, #27, #35, #46).** The sink was read at its line and column. Every source named in the SARIF message was resolved to its line, and the flow was followed to what actually gets printed or used.
- **Tooling scripts (7 alerts: #1 to #7).** The source and the sink were read, along with what the script's output is.
- **Test-only Rust (51 alerts: 49 open, 2 fixed).** For each, the enclosing scope was established: a `tests/` directory, or the `#[cfg(test)]` item around the line. That item was found with a brace matcher that skips strings, character literals and comments, and then spot-read. Each `#[path]` module was traced to its `#[cfg(test)]` declaration in the parent.
- **A name is never evidence.** A variable named `secret` inside a leak guard and a string named `NON_SECRET` were both read for what they actually hold.

### 1.3 Four checks CodeQL does not make

These came from the planning lane. The last column says what this record re-ran.

| check | why the query cannot answer it | result | re-run here |
|---|---|---|---|
| `Debug` of each secret type | a `{:?}` prints whatever the type's impl writes, and the query sees only the variable | `SecretBuf`, `MasterSecret`, `FileSalt`, `KeyfileSecret` and `WalletKey` each write `<redacted>`; the planning lane adds the `Key32`/`Seed32`/`Salt16` macro | the five named types; the macro was not re-read |
| `tracing` call sites | logging through `tracing` macros is not the sink set the query models | planning lane: none of them logs secret material | no |
| key-sized literals in production code | the query flags only values that flow into a key or salt parameter | planning lane: only pinned root fingerprints and Ed25519 group constants | no |
| features enabled in production builds | whether a literal behind `test-vectors` reaches a shipped binary is a Cargo question | `-p antseal-cli` builds `antseal-core` with `default` only; `--workspace` adds `test-vectors` (§8.3) | yes, with `cargo tree` |

### 1.4 Re-verification

The planning lane's 66 verdicts were re-derived, not transcribed. Two parts were read in full, as the brief required: the three L-PROD sinks and the four H-OUTBUF buffers. Also re-derived: the scope of every test alert, #10's `InitReport`, the P-NAME sources, the SHA-1 site, the CDP dispatch, the evidence for nondeterminism, and the 29 (alert, source) pairs. **No verdict was overturned.** Two statements carried into D169 need qualifying, and §8 records them.

---

## 2. By class

| class | rule | alerts | state | verdict | basis |
|---|---|---:|---|---|---|
| H-OUTBUF | `rust/hard-coded-cryptographic-value` | 4 | open | false positive | zero-initialised output buffers outside test code: each is filled completely before use, or never used |
| H-FIXTURE | `rust/hard-coded-cryptographic-value` | 27 | 25 open, 2 fixed | used in tests | inside `tests/` or a `#[cfg(test)]` item |
| H-NONCE | `rust/hard-coded-cryptographic-value` | 13 | open | used in tests | 8-byte TSA request nonces that committed real captures echo back, compiled only through `#[cfg(test)] #[path = …]` |
| L-PROD | `rust/cleartext-logging` | 3 | open | false positive | the sources are real secrets; what the sinks print is a count, a path, or `verify`'s result document |
| L-TEST | `rust/cleartext-logging` | 10 | open | used in tests | test-only: leak guards, redacted `Debug`, lengths, diagnostic codes |
| P-NAME | `py/clear-text-logging-sensitive-data` | 5 | open | false positive | the source is the `NON_SECRET` disclaimer; the output is a committed public vector document |
| W-PROTOCOL | `rust/weak-sensitive-data-hashing` | 2 | open | #21 false positive, #22 used in tests | RFC 2634 §5.4 fixes SHA-1 for ESSCertID v1, and the input is a public certificate |
| J-DRIVER | `js/unvalidated-dynamic-method-call` | 1 | open | false positive | dispatch through a `Map` in a local CDP driver |
| J-TRUE-NOOP | `js/identity-replacement` | 1 | open | true, no security effect | fixed in code (§5) |
| **total** | | **66** | 64 open, 2 fixed | **14 false positive · 49 used in tests · 2 fixed · 1 true** | |

---

## 3. The 40 / 4 correction

The mint recorded "20 test / 24 non-test" for the 44 hard-coded values. That is CodeQL's own `classifications` field, which comes from a path heuristic:

| where the value is | alerts | tagged `test` by CodeQL |
|---|---:|---:|
| a `tests/` directory | 5 (#28 to #31, #51) | 5 |
| a `tests.rs` module file declared `#[cfg(test)] #[path = …]` | 13 (#52 to #64) | 13 |
| `anchor/testing.rs`, inside `#[cfg(test)] mod tests` | 2 (#65, #66) | 2 |
| a `#[cfg(test)] mod tests { … }` inside an ordinary `src/` file | 20 (#23 to #25, #32 to #34, #36 to #45, #47 to #50) | **0** |
| code compiled outside tests | 4 (#26, #27, #35, #46) | 0 |

That makes **40 test-only and 4 outside tests**. CodeQL missed exactly the 20 values sitting in test modules inside `src/` files. The four exceptions are the only hard-coded alerts outside every `#[cfg(test)]` span and every `tests/` directory. Each one points at the zero initialiser of a buffer, not at the value next to it: #27 is the buffer on `session.rs:160`, not the empty HKDF salt on `:159`.

- **#26 and #27.** `hkdf` 0.13.0, the workspace pin, has `expand` return `InvalidLength` *before writing* when the output exceeds 255 × HashLen. Otherwise it `copy_from_slice`s every block. The two call sites map that error and return with `?` before the buffer becomes a key.
- **#46.** `hkdf_expand` calls `.expect` on that same `Result`, so a failure panics and never returns zeros.
- **#35.** The hex branch of `read_salt` runs only when the input is exactly `SALT_LEN * 2` characters, so `chunks_exact(2)` produces exactly `SALT_LEN` pairs. The loop assigns every slot or returns `SaltShape`.

---

## 4. `fixed` is not a witness

#24 and #48 sit on `crypto/hkdf.rs:482` at columns 32 and 60. They are the two operands of `assert_eq!(hmac_sha256(b"", &TEST_W), hmac_sha256(&[0u8; 32], &TEST_W))` inside `mod tests`. Both were reported at `cac8e6d` and `4a7f524` but not at `ef5f6d9`, so GitHub marked them `fixed`. Nothing was fixed:

| | `4a7f524` | `ef5f6d9` |
|---|---|---|
| `crates/` tree | `4451da70…` | `4451da70…` (the same at `cac8e6d`) |
| action | `github/codeql-action@v4` resolved to `b96794f0…` | same |
| CLI and Rust query pack | 2.27.0, `codeql/rust-queries` 0.1.42 | same |
| extractor inputs | 404 of 404 Rust files | same |
| database: relations, string pool, source archive | 259.94, 88.03, 47.54 MiB | **259.23**, 88.03, 47.54 MiB |
| Rust results | 59 | 57: exactly those two are gone, and they share `primaryLocationLineHash` `bcdbc536dc2c64ae:1` |

`git diff --quiet cac8e6d ef5f6d9 -- crates/` exits 0, and no file other than Markdown changed between those two commits. The `cac8e6d` and `4a7f524` SARIF files agree on rule, path, line, column and message for all 59 results.

**The mechanism is not established.** What is established: the same source, tool and queries produced a database 0.71 MiB smaller and two fewer results. D169 §2 R1 draws the consequence. An alert that comes back after `fixed` is re-dismissed under its class and is not read as a regression. An alert that goes `fixed` without a code change proves nothing about the code.

---

## 5. #6, the one true finding, and its fix

`scripts/verifier-page-pack.mjs:216` built each refused-token pattern from `refused.replace(/'/g, "'")`, which replaces a quote with a quote. The line now reads `` new RegExp(`(^|[\\s;])${refused}`) ``. A quote is not a regular-expression metacharacter, so the pattern is byte-identical and behaviour cannot change. For the same reason there is no "fails before, passes after" test for this deletion (D169 §2 R2).

What the alert did expose is that the loop had no planted fault: nothing had ever shown that the packer refuses either token. The self-test now has two arms. Each plants its fault **in the template and rebuilds the page**, because editing the built page alone trips the decomposition assertion first. That was measured on a scratch copy, which went red with `went red for the WRONG reason: … does not decompose back to the committed template`.

| run | result |
|---|---|
| baseline, before any edit | 3 arms RED, `self-test PASS`, exit 0 |
| two arms added, no-op still present | 5 arms RED, including `the policy carries 'unsafe-inline'` and `the policy carries 'unsafe-eval'`, exit 0 |
| no-op removed | the same 5, exit 0 |
| **plant**: refused list emptied | `::error::page-build self-test: the assertions stayed GREEN with script-src-attr 'unsafe-inline' — they are not checking anything`, and the same for `'unsafe-eval' beside 'wasm-unsafe-eval'`, exit 1 |
| **plant**: an arm whose edit matches nothing | `::error::page-build self-test: the planted fault "script-src-attr 'unsafe-inline'" changed nothing — the arm has no subject`, exit 1 |
| green control: the real build through the edited packer | exit 0, page byte-identical to the one the gate built at `ef5f6d9` (`73681650…`) |

The second plant tests a guard added together with the arms. When an arm's corruption leaves the state unchanged, the loop now reports that the plant did not apply, instead of blaming the assertions.

`'wasm-unsafe-eval'` occurs exactly once in each of the built page, the template and the self-test's page, always inside the CSP `content` attribute. The glue carries none. So the `'unsafe-eval'` arm is planted right beside the one eval token that must stay, and the real build is its counterpart. A match that is too loose (the unquoted `unsafe-eval`) would turn that build red. A match that is too tight (a boundary of `;` only) would leave the arm green.

---

## 6. What CodeQL's silence on the page does not cover

Neither JavaScript alert is in the verifier page. That does not show the page handles bundle text safely. D129 §7 is a rule about how the page writes to the DOM:

> All bundle-derived text reaches the DOM by `textContent`, extending D66 §3 R5.3's rule from endpoint strings to every sealer-authored string the page renders; the CSP is the second line, not the first.

Until now nothing enforced that rule mechanically. `crates/antseal-wasm/tests/page_template.rs` now refuses `innerHTML`, `outerHTML`, `insertAdjacentHTML` and `document.write`, and the last of these also matches `document.writeln`.

**Comments are scanned, not stripped.** A stripper that drops everything from `//` to the end of the line would also drop whatever follows `"https://` in live code, and the template has such lines. So the guard scans the whole template, which covers both of its `<script>` elements without needing a parser to find where they start and end. An occurrence is excused only when its bytes fall inside a pinned sentence. The template has exactly one: `// textContent (D129 §7), never by innerHTML.` The excuse applies to that match only, so code written on the same line as the comment still reds. A pin must occur exactly once, and it may not contain a quote, backtick, `*/`, angle bracket or newline, so no string, comment or element boundary can fall inside it.

**Blind spot.** Names are matched as written. The guard cannot see any of these:

- a computed name, such as `el["inner" + "HTML"]`;
- a `document` alias, or member access with spaces around the dot;
- a parser outside the list: `DOMParser`, `createContextualFragment`, `setHTMLUnsafe`, `srcdoc`;
- the wasm-pack glue, which is added at packaging and is not in the template (today it carries none of the four names).

| run | result |
|---|---|
| green baseline | `test result: ok. 11 passed; 0 failed` (9 existing tests, 2 new), exit 0 |
| **plant**: the guard's subject contains `el.innerHTML = x;` | `test result: FAILED. 10 passed; 1 failed`, with ``line 195: `innerHTML` in `el.innerHTML = x;` ``, exit 101 |
| **plant**: `innerHTML` removed from the list | the green control stays `ok`; the arm test fails with ``the guard stayed green over a planted `el.innerHTML = x;` … got: []``, exit 101 |
| **plant**: the exemption applies per line instead of per match | the arm test fails with `the exemption is per line, so one benign mention hides live code beside it`, exit 101 |
| **plant**: `//` treated as the start of a comment | the arm test fails with ``the guard is treating `//` inside a string as a comment``, exit 101 |
| final | `11 passed`, exit 0; `clippy -D warnings` on the crate's targets, exit 0 |

---

## 7. Proposed dismissals: NOT executed

Dismissing an alert is an external act on a public repository, and it needs the maintainer's consent at the time it is done. This record executes none and consents to none.

| class | alerts | reason | count |
|---|---|---|---:|
| H-OUTBUF | #26, #27, #35, #46 | `false positive` | 4 |
| L-PROD | #18, #19, #20 | `false positive` | 3 |
| P-NAME | #1 to #5 | `false positive` | 5 |
| J-DRIVER | #7 | `false positive` | 1 |
| W-PROTOCOL, outside tests | #21 | `false positive` | 1 |
| H-FIXTURE, open | #23, #25, #28 to #34, #36 to #45, #47, #49 to #51, #65, #66 | `used in tests` | 25 |
| H-NONCE | #52 to #64 | `used in tests` | 13 |
| L-TEST | #8 to #17 | `used in tests` | 10 |
| W-PROTOCOL, test | #22 | `used in tests` | 1 |
| **dismissals** | | | **63** |
| no dismissal | #24 and #48 (already `fixed`), #6 (fixed in code) | | 3 |

**That is 63, not 64.** The planning lane's plan has 64 calls: the 63 above, plus a `won't fix` for #6 marked *"Use ONLY if the one-line deletion is not taken"*. The deletion is taken, so that call should not run. #6 should close as `fixed` once default setup analyses a commit that carries the fix. That is expected, not established, and by §4 its closing proves nothing either way.

**Each dismissal comment should cite this record**, which D169 §2 R1 names as the place the evidence lives. The comments in the plan cite `tasks/Q.md` instead.

---

## 8. Findings beyond the alerts

### 8.1 A dismissal at a shared sink also covers sources nobody read

#19's message names eleven sources, but its SARIF result has code flows for only four of them. Its sink, `lib.rs:178`, is the entire alert. The other two L-PROD alerts name three sources each, and #18 and #20 are the two arms of `Ui::line`, a helper with twelve call sites in `commands.rs`. For those three alerts, then, "false positive" is a statement about the callers read on 2026-09-13, not about the line itself. A source that later reaches the same `println!` lands inside an alert that is already dismissed. Whether GitHub reopens a dismissed alert when its list of sources grows was **not measured**.

A cheap guard, if one is wanted: put the source count in each L-PROD dismissal comment (3, 11 and 3), so a changed message is noticeable. And do not apply D169 §2 R1's "re-dismissed by its class rule" to an L-PROD alert without reading its sources again.

### 8.2 The packer's refusal matches spelling, not CSP semantics

These probe builds used scratch copies of the template. Nothing tracked was changed.

| added to `script-src` | build |
|---|---|
| `'unsafe-eval'` (control) | exit 1, `the policy carries 'unsafe-eval', which D129 §6 refuses` |
| `'UNSAFE-EVAL'` | exit 0 |
| `&#39;unsafe-eval&#39;` | exit 0 |
| `https:` | exit 0 |

- **The uppercase spelling.** CSP3 grants eval when the source list has *"a source expression which is an ASCII case-insensitive match for the string "'unsafe-eval'"* (editor's draft, §4.4.1).
- **The escaped spelling.** An HTML parser decodes character references in an attribute value before the policy is read.

So by the spec both of those are grants. Neither was measured in a browser.

- **The extra `https:` source.** It passes because assertion 7 checks only that `script-src` *contains* its required sources. D129 §5 R9 item 7 says the directive carries *"exactly the hashes of the scripts actually present plus `'wasm-unsafe-eval'`"*.

Every one of these still needs an edit to the template before it can ship, and the decomposition assertion makes that edit visible in review. The template-side test at `page_template.rs:141` refuses `'unsafe-eval'` only when it appears as the adjacent string `script-src 'unsafe-eval'`. The `'unsafe-eval'` arm's policy therefore passes that test, and only the packer refuses it.

### 8.3 `test-vectors` has one enabler that is not a dev-dependency

D169 §1.2 says every other literal *"is behind `test-vectors`, which only `[dev-dependencies]` enable"*. But `crates/wasm-bitmatch/Cargo.toml` enables it under `[dependencies]`. Measured with `cargo tree -e features,normal`: `-p antseal-cli` builds `antseal-core` with `default` only, while `--workspace` adds `test-vectors`, pulled in through `wasm-bitmatch`. A shipped binary is affected only if the build that produces it also selects `wasm-bitmatch`. Which invocation builds release binaries is not established here.

### 8.4 The metric salt reader accepts an all-zero salt

D169 §4 handed this question to this record.

**The rule.** D73 §4 R7 says: *"`salt` is a single 32-byte random value generated once for the metric, held by the maintainer and **never committed**."* R7's privacy property depends on that: *"No reader can link a row to a bundle, a key, a work or a person, because the salt is secret."*

**No record requires refusing any particular salt value.** R7 governs how the salt is generated and kept. `docs/success-metric.md` restates it, and the only other mention is D169 §4. `read_salt` in `crates/antseal-core/src/bin/metric_vault_fp.rs` checks two things: length (32 raw bytes, or 64 hex characters once whitespace is removed), and on Unix, owner-only permissions (`mode & 0o077` must be 0). It accepts 32 zero bytes, or 64 `0` characters.

**This is not a product defect.** The binary requires `test-util`, which no production build enables. `docs/success-metric.md` has no filled row, so no fingerprint has yet been published under any salt.

**Its failure would be silent, though.** An all-zero salt, or any guessable one, lets anyone holding a participant's bundle recompute every `vault_fp` and `work_fp`. That is exactly the "committed salt" option R7 rejected, and the tool's output would look no different. A refusal in the tool could reject degenerate values only; no check can prove a salt is random. The natural place to close this is `Q35`'s salt-generation step.

### 8.5 Two sentences that are no longer accurate

- `metric_vault_fp.rs:131-136` says `docs/success-metric.md` *"does not exist yet"*. It has existed since 2026-08-27 (`170f1ad`). The conclusion that sentence draws, that no `vault_fp` has been published, still holds.
- The comment at `verifier-page-pack.mjs:215` says `'wasm-unsafe-eval'` contains `'unsafe-eval'` as a substring. Measured, the quoted string is not a substring; only the unquoted `unsafe-eval` is. The match that comment explains is correct, so the comment was left alone.

---

## 9. What this record does NOT establish

- **That CodeQL found everything.** Triaging what it reported says nothing about what it did not report. CodeQL reported no flow through the other eleven call sites of `Ui::line`, or into the `MachineResult::Value` arm, where every passphrase-taking command's result document goes. Neither was audited here.
- **The mechanism behind §4's nondeterminism**, or whether it affects other rules and languages.
- **What GitHub does with a dismissed alert whose source list grows** (§8.1).
- **That #6 will close as `fixed`** at the next analysis.
- **How a browser treats §8.2's probes.**
- **Which build produces release binaries** (§8.3).
- **The planning lane's `tracing` and key-literal scans** (§1.3). They are recorded from that lane and were not re-run.
- **Anything about default setup's own exposure.** D169 §2 R4 rules on that.
- **Consent.** Nothing here authorizes a single dismissal.

---

## Appendix: per-alert table

Rules: HC `rust/hard-coded-cryptographic-value` · CL `rust/cleartext-logging` · WH `rust/weak-sensitive-data-hashing` · PY `py/clear-text-logging-sensitive-data` · DM `js/unvalidated-dynamic-method-call` · IR `js/identity-replacement`. Each location is the alert's most recent instance. A `#[cfg(test)]` line cited in a reason is the attribute that gates the enclosing item.

| # | rule | state | location | class | verdict | reason |
|---:|---|---|---|---|---|---|
| 1 | PY | open | `testdata/vectors/v1/crypto/gen_vectors.py:639` | P-NAME | false positive | source is the `NON_SECRET` disclaimer literal (:89); sink writes the public vector document |
| 2 | PY | open | `testdata/vectors/v1/fine-tree/gen_vectors.py:555` | P-NAME | false positive | source is the `NON_SECRET` disclaimer literal (:282); sink writes the public vector document |
| 3 | PY | open | `testdata/vectors/v1/anchor/gen_vectors.py:609` | P-NAME | false positive | sources are `NON_SECRET` (:458) and its rendering (:535); sink writes the public anchor vector document |
| 4 | PY | open | `testdata/vectors/v1/anchor/gen_vectors.py:636` | P-NAME | false positive | same sources; `--check` prints an `inputs` key diff over public recorded artifacts |
| 5 | PY | open | `testdata/vectors/v1/anchor/gen_vectors.py:640` | P-NAME | false positive | same sources; `--check` prints a vector case name |
| 6 | IR | open | `scripts/verifier-page-pack.mjs:216` | J-TRUE-NOOP | true; fixed here | `replace(/'/g, "'")` replaced a quote with itself; removed, and the refusal loop now has planted arms (§5) |
| 7 | DM | open | `scripts/verifier-page-browser.mjs:277` | J-DRIVER | false positive | handler comes from a `Map` filled only by `on()` (:290); a local CDP driver, not page code |
| 8 | CL | open | `crates/antseal-cli/src/vault/keyfile.rs:437` | L-TEST | used in tests | `#[cfg(test)]`; prints `KeyfileSecret(<redacted>)` for a fixture key |
| 9 | CL | open | `crates/antseal-cli/tests/disclosure_preview.rs:397` | L-TEST | used in tests | integration test; leak guard over a throwaway test vault, prints only once a leak is detected |
| 10 | CL | open | `crates/antseal-cli/tests/init_command.rs:292` | L-TEST | used in tests | integration test; prints `report.asked` (`Vec<WizardStep>`), and `InitReport` has no field that carries an init source |
| 11 | CL | open | `crates/antseal-cli/tests/redaction_view.rs:309` | L-TEST | used in tests | integration test; `secret` is the rendered view, printed on failure after its withheld content was asserted absent |
| 12 | CL | open | `crates/antseal-core/src/anchor/caps.rs:775` | L-TEST | used in tests | `#[cfg(test)]`; `cert_bag` is a byte count |
| 13 | CL | open | `crates/antseal-core/src/anchor/verdicts/tests.rs:1197` | L-TEST | used in tests | `#[cfg(test)] mod tests;` (verdicts.rs:1196-1197); prints a diagnostic code string |
| 14 | CL | open | `crates/antseal-core/src/anchor/verdicts/tests.rs:1309` | L-TEST | used in tests | `#[cfg(test)] mod tests;` (verdicts.rs:1196-1197); prints a diagnostic code string |
| 15 | CL | open | `crates/antseal-core/src/verify/mod.rs:636` | L-TEST | used in tests | `#[cfg(test)]`; leak guard printing dummy hex patterns |
| 16 | CL | open | `crates/antseal-core/src/verify/file_stages.rs:2461` | L-TEST | used in tests | `#[cfg(test)]`; leak guard printing literal dummy patterns |
| 17 | CL | open | `crates/antseal-core/tests/anchor_caps.rs:154` | L-TEST | used in tests | integration test; prints `big.len()`, a length |
| 18 | CL | open | `crates/antseal-cli/src/commands.rs:114` | L-PROD | false positive | `Ui::line` stdout arm; the only flow is `vault import`'s line, which formats `ImportSummary.works` (a count) and `vault_dir` (a path) |
| 19 | CL | open | `crates/antseal-cli/src/lib.rs:178` | L-PROD | false positive | `MachineResult::Raw` arm; `Raw` is built only by `Outcome::raw`, called once, in `verify`, which prompts for nothing and opens no vault |
| 20 | CL | open | `crates/antseal-cli/src/commands.rs:112` | L-PROD | false positive | `Ui::line` stderr arm; same flows as #18 |
| 21 | WH | open | `crates/antseal-core/src/anchor/ess.rs:281` | W-PROTOCOL | false positive | SHA-1 fixed by RFC 2634 §5.4 for ESSCertID v1 (no algorithm field); input is the public signer certificate |
| 22 | WH | open | `crates/antseal-core/tests/anchor_real_tokens.rs:708` | W-PROTOCOL | used in tests | integration-test helper recomputing the ESSCertID v1 hash |
| 23 | HC | open | `crates/antseal-core/src/crypto/hkdf.rs:474` | H-FIXTURE | used in tests | `#[cfg(test)]` (hkdf.rs:306); empty salt of an independent RFC 5869 reference |
| 24 | HC | fixed | `crates/antseal-core/src/crypto/hkdf.rs:482` | H-FIXTURE | already fixed | `#[cfg(test)]` (hkdf.rs:306); went `fixed` at `ef5f6d9` with no Rust change (§4) |
| 25 | HC | open | `crates/antseal-cli/src/vault/cipher.rs:322` | H-FIXTURE | used in tests | `#[cfg(test)]` (cipher.rs:312); fixture vault key |
| 26 | HC | open | `crates/antseal-cli/src/vault/keyfile.rs:261` | H-OUTBUF | false positive | HKDF output buffer; `expand` fills all 32 bytes or errors, and the error returns before the buffer is used |
| 27 | HC | open | `crates/antseal-cli/src/vault/session.rs:160` | H-OUTBUF | false positive | HKDF output buffer (not the `Some(&[])` salt on :159); same fill-or-return as #26 |
| 28 | HC | open | `crates/antseal-cli/tests/vault_encryption.rs:44` | H-FIXTURE | used in tests | integration test; fixture KDF salt |
| 29 | HC | open | `crates/antseal-cli/tests/vault_encryption.rs:397` | H-FIXTURE | used in tests | integration test; wrong-length salt for a refusal case |
| 30 | HC | open | `crates/antseal-cli/tests/vault_encryption.rs:401` | H-FIXTURE | used in tests | integration test; wrong-length salt for a refusal case |
| 31 | HC | open | `crates/antseal-cli/tests/vault_encryption.rs:578` | H-FIXTURE | used in tests | integration test; fixture KDF salt |
| 32 | HC | open | `crates/antseal-core/src/anchor/request.rs:365` | H-FIXTURE | used in tests | `#[cfg(test)]` (request.rs:285); nonce buffer in a test DER dissector |
| 33 | HC | open | `crates/antseal-core/src/anchor/request.rs:508` | H-FIXTURE | used in tests | `#[cfg(test)]` (request.rs:285); fixed test nonce |
| 34 | HC | open | `crates/antseal-core/src/anchor/request.rs:524` | H-FIXTURE | used in tests | `#[cfg(test)]` (request.rs:285); fixed test nonce |
| 35 | HC | open | `crates/antseal-core/src/bin/metric_vault_fp.rs:414` | H-OUTBUF | false positive | hex-decode buffer; runs only when the input is exactly 64 hex characters, assigns every slot or returns `SaltShape` |
| 36 | HC | open | `crates/antseal-core/src/bin/metric_vault_fp.rs:716` | H-FIXTURE | used in tests | `#[cfg(test)]` (metric_vault_fp.rs:709); fixture salt |
| 37 | HC | open | `crates/antseal-core/src/bin/metric_vault_fp.rs:717` | H-FIXTURE | used in tests | `#[cfg(test)]` (metric_vault_fp.rs:709); fixture salt |
| 38 | HC | open | `crates/antseal-core/src/content/fine_tree/verify.rs:1046` | H-FIXTURE | used in tests | `#[cfg(test)]` (fine_tree/verify.rs:550); payload bytes for a tamper case |
| 39 | HC | open | `crates/antseal-core/src/content/fine_tree/verify.rs:1090` | H-FIXTURE | used in tests | `#[cfg(test)]` (fine_tree/verify.rs:550); payload bytes for a tamper case |
| 40 | HC | open | `crates/antseal-core/src/content/fine_tree/verify.rs:1254` | H-FIXTURE | used in tests | `#[cfg(test)]` (fine_tree/verify.rs:550); payload bytes for a tamper case |
| 41 | HC | open | `crates/antseal-core/src/crypto/commit.rs:215` | H-FIXTURE | used in tests | `#[cfg(test)]` (commit.rs:174); reference-commitment salt |
| 42 | HC | open | `crates/antseal-core/src/crypto/commit.rs:219` | H-FIXTURE | used in tests | `#[cfg(test)]` (commit.rs:174); reference-commitment salt |
| 43 | HC | open | `crates/antseal-core/src/crypto/commit.rs:223` | H-FIXTURE | used in tests | `#[cfg(test)]` (commit.rs:174); reference-commitment salt |
| 44 | HC | open | `crates/antseal-core/src/crypto/commit.rs:227` | H-FIXTURE | used in tests | `#[cfg(test)]` (commit.rs:174); reference-commitment salt |
| 45 | HC | open | `crates/antseal-core/src/crypto/commit.rs:358` | H-FIXTURE | used in tests | `#[cfg(test)]` (commit.rs:174); reference-commitment salt |
| 46 | HC | open | `crates/antseal-core/src/crypto/hkdf.rs:221` | H-OUTBUF | false positive | HKDF output buffer; `hkdf_expand` fills it or panics through `.expect`, never returns zeros |
| 47 | HC | open | `crates/antseal-core/src/crypto/manifest_aead.rs:479` | H-FIXTURE | used in tests | `#[cfg(test)]` (manifest_aead.rs:399); wrong-key negative case |
| 48 | HC | fixed | `crates/antseal-core/src/crypto/hkdf.rs:482` | H-FIXTURE | already fixed | `#[cfg(test)]` (hkdf.rs:306); went `fixed` at `ef5f6d9` with no Rust change (§4) |
| 49 | HC | open | `crates/antseal-core/src/verify/storage_linkage.rs:234` | H-FIXTURE | used in tests | `#[cfg(test)]` (storage_linkage.rs:225); fixture manifest key |
| 50 | HC | open | `crates/antseal-core/src/verify/storage_linkage.rs:376` | H-FIXTURE | used in tests | `#[cfg(test)]` (storage_linkage.rs:225); wrong-key negative case |
| 51 | HC | open | `crates/antseal-core/tests/crypto_properties.rs:351` | H-FIXTURE | used in tests | integration test; property-test buffer |
| 52 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:38` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 53 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:354` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 54 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:533` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 55 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:534` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 56 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:541` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 57 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:595` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 58 | HC | open | `crates/antseal-anchor/src/submit/tests.rs:596` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (submit.rs:415-417); nonce echoed in a committed real TSA capture |
| 59 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:48` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 60 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:49` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 61 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:50` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 62 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:51` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 63 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:55` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 64 | HC | open | `crates/antseal-anchor/src/tsa/tests.rs:56` | H-NONCE | used in tests | `#[cfg(test)] #[path]` (tsa.rs:532-534); nonce echoed in a committed real TSA capture |
| 65 | HC | open | `crates/antseal-core/src/anchor/testing.rs:804` | H-FIXTURE | used in tests | `#[cfg(test)]` (anchor/testing.rs:794); boundary test nonces |
| 66 | HC | open | `crates/antseal-core/src/anchor/testing.rs:834` | H-FIXTURE | used in tests | `#[cfg(test)]` (anchor/testing.rs:794); boundary test nonces |
