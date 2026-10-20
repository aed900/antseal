# D195 — A configured `[verify]` endpoint is printed **by its origin only**, and **no config refusal repeats a URL**: the esplora and Arbitrum RPC pairs are disclosed as `scheme://host` plus a non-default port, every URL-list refusal names the key, the line and the entry's position, and TSA and calendar URLs stay verbatim under `A20`

- **Status: RESOLVED. H8, for `U98`, fared (b): its direction — disclose the origin only —
  survived, and its premises fell. H9, for `U99`, fell (a) on its premise.**
  - **H8 — *disclose the origin only (`scheme://host[:port]`) on every surface — the human
    overlay, `--json`, and load-time refusals — through ONE redaction function on
    antseal-anchor's endpoint type that every caller uses*.** (b):
    - **"Every surface" collides with a ticked row.** TSA and calendar URLs are printed verbatim
      on purpose: `A20`'s Accept (*"Per-endpoint failures appear verbatim in the typed abort
      error and the degradation report"*, `tasks/A.md:250`) and the page that explains it
      (`docs/user/timestamp-authorities.md:321-323`). The ruling covers the two `[verify]` pairs
      only (§2 R1, R3).
    - **A load-time refusal has no origin to print.** A refused value may not parse at all — P2
      measured *"not a valid URI"* — so refusals name the entry's position instead, D188 R5's
      mechanism (§2 R4).
    - **Not every surface holds an `Endpoint`.** Two of the four overlay surfaces carry the
      failure's `String` (`crates/antseal-cli/src/verify_host.rs:410`), so the display function
      must also take a `&str`.
    - **`scheme://host[:port]` is not `Endpoint::origin()`.** `origin()` always prints the port
      and is the same-origin comparison key (`crates/antseal-anchor/src/http/endpoint.rs:155-162`).
      The display form is a new field computed in the same `parse`.
    - **"Two keys on one host" can never both be consulted.** `EndpointPair::new` refuses two
      endpoints at one origin (`crates/antseal-anchor/src/agree.rs:275-283`), so origin-only
      disclosure never makes the two endpoints of a pair indistinguishable.
  - **H9 — *redact userinfo in `EndpointError`'s Display itself, so no caller can echo it*.**
    (a), on its premise. Of the 9 credential-bearing shapes P2 drove through the binary, only 5
    construct an `EndpointError`: 2 go through the URL shape check and 2 through the config
    subset's own value error. One of the 5 does not parse, so its userinfo cannot be located
    structurally (§1.4).
  - **The deadline moves.** `U98`'s overlay content is D65 tier C, so it lands before `U32`,
    not merely before `Q31` (§2 R5).
- **Date: 2026-10-19**
- Owner rows: **`U98`** (§2 R1–R3, R5, R6); **`U99`** (§2 R4, R5).
- Related:
  - **D188** (§2 R1's last sentence — *"Calendar URLs carry no credentials, so the `tsa_urls`
    echo convention stands"* — is amended and takes a dated addendum; §2 R5's no-echo rule for
    `rpc_endpoints`, which §2 R4 here extends to every URL-list key; §4's `U98` bullet, which
    this record answers);
  - **D180** (§2 R1: the refusal *"**never echoes the value**"*, on ground 2, an input that *"in
    its common real form, carries a credential"*, D180:196-200);
  - **D55** (the keyed RPC providers in its survey, D55:102-103; *"A default requiring a key is
    not a default"*, D55:12-13);
  - **D65** §3 tier C (D65:457-468: the `verify` overlay becomes a promise at `U32`);
  - **D194** (`A20`'s verbatim failures reach the gate abort);
  - **D196** (this wave's other config ruling: the same lane, the same files);
  - **`A20`**, **`U30`** (the consumer), **`U32`**, **`Q31`**.

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). The tree was clean: `git status --porcelain` printed 0
lines at both of the planning lane's checks.

Planning lane P2 (wave 39, 2026-10-19) worked read-only. Its one execution ran a private copy
of the HEAD debug binary (`antseal 0.0.0`, built after the last commit that touched `crates/`)
over 26 hand-written `config.toml` cases. Each case ran under a fresh `HOME` and
`ANTSEAL_DIR` holding only the config, with `ANTSEAL_NO_REAL_ANCHOR_NETWORK=1` and
`ANTSEAL_NO_REAL_NETWORK=1`, as `antseal --json list`, and the exit code was read from `$?`
into a file. Exit 2 is that command's "no vault exists": the config **loaded**. Lane PS (the
availability survey) found the conflict with `A20` that §2 R3 settles.

Before this record was written, the records lane re-read every locator below at `07a170c`
through `git show 07a170c:<path>`, because implementing lanes were already editing these files
in the shared tree. Every citation held, with two refinements:
- the page's verbatim sentence is `docs/user/timestamp-authorities.md:321-323` (PS wrote
  `:320-322`);
- the rows' own locators drifted with wave 38's edits: `EndpointError`'s two `#[error]` lines
  are `http/endpoint.rs:247` and `:255` (D188 §1.7 and the rows say `:246` and `:254`), and
  `OnlineEndpoints::identities()` is `verify_host.rs:247-257` (the row says `:241-251`).

## 1. What was measured

### 1.1 Where a configured `[verify]` URL is printed today

Four overlay surfaces carry it:
- **S1, the human `endpoints:` line.** `endpoints_line`
  (`crates/antseal-core/src/verify/wording.rs:1029-1040`), printed at
  `crates/antseal-cli/src/verify_out.rs:323`. Its input is
  `ProbeEndpoints::new(endpoints.identities(), endpoints.overridden)`
  (`verify_host.rs:158-161`), and `identities()` pushes each endpoint's `url()`
  (`verify_host.rs:247-257`).
- **S2, `--json`'s `result.overlay.endpoints.{identities,line}`** (`overlay.rs:545-555`, built
  at `:730-737`), from the same list.
- **S3, each per-anchor failure line and its `failures[].endpoint`.** `probe_failure` copies
  `failure.endpoint().to_owned()` (`verify_host.rs:410`). For esplora that string is the
  *derived* request URL, `format!("{}/{path}", endpoint.url()…)`
  (`crates/antseal-anchor/src/esplora.rs:245-246`), so a key in the configured base reaches it.
- **S4, the receipt failure line and `receipt.outcome.failures[].endpoint`**, the RPC
  endpoint's `url()` (`arbitrum/confirm.rs:263`).

Core's own field doc calls the value *"The endpoint's identity (its configured URL)"*
(`crates/antseal-core/src/verify/overlay.rs:146`). Three refusal surfaces also print the URL
— the use-time Bitcoin-pair refusals (`verify_host.rs:308`, `:335-358`; `status.rs:806-825`)
and the hook's debug trace (`upgrade_hook.rs:333-341`) — and D196 §2 R3 makes all three
unreachable from a config that loaded. The load-time refusals are §1.4's.

What is **not** a surface, as P2 measured it: `AnchorHttpError`'s Display is never rendered for
a verify-pair failure, because `probe_failure` keeps the endpoint string and a class, never the
error's text (`verify_host.rs:402-413`); `status --upgrade`'s notes
name the calendar's own pending URI, and `HeaderError` names no endpoint
(`ots/upgrade.rs:495-520`); `antseal-anchor` emits no tracing at all.

It is **not a format question.** The bundle schema has no URL field, and `[verify]` URLs are
never written to the vault. The vault does keep each seal-stage TSA URL, encrypted at rest
(`crates/antseal-cli/src/pipeline/anchors.rs:156-159`) — `A20`'s family, §1.5.

### 1.2 A key in the URL is legitimate, and the repository's own example puts it in the path

- D55 ruled the pinned pairs keyless: *"A default requiring a key is not a default"*
  (D55:12-13). Its survey recorded the keyed providers: `https://rpc.ankr.com/arbitrum`
  answering *"Unauthorized: You must authenticate your request with an API key"* (D55:102), and
  `https://arb-mainnet.g.alchemy.com/v2/demo`, whose key is a **path segment** (D55:103).
- `docs/config.md:289-295` already tells users that *"providers put the key in the URL"* and
  that `verify --online` *"does print every endpoint it consulted, by full URL, on its
  `endpoints:` line and in `--json` output, so a key in one of these URLs appears there: treat
  that output as you would the key"*. The same page opens by saying that the file carries
  *"**operator preferences only** — never secrets"* (`docs/config.md:8`). The page contradicts
  itself.
- So a credential-only redactor — strip the userinfo and the query, keep the path — fails open on
  the one key shape the repository recorded, and recognising a key-bearing path segment would
  need a heuristic. Userinfo is already refused at load for every family
  (`http/endpoint.rs:147-148`, *"userinfo is not permitted in an endpoint URL"*).

### 1.3 The origin loses nothing a reader needs, but it is not `origin()`

- **Within a pair the origins differ by construction.** `EndpointPair::new` returns
  `PairError::SameOrigin` when `first.origin() == second.origin()` (`agree.rs:275-283`). That
  check runs at load for `rpc_endpoints`, and for `bitcoin_endpoints` once D196 §2 R3 lands.
- **Across the two pairs** one provider's origin can repeat. The disclosure order — *"the
  Bitcoin pair, then the Arbitrum pair"* (`verify_host.rs:244-245`) — and each failure line's own
  context (block lines are esplora; the receipt line is RPC) tell them apart.
- **`Endpoint::origin()` always prints the port**, `format!("{}://{}:{port}", …)` with the
  port defaulted to 443 or 80 (`http/endpoint.rs:155-162`; accessor `:193`). It is the
  same-origin comparison key, so it cannot change; the display form is one more field computed in
  the same `parse`.
- **`identities()` doubles as a safety pre-flight.**
  `a_configured_pair_is_what_the_receipt_probe_contacts` compares it with the stubs' full URLs
  and fails with *"the run would consult an endpoint that is not one of this test's stubs —
  refusing to probe"* (`crates/antseal-cli/src/verify_host/tests.rs:436-447`). Redefining
  `identities()` would blind that check; the disclosed form must be a separate projection.

### 1.4 The load-time echo has three paths, not one

P2 drove 9 credential-bearing shapes through the binary: 9 exits of 17, with the canary on
stderr **and** in `--json`'s `error.message` in 9 of 9.
- **(i) The parse check — 5 of 9.** ``antseal_anchor::Endpoint::parse(item, tls)
  .map_err(|reason| err(format!("`{what}`: {reason}")))?;`` (`config.rs:852-853`), whose
  `reason` is `EndpointError`'s Display, `"{endpoint}: not a usable endpoint URL ({reason})"`
  (`http/endpoint.rs:247`). One of the five, `https://user:CANARY PW@…`, does not parse at all
  (*"not a valid URI"*), so no structural redaction can find its userinfo.
- **(ii) The URL shape check — 2 of 9.** `` "`{what}` entries must be http:// or https:// URLs
  (got `{item}`)" `` (`config.rs:821-823`) echoes `user:CANARYPW@tsa.example/tsr` and
  `ftp://user:CANARYPW@…` without ever building an `EndpointError`. It is the deviation D188 §6
  recorded: *"The shared URL shape refusal now names its entry"*.
- **(iii) The subset's own value error — 2 of 9.** `` "value `{raw}` is not a quoted string, a
  [\"…\"] array, or a bare true/false …" `` (`config.rs:566-569`) quotes an unquoted item and an
  unquoted value. P2 read every message of the subset parser (`:484-570`): this is the only one
  that quotes its input.

The value-free machinery already exists: `RPC_VALUE_NOT_REPEATED` (`config.rs:701-702`),
`rpc_endpoints_value`, which parses the raw value without quoting it (`:704-716`), and
`endpoint_refusal_without_url` (`:773-785`).

Two tests bless the echo today:
- `ots_calendars_load_validated_and_replace_wholesale` refuses `"https://user:pw@cal.example.org"`
  (`crates/antseal-cli/tests/config_file.rs:325`) and asserts `err.detail.contains(entry)`:
  *"names the entry (a calendar URL is no credential)"* (`:339-343`);
- `a_plain_http_verify_endpoint_is_refused_at_config_load` asserts the Bitcoin refusal contains
  `http://plain.example/api`: *"the failure must name the offending endpoint"* (`:200-203`).

Two more facts bear on the remedy:
- `EndpointError`'s Display is bound to `AnchorHttpError`'s by
  `endpoint_errors_convert_with_identical_text` (`crates/antseal-anchor/src/http/tests.rs:734`),
  so H9's edit would have had to move `http.rs`'s twin arms in the same act.
- A query-borne key in a TSA URL loads today: `tsa_urls =
  ["https://tsa.example/tsr?apikey=CANARYQ"]` exits 2 in P2's probe.

### 1.5 `A20` keeps TSA and calendar URLs verbatim

- `A20`'s Accept (`tasks/A.md:250`; the row is ticked): *"Per-endpoint failures appear verbatim
  in the typed abort error and the degradation report."* The page defends it:
  *"It names every endpoint that failed, verbatim and with its failure class in brackets,
  because your next action is to look at those URLs"* (`docs/user/timestamp-authorities.md:321-323`).
- It is printed in exit 22's exemplar (`crates/antseal-cli/tests/snapshots/cli-errors.display.txt:54`,
  *"What failed: tsa https://tsa-one.example/tsr [http] …"*), in the seal degradation report
  (`crates/antseal-cli/tests/snapshots/json-envelopes.txt:32`,
  `"degradation":["tsa http://tsa-two.example [http] …`),
  in seal's human Anchors block (`crates/antseal-cli/src/seal_run.rs:171-182`) and in seal
  `--json`'s `anchors.endpoints[].endpoint` (`seal_run.rs:237-240`).
- Every one of these is a **seal-time** anchor family. None is a verify-time pair, whose
  output is D64's overlay.
- The two default TSAs' URLs carry no key, and both answered live captures with `HTTP 200`
  (`https://freetsa.org/tsr`, `http://timestamp.digicert.com`;
  `docs/user/timestamp-authorities.md:80-81`). D188 §2 R1 ruled that calendar URLs carry no
  credentials.

### 1.6 The deadline for the overlay is `U32`

D65 §3 tier C (D65:457-468): *"everything else inside `result` — for `verify`, the overlay and
live siblings and the verdict data … **U32 is where these become promises**"*. No snapshot pins
the identities today: the committed envelope shows `"overlay":null`
(`crates/antseal-cli/tests/snapshots/json-envelopes.txt:44`). `U98`'s *"before `Q31`"* is therefore too late for
the overlay content, which is a pre-`U32` change.

### 1.7 The verifier page is a different surface

The page builds its identities from the fields the user typed
(`verifier-web/index.template.html:713-716`) and renders them in the user's own tab. No test
compares the CLI's identity strings with the page's.

## 2. RULING

### §2 R1 — The two `[verify]` pairs are disclosed by origin only (`U98`)

- **Scope.** The esplora pair — `[verify] bitcoin_endpoints`, and the pinned default — and the
  per-network Arbitrum RPC pair — `[verify.<network>] rpc_endpoints`, and the pinned defaults.
- **The form.** `scheme://host`, plus `:port` only when it differs from the scheme's default;
  the host lowercased; an IPv6 host bracketed. The pinned defaults then render as
  `https://blockstream.info, https://mempool.space, https://arb1.arbitrum.io,
  https://arbitrum.drpc.org` (`esplora.rs:83-84`, `arbitrum/endpoints.rs:22-23`).
- **The mechanism, in `antseal-anchor`.** This is **not** `Endpoint::origin()`, which always
  prints the port and is the same-origin comparison key (§1.3). `Endpoint` gains a display form
  computed in the same `Endpoint::parse` — no second URL parser — and the crate gains
  `pub fn disclosed(s: &str) -> String` for the failure strings. For an input that does not
  parse, `disclosed` returns a fixed phrase that never contains the input.

*Why the origin, and not the credential:* the repository's own example of a keyed provider puts
the key in the path (§1.2), and no structural rule can tell a key-bearing path segment from an
ordinary one. The origin needs no recognition, and it loses nothing a reader needs: the two
endpoints of a pair are two origins by construction, and the disclosure order separates the
pairs (§1.3).

### §2 R2 — Where: at the hand-off from the CLI to core

- `verify_host.rs` `probe_online` (~`:158-161`): `ProbeEndpoints` receives the **disclosed**
  identities, through a sibling of `OnlineEndpoints::identities()` (for example
  `disclosed_identities()`).
- `verify_host.rs` `probe_failure` (~`:409-411`): each failure's endpoint string goes through
  `disclosed`.
- `OnlineEndpoints::identities()` is **kept unchanged**: the safety pre-flight in
  `verify_host/tests.rs` (~`:436-446`) relies on the full URL (§1.3).
- Core is untouched, except an optional doc line on `EndpointProbeFailure::endpoint`
  (`overlay.rs` ~`:146-147`: *"as the host discloses it (the CLI: its origin)"*), which
  `L-VOCAB2` carries.

*Why there:* the CLI is the one host that holds configured URLs; S1–S4 all pass through these
two hand-offs (§1.1), so core, its wording and the page's WASM boundary need no change.

### §2 R3 — TSA and OTS-calendar URLs stay verbatim (`A20`)

`A20`'s ticked Accept (`tasks/A.md:250`) and the page that defends it
(`docs/user/timestamp-authorities.md:321-323`) keep every TSA and calendar URL verbatim on
every surface that prints one today. One sentence goes into `docs/config.md`'s `[anchors]`
comment and into `docs/user/timestamp-authorities.md` §4: *antseal prints every TSA and calendar
URL in full — in the seal report, in a gate abort and in `--json` — so none of them may carry a
credential.* No `A20` test or snapshot moves: `cli-errors.display.txt:54` and
`json-envelopes.txt:32` are untouched.

*Why:* a failed TSA's URL is exactly what the user must look at next (§1.5), the default TSAs'
URLs carry no key, and userinfo is already refused at load for every family. The
residual — a query-borne key in a TSA or calendar URL loads (§1.4) and would be printed — is
documented where the keys are configured instead of redacted.

### §2 R4 — No URL-list refusal repeats its value (`U99`)

- Config refusals for **every** URL-list key — `tsa_urls`, `ots_calendars`,
  `bitcoin_endpoints`, `rpc_endpoints` — name the key, the line and the entry's position
  (`entry N`), never the value.
- All three echo paths of §1.4 change:
  - the URL shape check (`config.rs` ~`:821-823`) names `entry N`;
  - the parse check says the `EndpointError` through the existing `endpoint_refusal_without_url`,
    with `entry N`;
  - the config subset's one value-quoting message (`config.rs` ~`:566-569`) becomes value-free
    **for every key**.
- A new constant beside `RPC_VALUE_NOT_REPEATED`:
  `URL_VALUE_NOT_REPEATED = "the value is not repeated here, because a URL can carry a credential"`.
- **This amends D188 §2 R1's last sentence.** Calendar URLs were echoed on the ground that they
  *"carry no credentials"*; the `tsa_urls` echo convention is retired. D188 takes a dated
  addendum.
- Size **S**, not the row's XS: three paths, two flipped pins (§1.4) and this record.

*Why one value-free rule, and not H9's structural redaction:* 4 of the 9 measured echoes never
construct an `EndpointError`, and one of the 5 that do cannot be redacted structurally (§1.4). A
rule that never repeats the value needs no parse to decide what is safe, so it also holds for
input that does not parse. The refusal still lets the user find the entry: the key, the line
(`ConfigParseError.line`) and its position.

### §2 R5 — Timing

`U98`'s overlay content is D65 tier C, so it must land **before `U32`**, not merely before
`Q31` (§1.6). `U99` lands before `Q31`. Both land now.

### §2 R6 — Documents

- `docs/config.md`:
  - `:8` gains a clause: an endpoint URL may carry a provider's API key, which antseal never
    prints beyond its origin;
  - `:289-295` takes P2's text: *"**No output repeats these URLs.** Providers put an API key in
    the URL, so a refusal names the key, the table, the line and the entry's position, and
    `verify --online` discloses each endpoint it consulted by its origin only — scheme, host and
    a non-default port — on its `endpoints:` line, in its failure lines and in `--json` output.
    The file itself is plaintext beside the vault (and encrypted inside `vault export`): protect
    it as you would the key."*;
  - `:158-166`: refusals name the key, the line and the entry's position, never the URL;
  - the schema comment, and §2 R3's sentence in the `[anchors]` comment.
- `docs/user/timestamp-authorities.md` §4: §2 R3's sentence.
- **Not touched:** the verifier page and `crates/antseal-wasm/**`. The asymmetry is deliberate:
  the page renders, in the user's own tab, the fields that user typed (§1.7), while the CLI's
  output goes to terminals, logs and `--json` consumers.

## 3. Fault plants

The implementing lane owes these (P2 §2, U98 (g) and U99 (g)). Green baselines come first;
each plant is judged by its **message**; every restore is followed by a `touch`. G99-2 spawns
the binary and runs in a shadow copy with a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

1. **G98-1** (in-process, `verify_host/tests.rs`, loopback stubs):
   `the_overlay_discloses_origins_and_never_a_configured_path_or_query`. Two esplora and two
   RPC stubs, each configured as `{base}/CANARY-PATH/x?apikey=CANARY-Q`. The existing
   `identities()` pre-flight runs against the stubs first; then `probe_online` over a bundle
   with a receipt and an upgraded OTS anchor, and `run_verify` with the overlay. Both the human
   overlay and `to_canonical_json()` are rendered: neither canary appears in either, and every
   disclosed identity equals a stub's `http://127.0.0.1:PORT`. **The consulted half:** each
   stub's request log contains `CANARY-PATH` (the RPC stubs in the request line, the esplora
   stubs in the derived path), so the keyed URL was *used*, not merely printed less.
2. **G98-2:** the same with every stub answering 500, so the S3 and S4 failure lines render;
   the canaries are absent, and each failure's endpoint is a stub's origin.
3. **G98-3** (unit, `http/endpoint.rs`): `disclosure_is_scheme_host_and_a_non_default_port_only`
   — `HTTPS://Example.ORG:443/v2/K?x=y#f` → `https://example.org`;
   `http://127.0.0.1:8080/a?k=1` → `http://127.0.0.1:8080`; `https://[::1]:8443/x` →
   `https://[::1]:8443`; `https://h.example:80/` → `https://h.example:80`; and
   `disclosed("not a url")` is the fixed fallback, with the input absent from it.
4. **G99-1** (in-process, `config_file.rs`): `no_url_list_refusal_repeats_its_value`. Seven
   measured shapes (https userinfo; `http://CANARY@`; unparseable with userinfo; scheme-less;
   `ftp://`; an unquoted item; an unquoted value) × three keys (`tsa_urls`, `ots_calendars`,
   `bitcoin_endpoints`) = **21 cases**, the count asserted before the loop. Each Bitcoin list
   carries a valid second entry, so that after D196 the per-entry check, not the count, refuses
   it. Each case: an error on line 2 whose detail names the key and `entry N` (or the subset
   sentence), and no canary.
5. **G99-2** (spawned): `a_credential_in_a_url_entry_is_exit_17_and_never_printed`. One config
   per key with a userinfo canary; `--json verify b.sealproof` exits 17 with class
   `malformed-config`, the message names the key and `config.toml:2`, and the canary is on
   neither stream. Control: the same entry without userinfo loads, and the command reaches exit
   4, as the control of `a_flat_arbitrum_endpoints_key_is_exit_17_before_any_command_runs`
   does (`config_file.rs:1318-1369`).
6. **Flipped, deliberately:** `ots_calendars_load_validated_and_replace_wholesale`'s entry
   assertion (`config_file.rs:339-343`) now says *"names `entry 1`, never the entry"*, and the
   Bitcoin half of `a_plain_http_verify_endpoint_is_refused_at_config_load` (`:200-203`) names
   `entry 1`, with the URL absent.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P98a `ProbeEndpoints::new(endpoints.identities(), …)` restored | G98-1, on *"the overlay disclosed a configured path or query"* |
| P98b `probe_failure` back to `failure.endpoint().to_owned()` | G98-2; G98-1 stays green, which proves S3/S4 are covered separately |
| P98c `disclosed()` returns `url()` | G98-3 |
| P98d the fallback echoes its input | G98-3's fallback case |
| P98e `endpoints_from_config` ignores `[verify]` | G98-1, at the pre-flight, before any request — so no public endpoint is dialled |
| P99a the parse check's ``format!("`{what}`: {reason}")`` restored | G99-1 and G99-2, on *"must not carry the value"* for the userinfo shapes |
| P99b the shape check's `` (got `{item}`) `` restored | G99-1, on the scheme-less and `ftp://` shapes only (path ii) |
| P99c the subset message's `` value `{raw}` `` restored | G99-1, on the two unquoted shapes only (path iii) |
| P99d (control) the shape check refuses every entry | `full_schema_parses_with_every_slot` (`config_file.rs:120`) and `https_and_loopback_verify_endpoints_are_admitted_and_tsa_http_is_untouched` (`:244`) — the rule is a rule, not a blanket refusal |

## 4. What this record does NOT decide

- **`status --upgrade`'s notes.** They name calendar URIs — `A20`'s family, verbatim under §2
  R3 — never a `[verify]` endpoint (§1.1).
- **The verifier page** (§2 R6). It keeps showing the URLs its user typed.
- **A query-borne key in a TSA or calendar URL.** It loads (§1.4) and `A20`'s surfaces would
  print it; §2 R3 documents the rule instead of refusing or redacting. A future need for an
  authenticated TSA would reopen `A20` through its own record.
- **The refused alternatives.** Masking (`https://host/…`, the same mechanism plus one bit) is
  cosmetic; redacting only overridden endpoints needs a per-pair flag where `overridden` is one
  run-level flag (`verify_host.rs:226`, `:328`), and renders one list two ways; a
  documentation-only remedy forbids the keyed providers the same page says serve old receipts.
- **An esplora base carrying a query or a fragment** — a request-shape question for the
  Bitcoin pair's load validator, recorded in D196 §4.
- **No row is minted by this record.**

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CFG2 (round 1) — `U99`, then D196's `U101` and `U100`, then `U98`, in one lane

The four rows share `config.rs`, `config_file.rs` and `docs/config.md`, and `U98` shares
`verify_host.rs` with `U101`, so one lane takes them in that order.
- `crates/antseal-anchor/src/http/endpoint.rs`: the display field on `Endpoint` (computed in
  `parse`, ~`:155-165`), `pub fn disclosed(&str) -> String`, and their unit tests (G98-3). No
  other `antseal-anchor` file.
- `crates/antseal-cli/src/config.rs`: the URL shape check (~`:812-833`), the parse check
  (~`:846-856`), the subset message (~`:566-569`), `URL_VALUE_NOT_REPEATED` beside
  `RPC_VALUE_NOT_REPEATED` (~`:701`), and the comments that explain the echo (~`:817-820`,
  ~`:930-936` — *"a calendar URL carries no credential, so the entry is echoed"* — and
  ~`:704-707`).
- `crates/antseal-cli/src/verify_host.rs` — **only** `probe_online` (~`:158-161`),
  `OnlineEndpoints` (~`:244-257`, the sibling of `identities()`) and `probe_failure`
  (~`:400-413`) for this record. `run_verify_live` and its doc (~`:418-489`) are `L-VOCAB2`'s, in
  round 2.
- `crates/antseal-cli/src/verify_host/tests.rs`: G98-1 and G98-2, appended at the end.
- `crates/antseal-cli/tests/config_file.rs`: G99-1, G99-2 and the two flips (§3).
- `docs/config.md` (§2 R6); `docs/user/timestamp-authorities.md` — **only** §2 R3's sentence in
  §4 (and D196's clause). Its `path:line` citations are `L-LOC`'s.
- Spawned tests run in a shadow copy with a private `CARGO_TARGET_DIR` and `CARGO_BUILD_JOBS=1`;
  in-process tests in the shared target under the lock protocol.
- Not touched by this lane: `backend.rs`, `commands.rs`, `error.rs`, `seal_run.rs`,
  `antseal-core`, and the A20 snapshots (`cli-errors.display.txt`, `json-envelopes.txt`).
- The storage and payment path and `commands.rs` are untouched, so this record forces neither
  the heavy tier nor the devnet E2E; the gate's own trigger decides.

### L-VOCAB2 (round 1)

- `crates/antseal-core/src/verify/overlay.rs` ~`:146-147`: the optional doc line of §2 R2,
  *"as the host discloses it (the CLI: its origin)"*.

### L-LOC (round 3, after the last code edit)

- The living docs' `path:line` citations into the files this record moves — among them
  `docs/user/timestamp-authorities.md`'s citations of `config.rs` — re-pointed by meaning.

### RECORDS-A — dated addendum

D188: §2 R1's last sentence amended — the echo convention is retired (§2 R4) — and §4's `U98`
bullet answered by this record (written with D196's addendum, as one addendum).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`

- `U98`'s deadline annotated *before `U32`* (§2 R5).
- `U98` and `U99` ticked when the lane's greens and plants are in its report.
- This record's index row and register row.

## 6. As built — wave 39, lane L-CFG2 (recorded in place before this record was first committed)

One lane landed this record and D196, in the order `U99` → `U101` → `U100` → `U98`. Every run
and every plant was in a shadow copy (`git archive HEAD` plus the lane's files, compared by
sha256) with a private `CARGO_TARGET_DIR`; no plant touched the tree. The verdicts are the
lane's, quoted with the exit codes its report gives; the code facts were re-read in the tree.
Nine of the lane's ten files still hash as its report lists. `verify_host.rs` differs from the
lane's last copy only by the module-doc hand-off below and D199's changes to `run_verify_live`.

- **§2 R1 (`U98`).** `Endpoint` gains a `disclosed` field computed in the same `parse`
  (`crates/antseal-anchor/src/http/endpoint.rs:163-169`): `scheme://host`, plus `:port` only
  when it is not the scheme's default, the host lower-cased, an IPv6 host bracketed. `origin()`
  is unchanged and keeps its port. The free `disclosed(url: &str) -> String` (`:275-280`)
  re-parses under `TlsPolicy::Optional`; an input that does not parse gives the fixed *"an
  endpoint whose URL does not parse"* (`:262`), never the input.
- **§2 R2.** `probe_online` hands core `endpoints.disclosed_identities()`
  (`crates/antseal-cli/src/verify_host.rs:167-168`; the new method is at `:277`), and
  `probe_failure` passes each failure's endpoint through `disclosed` (`:450`). `identities()` is
  unchanged (`:260`); its only callers are the two test pre-flights (`verify_host/tests.rs:436`,
  `:573`), and its doc says why it stays. For this record, core gains only `L-VOCAB2`'s doc line
  (`crates/antseal-core/src/verify/overlay.rs:146-147`). The lane's hand-off for the module doc,
  which still said core carries *"the endpoint's own configured URL"*, has landed:
  `verify_host.rs:31-33` reads *"the endpoint's origin (U98, D195 R2) — never its configured
  URL, which may carry a provider's key"*.
- **§2 R3 (`A20`).** No `A20` surface moved: `cli-errors.display.txt:54` is byte-identical to
  `HEAD`, and `json-envelopes.txt` is unmodified.
  - **Deviation: the sentence drops "every"** (the lane's deviation 2). It reads *"antseal prints
    TSA and calendar URLs in full — in the seal report, in a gate abort and in `--json` — so none
    of them may carry a credential."* A gate abort lists only the endpoints that failed
    (`crates/antseal-anchor/src/gate.rs:206-208`), so *"every … URL"* would overclaim. It sits in
    `docs/config.md:93-95` and as a bullet at `docs/user/timestamp-authorities.md:243-244`.
- **§2 R4 (`U99`).** All three echo paths are value-free (`crates/antseal-cli/src/config.rs`):
  the shape check (`:1002-1003`, *"`{what}` entry {index} is not an http:// or https:// URL;
  {URL_VALUE_NOT_REPEATED}"*); the parse check (`:1042`, through
  `endpoint_refusal_without_url`); and the subset's message, for every key (`:588-591`, *"the
  value is not a quoted string, a ["…"] array, or a bare true/false (…); it is not repeated
  here"*). `URL_VALUE_NOT_REPEATED` carries the ruled text (`:815-816`).
  - Positions count from 0, as `bootstrap`'s and `rpc_endpoints`' refusals already did, so
    `entry 1` is a list's second entry (`docs/config.md:179`: *"`entry 0`, `entry 1`, …"*).
  - The comments that excused a refusal raised before the parse by *"the subset echoes the
    value"* were rewritten, the `ots_calendars` arm's among them.
  - **Deviation: the subset path names the key, not the entry's position** (deviation 1).
    `apply()`'s `value` closure now prefixes `` `{key}`: `` to every subset refusal, for every
    key that uses it. The subset parser reports no positions, so it cannot say `entry N`; §3's
    G99-1 already accepted *"the subset sentence"* there. The lane proposed an unnumbered row,
    two lines in `parse_value`'s array branch, that would make §2 R4's sentence true in full. It
    was not minted this wave.
- **§2 R5.** Both rows landed this wave: `U98` before `U32` and `U99` before `Q31`.
- **§2 R6.** In `docs/config.md`:
  - **Deviation: `:8-12`'s clause is scoped** (deviation 3). It reads *"…never secrets, except
    that a `[verify]` endpoint URL may carry a provider's API key, which antseal never prints
    beyond its origin"*. Unscoped, it would be false for the TSA and calendar URLs that §2 R3
    keeps verbatim. The lane re-checked every `[verify]` print path to make the clause true:
    - the hook's trace prints only value-free refusals;
    - its notes name no `[verify]` endpoint (D202's `BudgetSpentBeforeHeader` names only the
      calendar URI);
    - `parse_pair` prints only the compiled-in pinned pairs.
  - `:175-181`: the refusal paragraph.
  - `:307-314`: the bullet opens *"**No output repeats these URLs.**"* and takes P2's text
    after its existing first sentence. It replaces *"These refusals never repeat an RPC URL"*,
    whose claim that `verify --online` prints every endpoint by full URL is now false.
  - `:128-129`: the `[verify]` schema comment.

  The verifier page and `crates/antseal-wasm/**` are not in the lane's file list.
- **§3, the greens.**
  - G98-1 and G98-2 (`verify_host/tests.rs:611`, `:663`) share `keyed_run` (`:554`): four
    loopback stubs, the esplora pair at `{base}/NOT-A-KEY-path-canary/x` and the RPC pair at the
    same path plus `?apikey=NOT-A-KEY-query-canary`. Neither canary reaches the human or the
    `--json` surface, every disclosed identity is a stub's origin, and every stub's request log
    carries its canaries: the keyed URL was used, not merely printed less.
  - **Deviation: the bundle is not the bare F13 shape** (deviation 10). The overlay renders S3's
    per-anchor lines only for an OTS anchor attested offline, and F13's anchors are placeholders.
    The bundle keeps F13's receipt and carries one genuinely attested anchor, built with
    `antseal_core::anchor::testing::ots_writer`.
  - **D196's widening reaches this test** (deviation 6). A query in an esplora base is now refused
    at load, so the esplora stubs carry a key-shaped path only, and the query canary rides on the
    RPC pair.
  - G98-3 (`http/endpoint.rs:537`) has 6 cases, the count asserted, adding
    `http://h.example:80/rpc` → `http://h.example`. G99-1 (`config_file.rs:1494`) asserts its 21
    cases before the loop and `checked == 21` after it (`:1562`), and checks for the canary before
    the wording, so a restored echo fails on the echo. G99-2 (`:1573`) also runs plain mode. The
    flips are at `:204` and `:353`.
- **Red baselines.**
  - U99: `0 passed; 2 failed`, with G99-1 failing on *"`tsa_urls`, https userinfo: the refusal
    must not carry the value — … https://user:NOT-A-PW-canary@host.example/x: not a usable
    endpoint URL (userinfo …)"*.
  - U98: `0 passed; 2 failed`, and the render showed S1, S3 and S4 all leaking.
  - G98-3 named a method that did not exist yet, so it was a compile check; P98c and P98d are
    its reds.
- **Plants, every one red by message.** Each one compiled, and each restore was `cp`, then
  `touch`, then a sha256 match against the snapshot.
  - **P98a** reddened G98-1 and G98-2 (*"the overlay disclosed a configured path or query on its
    human surface:"*).
  - **P98b** left G98-1 `ok` and reddened G98-2, as §3 predicted.
  - **P98c** reddened G98-3: *"left: "HTTPS://Example.ORG:443/v2/K?x=y#f""*.
  - **P98d** reddened G98-3 on *"the fixed phrase"*.
  - **P98e** stopped G98-1 at the pre-flight, before any request: *"the run would consult an
    endpoint that is not one of this test's stubs — refusing to probe"*.
  - **P99a** reddened G99-1 and G99-2 on *"must not carry the value"* and *"--json stdout must
    not carry the credential"*.
  - **P99b** and **P99c** reddened G99-1 at their first case (*"no scheme"*, *"an unquoted
    entry"*), every earlier shape passing.
  - **P99d** reddened both controls, the first on *"line: 9, detail: "`tsa_urls` entry 0 is not
    an http:// or https:// URL; …""*.
- **Found (instrument findings; no row).**
  - `rpc_url_is_refused_at_load_under_every_network`'s canary no longer pins *where* that refusal
    is raised. Its table needle still does, and its doc now says so.
  - `rustfmt` run on a test file also formats that file's `#[path]` children
    (`tests/common/spawn.rs`, `verify_host/tests.rs`). A lane formatting one file in the shared
    tree can rewrite a helper it does not own, so this lane formatted in the shadow first.
- **At the lane's close.** In the shadow: `antseal-cli --lib` 322 passed, 0 failed;
  `--test config_file` 32 passed; `antseal-anchor --lib` 214 passed, 1 ignored.
  `clippy --all-targets -- -D warnings` exited 0 on both crates, and a planted `Some(1).unwrap()`
  in `tests/config_file.rs` made it exit 101, so the test targets are linted. In the shared tree
  with every lane's edits, G98-1, G98-2 and G98-3 passed in-process. `check-copy-style.py` and
  `check-personal-data.py` exited 0.
- **Rows.** `U98` and `U99` are still open in `TODO.md` at this writing; the orchestrator ticks
  them (§5).

## Closing — this record is not consent

It changes what antseal prints for two endpoint families and what its config refusals say,
inside the wave's own commits. Nothing in it authorises a push, a workflow dispatch, a deploy or
any other outward act; each of those needs the maintainer's express consent naming the action,
the destination and the account.

## Addendum — 2026-10-20 (wave 40, `U108`): §6 deviation 1's "two lines" would not have made §2 R4 true in full; `U108` numbers every entry and carries the position through `rpc_endpoints_value`

§6's deviation 1 records that the subset path names the key and not the entry's position, and
that the lane proposed *"two lines in `parse_value`'s array branch, that would make §2 R4's
sentence true in full"* (`:476-477`). The register carries that row as `U108` (`TODO.md:1103`).
**As measured at `6e1cab3`, the two lines would not have made it true in full.** §2 R4 names
four keys — `tsa_urls`, `ots_calendars`, `bitcoin_endpoints`, `rpc_endpoints` (`:265-267`) —
and numbering inside `parse_value` reaches only those whose refusal carries `parse_value`'s
reason through `apply()`'s `value` closure (`crates/antseal-cli/src/config.rs:985`): the first
three, and `bootstrap`. `rpc_endpoints_value` (`config.rs:823-831`) maps every failure of
`parse_value` to its own sentence (`_ => Err(format!(…))`) and discards the reason, so no number
added inside `parse_value` could reach a user.

Executed by wave 40's planning lane P2 (a copy of the `HEAD` binary, ten cases, the canary
absent from both streams in all ten): an unquoted **second** entry of `tsa_urls`,
`ots_calendars`, `bitcoin_endpoints` or `bootstrap` is refused (exit 17) with *"`<key>`: the
value is not a quoted string, …; it is not repeated here"*, the word `entry` absent; boolean,
nested-array and escape entries are equally unnumbered; and under `[verify.arbitrum-one]` an
unquoted second `rpc_endpoints` entry reads *"`rpc_endpoints` under [verify.arbitrum-one] takes
a one-line array of exactly two quoted endpoint URLs; the value is not repeated here, because an
RPC URL often carries an API key"*. The shape check's control already says *"`tsa_urls` entry 1
is not an http:// or https:// URL; …"*, counting from 0 as this record's §6 says.

**`U108` is ruled under §2 R4, without a record of its own:**
- **Every per-entry failure inside `parse_value`'s array branch is numbered**, from 0, in the
  house form *"`{key}` entry {N}: …"* — for example *"`tsa_urls` entry 1: the value is not a
  quoted string, a ["…"] array, or a bare true/false (integers, dates, and inline tables are
  outside the antseal config subset); it is not repeated here"*. The boolean, nested-array,
  escape, stray-quote and unterminated-quote reasons take the same prefix.
- **The position is carried through `rpc_endpoints_value` too:** *"`rpc_endpoints` under
  [verify.arbitrum-one] takes a one-line array of exactly two quoted endpoint URLs, and entry 1
  is not one; the value is not repeated here, because an RPC URL often carries an API key"*.
- **The carrier is the lane's choice**, stated in its report: a small typed
  `SubsetError { entry: Option<usize>, reason }` reaching `parse_value`'s four call sites, all in
  `config.rs` (preferred), or a `String` if that is smaller.
- **An unquoted value that is not an array stays unnumbered:** it has no entry.
- `docs/config.md:180-182` says that a list entry is named by its position.
- **Tests and plants:** G108-1, `an_array_entry_outside_the_subset_is_named_by_its_position`
  (each list key with an unquoted second entry → line 2, the key, *"entry 1"*, no canary; an
  unquoted first entry → *"entry 0"*; boolean, nested and escape entries at index 1 →
  *"entry 1"*; `rpc_endpoints` under both networks → *"entry 1"*; a bare unquoted value → no
  *"entry"*; the case count asserted), and the *"an unquoted entry"* case of
  `no_url_list_refusal_repeats_its_value` (`tests/config_file.rs:1524-1526`) tightened to require
  *"entry 0"*. Plants: P108-a drops the number (the Accept's), P108-b counts from 1, and P108-c
  drops the position from `rpc_endpoints_value`.

How the lean fared: *"number entries in parse_value's array branch and carry `entry N` into the
subset refusal; XS, no ruling"* fell (b). Its direction survived; *"no ruling"* fell on
`rpc_endpoints`, which needed one ruling line — the second bullet above, recorded here —
applying §2 R4 to `rpc_endpoints_value`.
Lane L-CFG3 lands it in wave 40, with D207. Once it lands, §2 R4's sentence is true for all four
of its keys. The ruling and §6 above stay as written.
