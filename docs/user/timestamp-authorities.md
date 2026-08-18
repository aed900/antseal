# Timestamp authorities

Every `antseal seal` asks one or more **RFC 3161 timestamp authorities** (TSAs)
to sign a statement of the form *"I saw this 32-byte digest at this instant."*
That signed statement — a *timestamp token* — is what lets a bundle recipient,
years later and with no network, establish that your content existed no later
than the time the authority stamped.

This page tells you which authorities antseal contacts by default, which
alternates are documented and what each one costs you, how to configure your
own list, and exactly what happens when an authority is unreachable.

It is written for someone deciding whether to trust a timestamp. Two limits
first, because everything below is only as strong as they allow.

> a seal proves the holder of the sealing key possessed this content by the proven time — not authorship, and not exclusive possession

That sentence is the product's frozen wording
(`crates/antseal-core/tests/snapshots/verdict-wording.txt:6`). A timestamp
authority signs a time; it does not read your content and it does not know who
you are. It is not a legal notary, and neither is antseal. What antseal proves
is existence, integrity and priority — and the priority it proves runs only
against *later* evidence, so an earlier seal by someone who received your work
outranks yours. **Seal before you share.**

---

## 1. The rule that decides everything else

An authority returning `HTTP 200` with `PKIStatus: granted` is **not** enough
for antseal to count its token. A token counts only when it passes the full
offline pipeline the eventual bundle recipient will run
(`crates/antseal-anchor/src/tsa.rs:4-21`):

1. the CMS signature, signed attributes, `messageImprint` and the **nonce
   antseal chose for that request** all verify;
2. the signer's certificate chain validates against the **root store compiled
   into antseal**, not against your operating system's trust store;
3. the resulting state is *headline-eligible* — `proven`, or
   `valid-at-stamping-cert-since-expired`.

A token that reaches step 2 and fails it renders
`internally-consistent-only` — *"cryptographically well-formed but not
independently anchored"*
(`crates/antseal-core/tests/snapshots/verdict-wording.txt:19`) — and
contributes **nothing**. This is the single most common surprise when
configuring an authority yourself: a perfectly healthy TSA whose root antseal
does not pin is, for antseal's purposes, a failure.

### The pinned root store, version 1

Store v1 holds **exactly four roots**, asserted as data by
`pinned_store_is_exactly_four_roots_at_version_1`
(`crates/antseal-core/src/anchor/roots/mod.rs:360-376`); the roots themselves
are at `crates/antseal-core/src/anchor/roots/mod.rs:263-308`, each with a
per-channel provenance record in
`crates/antseal-core/src/anchor/roots/PROVENANCE.md`:

| label | covers |
| --- | --- |
| `freetsa-root-ca` | FreeTSA |
| `digicert-trusted-root-g4` | DigiCert |
| `dfn-verein-community-root-ca-2022` | `zeitstempel.dfn.de` |
| `sectigo-public-time-stamping-root-r46` | Sectigo — and Entrust, see §3 |

The store carries a version and a build date (`1`, `2026-08-03`) and the
version appears in verdict data, so a report always says which trust store
produced it. Adding or rotating a root is a reviewed, versioned change with a
documented procedure — see `docs/anchors/root-store-update.md`.

---

## 2. The two defaults

`MVP-SPEC.md:109` fixes them, and they are compiled in as `DEFAULT_TSA_URLS`
(`crates/antseal-anchor/src/tsa.rs:94-103`):

| authority | endpoint | evidence |
| --- | --- | --- |
| **FreeTSA** | `https://freetsa.org/tsr` | ECDSA P-384 signer; live capture 2026-08-02, `HTTP 200`, nonce echoed (`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:36`) |
| **DigiCert** | `http://timestamp.digicert.com` | RSA-4096 signer; live capture 2026-08-02, `HTTP 200`, nonce echoed (`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:37`) |

Both were re-proved through antseal's own client on 2026-08-11T17:56Z: each
reached `state=Proven` against the pinned store with `root_store_version=1`,
anchored at `freetsa-root-ca` and `digicert-trusted-root-g4` respectively
(`testdata/anchors/A25-wave16-cycle/TSA-CAPTURE.log:18-19`).

### DigiCert is plain HTTP, and that is a requirement rather than a shortcut

`timestamp.digicert.com` **refuses connections on port 443**. Measured
2026-08-02T19:35:19Z and 19:35:51Z: `https://` times out after 20 s, port 443
does not answer at all, port 80 is open and serves normally
(`docs/decisions/D90-anchor-http-substrate.md:785-797`). A TLS-only client
cannot reach one of the two authorities the spec names.

This is safe here and only here. An RFC 3161 token is signed by the authority
and bound to a nonce antseal drew for that one request, so an attacker on the
network path can neither forge a token, replay an old one, nor substitute one
issued for a different digest. What plain HTTP does cost is **privacy**: a
passive observer learns that this machine timestamped a particular 32-byte
digest at a particular moment, and could link it to a bundle you publish later
(`docs/config.md:101-107`). If that matters to you, drop DigiCert from your
list — nothing else changes, and FreeTSA is HTTPS.

By contrast, the endpoints under `[verify]` in your config **must** be
`https://`, and antseal refuses the file at load if one is not. Their replies
carry no signature of their own, so transport is their only integrity control
(`docs/config.md:94-99`; `crates/antseal-cli/src/config.rs:541-553`).

---

## 3. Documented alternates, with their caveats

`MVP-SPEC.md:109` names three. All were captured live on **2026-08-02**;
the caveat column says for each whether the constraint was **measured** here
or is **published by the operator and never tested** — the same distinction
`docs/anchors/real-smoke-runbook.md:62-78` draws, and it is not a formality:
a limit nobody has approached is a limit nobody has confirmed.

| authority | endpoint | root in store v1 | caveat | measured or published | date |
| --- | --- | --- | --- | --- | --- |
| **DFN** | `http://zeitstempel.dfn.de` | yes — `dfn-verein-community-root-ca-2022` | **non-commercial use only** (operator's terms) | **published** | 2026-08-02 |
| **Sectigo** | `http://timestamp.sectigo.com` | yes — `sectigo-public-time-stamping-root-r46` | **~15 s minimum spacing** between requests | **published** — never approached at capture (`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:47-49`) | 2026-08-02 |
| **SwissSign** | `http://tsa.swisssign.net` | **NO — quarantined** | **~10 requests/day**; and its root is not compiled in, so its tokens reach `internally-consistent-only` and count for nothing | quota **published** — never approached (`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:47-49`); the quarantine is **measured** (`crates/antseal-core/src/anchor/chain.rs:1488-1493`) | 2026-08-02 root capture; quarantine re-asserted continuously by the test suite |

Read the SwissSign row twice before configuring it. Its root
`swisssign-signature-services-root-2020-2` is **deliberately not compiled in**:
the vendor's own download endpoint answered `HTTP 403` from every attempt, so
the root rests on an archive snapshot and the token's own copy rather than on a
live first-party fetch (`crates/antseal-core/src/anchor/roots/PROVENANCE.md:251-297`).
The consequence is stated there in as many words: a user who configures **only**
quarantined authorities gets a **hard pre-payment seal abort**, not a weaker
bundle (`crates/antseal-core/src/anchor/roots/PROVENANCE.md:259-266`). Loud and recoverable, by design. The test
that pins it verifies a real SwissSign token twice — `proven` against an
injected store holding its root, `internally-consistent-only` against the store
antseal actually ships.

### Sectigo and Entrust are one authority, not two

`timestamp.entrust.net` is **served by Sectigo**. The two captures carry the
same signer certificate — issuer `CN=Sectigo Public Time Stamping CA R41`,
serial `0xE74EF255B0504FFADBA6DFF7FC8BA315` — measured **2026-08-02**
(`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:51-54`; both fixtures
committed as `D60-tsa-{entrust,sectigo}-resp.tsr`).

Three consequences, and the third is the one that costs money:

- Configuring both gives you **one** authority behind two names, never two
  independent anchors. One key compromise, one revocation, one outage takes out
  both.
- Sectigo's ~15 s spacing applies **across both names**
  (`docs/anchors/real-smoke-runbook.md:80-86`).
- Pinning the Sectigo root also covers Entrust, so an Entrust token does chain
  (`crates/antseal-core/src/anchor/roots/PROVENANCE.md:245-248`) — it simply
  is not a second opinion.

antseal detects this without being told: two tokens are from the same authority
when their signer certificates share an `(issuer, serialNumber)` pair, and the
degradation report counts **distinct authorities** rather than distinct URLs.
The abort threshold itself is unchanged by the collapse — see §5.

### Four more endpoints that are live and are not in the list above

All four answered `HTTP 200` with `PKIStatus: granted` and the request nonce
echoed exactly, captured **2026-08-02**
(`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:41-44`, granted-and-echoed at
`:46`). They are recorded here because they are real options — and because
two of them are traps a reader would otherwise walk into.

| authority | endpoint | what antseal actually does with its token |
| --- | --- | --- |
| **Apple** | `http://timestamp.apple.com/ts01` | **REFUSED.** Its `SignerInfo.digestAlgorithm` is SHA-1, which antseal does not accept in any position; the token is well-formed and the refusal is a named policy decision, `anchor-digest-alg-unsupported`, never a signature failure (`crates/antseal-core/tests/anchor_real_tokens.rs:303-310`) |
| **GlobalSign** | `http://timestamp.globalsign.com/tsa/r6advanced1` | verifies cryptographically, but its root is not among store v1's four, so the chain closes against nothing pinned → `internally-consistent-only`, counting zero |
| **Certum** | `http://time.certum.pl` | same as GlobalSign: verifies, root not pinned, counts zero |
| **Entrust** | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | chains (Sectigo's root is pinned) — but it **is** Sectigo, so it is not an independent second anchor |

Eight of the nine authorities captured verify at the signature stage and one
does not; the loop that asserts it names Apple explicitly and requires the
failure to carry the algorithm code rather than a forgery code
(`crates/antseal-core/tests/anchor_real_tokens.rs:273-297`).

Two of those rows are on a weaker footing than the others, and it is worth
saying which. Apple's refusal and the Sectigo/Entrust collapse are each pinned
by a test named for them. The GlobalSign and Certum rows are read off the
root store instead: their roots are demonstrably not among store v1's four, and
§1's rule then decides the outcome — the same rule SwissSign demonstrates on
real material. No test is named for either one.

**None of the four is recommended today.** Apple cannot be used at all; adding
GlobalSign or Certum to your list without also getting their roots into the
store buys you extra HTTP requests and no extra evidence. If you want one of
them to count, that is a root-store change — a reviewed, versioned append with
its own provenance record (`docs/anchors/root-store-update.md`), not a config
edit.

---

## 4. Configuring your own list

The slot is `[anchors] tsa_urls` in `config.toml`, which lives **in the vault
directory** — `~/.antseal/config.toml`, or `$ANTSEAL_DIR/config.toml`
(`docs/config.md:1-11`). `antseal init` writes the initial file; edit it by
hand afterwards.

```toml
[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]
```

The behaviour, read off the implementation rather than off intent:

- **A non-empty list replaces the built-in defaults wholesale.** It is not
  merged with them and not appended to them. An **absent or empty** key means
  the two defaults (`crates/antseal-anchor/src/tsa.rs:111-141`, the single
  function every consumer collapses through).
- **Duplicates are removed** before any request goes out, by exact string
  match. Two identical entries would otherwise send two requests to one
  authority inside one second — precisely what a spacing caveat forbids — and
  report two verified tokens where you hold one piece of evidence
  (`crates/antseal-anchor/src/tsa.rs:112-126`).
- **Every entry is parsed at config load**, through the same endpoint parser
  the HTTP client uses, under a policy that allows plain HTTP because DigiCert
  requires it (`crates/antseal-cli/src/config.rs:517-528`). A URL with no host
  (`http:///tsr`), an unusable scheme, or embedded credentials
  (`http://user:pw@host/`) is refused **at load**, naming the key and the line
  — exit code **17**, class `malformed-config` — rather than surfacing as a
  failed anchor midway through a seal
  (`crates/antseal-cli/tests/snapshots/cli-errors.display.txt:43`).
- **A malformed config is never silently ignored.** It is a hard error on
  every command; a silently dropped override is worse than a loud stop
  (`docs/config.md:12-20`).
- **`seal` answers both of its config questions from a single read.** The
  effective network and this TSA list come from one `load()`, so an invocation
  can never resolve its network from one read of the file and its endpoints
  from another (`crates/antseal-cli/src/commands.rs:280-286`). Stated exactly,
  because it is easy to over-read: the *process* reads `config.toml` twice —
  once at dispatch, which is where a malformed file hard-fails every command
  (`crates/antseal-cli/src/lib.rs:127`), and once inside `seal`
  (`crates/antseal-cli/src/commands.rs:286`). What is guaranteed is that the
  two answers `seal` acts on come from the same read, not that the file is
  opened once. There is exactly one place in the product that turns config
  into an anchor-stage endpoint set
  (`crates/antseal-cli/src/commands.rs:394-397`).
- **Unknown keys and sections are warnings**, printed to stderr, so a config
  written by a newer antseal still loads. Invalid *values* for recognised keys
  are hard errors.

### Two things configuration cannot do for you

**It cannot make an unpinned authority count.** Re-read §1. The list decides
who is *asked*; the compiled root store decides whose answer is *evidence*.

**It cannot space your requests across runs.** Within one seal each distinct
endpoint is contacted exactly once, so no spacing rule can be broken by a
single seal. Honouring a spacing rule *between* invocations would need a
persisted last-contact time, which antseal does not keep
(`crates/antseal-anchor/src/tsa.rs:66-75`). So if you configure Sectigo — or
Entrust, which is Sectigo — and run two seals within about fifteen seconds,
the second request may be refused by the authority, and antseal will not have
paced it for you. Space them yourself.

---

## 5. The minimum-anchor policy: at least one token, or the seal aborts

The gate is one line of policy and it is worth stating plainly:

> A seal proceeds only if **at least one** timestamp token passed full
> verification. Otherwise it aborts — **before** anything is paid or uploaded.

The threshold is a named constant, `MIN_VERIFIED_TSA_TOKENS = 1`
(`crates/antseal-anchor/src/submit.rs:292`), and the gate compares it against
the count of tokens that verified in core, never against the number of
endpoints tried (`crates/antseal-anchor/src/submit.rs:252-283`). The
Sectigo/Entrust collapse of §3 does not change the threshold — two endpoints
resolving to one authority still clear a threshold of one — it changes what
the report is allowed to claim.

**Where the gate sits in the seal is the whole point.** The anchor stage runs
after you have consented to the cost and strictly before the payment call, so
a total anchor failure costs you nothing:

```
canonicalize → encrypt → sign → address → quote → YOUR CONSENT
    → anchor stage (OTS submits first, then TSA captures)
    → THE GATE  ←  aborts here, with zero spent
    → pay → upload
```

OTS calendar submits run before TSA captures deliberately: an OTS submit can be
re-issued later at no cost if the gate then aborts, while a TSA capture
consumes a rate-limited request. Doing the cheap, abortable half first keeps a
failed gate from having burned the scarcer resource
(`crates/antseal-anchor/src/submit.rs:31-38`).

When the gate refuses, the message names every endpoint that failed, verbatim,
because your next action is to look at those URLs
(`crates/antseal-anchor/src/gate.rs:184-196`):

```
the minimum-anchor policy was not met: 0 of N TSA endpoint(s) produced a
verified token, so nothing was paid for.
  <every per-endpoint failure, one per line>
Re-run when an endpoint recovers, or pass --force-degraded to seal with a
loudly recorded degraded anchor set.
```

The process exits **22**, class `anchor-gate-abort`
(`crates/antseal-cli/tests/snapshots/cli-errors.display.txt:53-54`), which
makes it a scriptable condition. The usual cause is transient: an authority is
down, or your network is. Re-running is the normal remedy.

### A failure is downgraded, never swallowed

antseal does not quietly drop an authority that did not answer. Every endpoint
appears in the seal report with its own outcome, and the failure classes are
kept distinct because they call for different responses — a transport failure
may be transient; a non-granted status is the authority declining, with its
own reason; an unverifiable token is that authority misbehaving or something on
the wire rewriting it; and a well-formed token that reaches no pinned root is a
configuration or root-store fact rather than an incident
(`crates/antseal-anchor/src/tsa.rs:144-200`).

This is the committed golden rendering of a seal that lost its only authority
and proceeded anyway
(`crates/antseal-cli/tests/snapshots/seal-degraded-report.txt`, produced by
`crates/antseal-cli/src/seal_run.rs:163-215`):

```
  Anchors:
    tsa http://127.0.0.1:<port> — FAILED [http] http://127.0.0.1:<port>: HTTP 503 (39 body byte(s))
    0 of 1 TSA endpoint(s) returned a verified timestamp token; 0 calendar route(s) accepted a pending attestation to upgrade later.
  WARNING: --force-degraded: this seal proceeded with ZERO verified timestamp tokens. It records that the holder of this key possessed this content, and that the content is intact — it does not establish a time attested by any independent party. The payment receipt is supporting evidence only.
  DEGRADED ANCHOR SET — recorded on this work:
    tsa http://127.0.0.1:<port> [http] http://127.0.0.1:<port>: HTTP 503 (39 body byte(s)) (<elapsed> ms)
    tsa: 0 verified token(s) from 0 distinct TSA(s); ots: 0 distinct calendar(s)
```

Note the last line. Verified **tokens** and distinct **authorities** are
reported as two separate quantities, and calendar routes as a third. None of
the three is added to the others, and none is called "independent" — because a
count of endpoints is not a count of independent attesting parties.

---

## 6. `--force-degraded`, and what it costs

`--force-degraded` converts the abort into a loud proceed. Its help text is
*"Proceed even if fewer than one TSA token was obtained (records a degraded
anchor set, loudly)"* (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:136-137`).

**It never adds evidence and never suppresses a report line.** It changes an
abort into a proceed and nothing else
(`crates/antseal-anchor/src/submit.rs:46-48`).

What you get instead:

- The seal completes. You pay, and the upload is permanent and irreversible.
- The warning above is printed at seal time and cannot be turned off.
- `degraded` is recorded on the work in the vault
  (`crates/antseal-cli/src/vault/store.rs:209-210`) and is read back **from the
  record**, not from the flag you typed — `list` reads `record.degraded`
  (`crates/antseal-cli/src/listing.rs:569`) and so does `status`
  (`crates/antseal-cli/src/status.rs:411`) — so the three surfaces cannot
  disagree about it later.
- With zero tokens the work is **UNANCHORED**. `list` badges it; `status`
  prints *"UNANCHORED — integrity and signature only, no provable time"*
  (`crates/antseal-cli/tests/snapshots/status-report.txt:26-28`), and so does
  any bundle you reveal from it
  (`crates/antseal-core/tests/snapshots/verdict-wording.txt:11`).
- The Arbitrum payment receipt does not rescue this. It renders in its own class, "supporting evidence — no independently proven time", and is never eligible for the headline.

**It is not refused on mainnet.** `--no-anchor` — the development shortcut — is
refused on a permanent network at three independent layers, so a paid permanent
seal can never be minted with the gate bypassed
(`crates/antseal-anchor/src/submit.rs:39-45`). `--force-degraded` carries no
such restriction (`crates/antseal-anchor/src/submit.rs:252-283`): you can spend
real money on a permanent seal that establishes no time. That is a deliberate
escape hatch for the case where you would rather have a dated-by-nothing
permanent record than none at all, and it is your judgement to make.

Almost always, the better move is to wait and re-run. An anchor failure is
cheap, reversible and usually transient — and an aborted seal leaves an
incomplete work that the next run with the same inputs **auto-resumes** rather
than sealing a second time (`crates/antseal-cli/src/seal_resume.rs:42-47`). The
gate's own message does not say so today; it tells you to re-run, which is the
right advice, and this is what re-running actually does.

---

## 7. Aging bundles: expired is not invalid

Timestamp certificates expire. Yours will outlive them, and that is fine.

antseal evaluates a token's certificate chain **at the token's own `genTime`**
— the moment the authority says it stamped — not at the moment you happen to
verify. A token whose chain was valid at stamping and whose certificate has
since expired renders `valid-at-stamping-cert-since-expired`, a *distinct*
state from `invalid`, and it stays **headline-eligible**: it still carries an
independently proven stamping time
(`MVP-SPEC.md:130`;
`crates/antseal-core/tests/snapshots/verdict-wording.txt:16`). Aging bundles
must not silently rot, and this is the mechanism that stops it.

Two consequences worth carrying:

- **A `.sealproof` bundle never needs re-issuing** because a certificate
  aged out. There is no renewal, no re-stamping, no expiry date on your
  evidence.
- **Verification is offline.** The roots are compiled into antseal, so
  checking a token needs no network, no clock service and no authority that is
  still in business. Open a bundle at `https://antseal.org/` or run
  `antseal verify` — the offline verdict is the same either way.

### A local clock never decides whether a token is valid

The obvious sanity check — *"a timestamp cannot be from the future, so reject
it if `genTime` is later than when I fetched it"* — is **wrong**, and antseal
deliberately does not do it.

The machine that captured every timestamp fixture in this repository had a slow
clock, and the tokens' `genTime` values run roughly **two minutes ahead** of
that machine's own reading of the time. The capture log records the
measurement, and the warning it draws from it, in its own words:
`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:16-28`. A per-token
re-measurement of the two frozen artifacts is recorded separately at
`testdata/vectors/v1/anchor/README.md:142-147` — a smaller figure than the
log's headline, because the log quotes the offset to three unrelated hosts
rather than a property of the tokens.

An implementer writing that check would reject **every** token in this
repository, and would reject real tokens on any machine whose clock is behind
by more than an authority's response latency — a common and entirely benign
condition. So antseal records the fetch date as provenance metadata and never
as a validity input, and the pre-payment gate's verdict does not depend on the
host clock at all (`crates/antseal-anchor/src/tsa.rs:34-59`). The regression
test is driven by a real committed token whose fetch date precedes its
`genTime`.

If your own tooling compares a token's `genTime` against a local clock, that
tooling is wrong, not the token.

---

## 8. Practical guidance

**Leave the defaults alone unless you have a reason.** FreeTSA and DigiCert
are two independent organisations, two independent roots, two independent
signing keys, and both are pinned. That is the configuration every part of
this project is measured against.

**If you want a third opinion**, add `zeitstempel.dfn.de` — its root is pinned
and it chains — but read its non-commercial terms first and decide whether
your use qualifies. Sectigo is pinned too, at the cost of the spacing caveat
that antseal will not enforce for you between runs.

**Do not treat two names as two anchors.** Check whether two endpoints you are
considering are really one operator. The Sectigo/Entrust case is the one this
project measured, but resale and white-labelling are ordinary in this market,
which is why antseal keys authority identity on the signer certificate rather
than on the URL.

**Privacy, if it matters.** Every request tells an authority that this machine
timestamped one 32-byte digest at one instant. The digest reveals nothing about
your content, but the pattern is a fact about you. Fewer authorities means
fewer observers; one is the minimum the gate accepts.

**Expect endpoint rot and treat it as normal.** URLs move, services close,
roots rotate. The gate makes that a cheap, loud, pre-payment failure rather
than a silent weakening — which is the whole reason it sits where it sits.

---

## Where the evidence for this page lives

Nothing above is asserted from memory. The primary sources:

| claim | source |
| --- | --- |
| defaults, alternates, root-store requirement | `MVP-SPEC.md:109` |
| nine live authorities captured, all `200` + granted + nonce echoed | `testdata/anchors/A25-bootstrap/D60-CAPTURE.log:36-46` |
| spacing and quota never approached at capture | `testdata/anchors/A25-bootstrap/D60-CAPTURE.log:47-49` |
| Entrust is served by Sectigo — issuer and serial | `testdata/anchors/A25-bootstrap/D60-CAPTURE.log:51-54` |
| clock skew, and the check not to write | `testdata/anchors/A25-bootstrap/D60-CAPTURE.log:16-28` |
| DigiCert has no port 443 | `docs/decisions/D90-anchor-http-substrate.md:785-797` |
| the four pinned roots, asserted as data | `crates/antseal-core/src/anchor/roots/mod.rs:360-376` |
| SwissSign's quarantine and its user-visible cost | `crates/antseal-core/src/anchor/roots/PROVENANCE.md:251-297` |
| Apple's SHA-1 refusal, by name | `crates/antseal-core/tests/anchor_real_tokens.rs:273-310` |
| the gate, its threshold and its ordering | `crates/antseal-anchor/src/submit.rs:31-48, 252-292` |
| the degraded rendering, byte for byte | `crates/antseal-cli/tests/snapshots/seal-degraded-report.txt` |
| the config slot and its validation | `crates/antseal-cli/src/config.rs:106-111, 517-528`; `docs/config.md:48-107` |
| root-store update procedure | `docs/anchors/root-store-update.md` |
| how a real-endpoint run is conducted | `docs/anchors/real-smoke-runbook.md` |
