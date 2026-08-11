# D59 — Request-nonce persistence semantics: capture-time only, verdict-inert on the bundle path

- **Status: RESOLVED — the nonce is generated in `antseal-anchor` (8 bytes,
  OS CSPRNG, never derived from `W`), compared in `antseal-core` only when
  an expected nonce is supplied, persisted in the vault's per-anchor capture
  record, and is **verdict-inert** on every bundle path: with
  `expected_nonce = None` the `TSTInfo` nonce is parsed and then ignored, and
  its presence or absence may not change any `AnchorState`, any error code,
  any headline eligibility, or one byte of report v1. A capture-time mismatch
  makes that TSA's outcome a typed failure that does not count toward A20's
  ≥1-verified-TSA gate — firing after permanence consent and strictly before
  `pay`, so nothing is spent. The register's conclusion survives; **its stated
  reason does not**: bundles *do* carry the nonce, inside the signed
  `TSTInfo` inside §7.9 key 1 — measured today at offset 169 of a 4 642-byte
  FreeTSA response. What the verifier lacks is not the nonce but the second
  copy to compare it against, and that correction is what settles §1, §3 and
  §5. A bundle-side *request*-nonce field is additionally ruled a permanent
  non-rule for every future version, on §7.6.1's own grounds.**
- **Date: 2026-08-02** (M2 Anchors planning round; register TODO.md:571,
  `tasks/A.md:365` A-OD7)
- **Owning tasks: A8** (the core-side comparison and its inertness), **A10**
  (generation, capture-time comparison, the typed failure), **A2** (the
  capture-record struct), with **U9/U22** (vault persistence) and **U12/D47**
  (export)
- **Blocks: A8, A10** (both name A-OD7 in their Deps)

## Context

`tasks/A.md:365` registers A-OD7 as:

> **A-OD7 — Request-nonce persistence semantics**: nonce checked at capture
> time (vault stores it); bundles do not carry request nonces (per the
> line-114 bundle contents list), so third-party verification checks
> messageImprint only. Record as a signed-off decision.

The entry says "sign off", which the house rule says to distrust. Its
*conclusion* — third-party verification compares messageImprint and not the
nonce — is correct and is ratified below. Two of its supporting statements
are wrong or under-specified, and the second of them changes the privacy
analysis and the residual-risk statement entirely.

MVP-SPEC.md line 109 is the reason this decision has to exist at all. Its
verification clause reads:

> Verification (in `antseal-core`, WASM-safe): full CMS SignedData —
> signed-attributes check, **messageImprint + nonce match**, ESSCertID, EKU
> `id-kp-timeStamping`

while line 114's bundle-contents enumeration carries no request nonce. Read
literally, line 109 asks the WASM verifier to perform a check whose input it
is never given. D59 resolves that as: **line 109's clause describes the
capture path**, and the bundle path performs every other item on that list.

## The register's framing, corrected

### Correction 1 — the frozen registry confirms the absence, and does so more strongly than the entry claims

The entry cites "the line-114 bundle contents list". The authority is
`docs/format/registry-v1.md`, and it is stronger than a prose list:

- **§7.9** assigns the TSA anchor artifact keys **0–3 only** — `status`,
  `token`, `intermediates`, `fetch_date` — and `4–23` are reserved.
- **§12** records the enumeration as closed, verbatim: *"line 112's
  enumeration for a TSA artifact ('TSA tokens + intermediate certs, fetch
  dates') is **exhaustive**: §7.9 assigns keys 0–3 and nothing more"*.
- **§7.9** further records that key 4 specifically *"is plain reserved, and
  its absence is checked (D8 §1)"*, and that *"Present in v1 input, key 4
  raises F10's ordinary reserved-slot error"*.

So a bundle-side nonce field is not merely unlisted in v1 — it is
**unrepresentable**, and the rejection is already executed by
`crates/antseal-core/tests/bundle_schema.rs:192`
(`tsa_intermediates_may_be_empty_and_key_4_is_reserved`), whose failure code
is `bundle-reserved-key`. No new v1 test is required to hold this half.

### Correction 2 — "bundles do not carry request nonces" is true of the registry's keys and false of the bytes

RFC 3161 §2.4.2 requires the TSA to echo the request nonce into `TSTInfo`,
which the TSA then *signs*. `TSTInfo` is the eContent of the CMS `SignedData`
that §7.9 key 1 carries verbatim as an opaque `bstr`. The nonce therefore
travels in every bundle that carries a token — signed, authentic, and
readable by any verifier.

Measured, this session (see Evidence 1): the nonce occupies **8 content
octets at offset 169** of a 4 642-byte FreeTSA `TimeStampResp`, encoded
`02 08 52 e8 9c 47 fc 42 60 54`.

The consequence is not cosmetic. It means:

- the verifier is not missing *the nonce*; it is missing **the second copy**
  — the request — and a one-copy equality check is not a check;
- **persisting the nonce discloses nothing a shipped bundle does not already
  disclose** (§3 below), which is the whole of the privacy question the brief
  raised;
- the residual risk is not "a value is absent" but "a comparison is
  unwitnessed" (§5), which is a different and more precisely stateable
  property.

### Correction 3 — `tasks/A.md` A4's "≥ 64 bits" is a floor with no ceiling, and the width is a permanent per-bundle cost

A4's Do says *"a caller-supplied random nonce (≥ 64 bits)"*. Because the
value is echoed into a signed token that ships in every bundle forever, its
width is a permanent wire cost and a permanent per-anchor unique tag, not a
free security parameter. D59 fixes it at exactly 8 bytes and gives the
reason (§4 of the Decision) rather than leaving an open-ended floor that an
implementer would reasonably resolve upward by analogy with the project's
16-byte salts — where the analogy does not hold, because salts are secret
and this value is published.

## Evidence

### 1. The nonce round-trip, executed against the default TSA

Authorised by the round's network permission (RFC 3161 submissions to public
TSAs with a throwaway digest from the documented fixed test seed). The digest
is `digest-A.bin` from `testdata/anchors/A25-bootstrap/` — the committed
golden-vector `anchor_digest`
`083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df`, already
submitted publicly to three OTS calendars by the orchestrator at
2026-08-02T19:16Z.

Request built at **2026-08-02T19:26:47Z**:

```
$ openssl ts -query -digest 083f87df…69df -sha256 -cert -out req.tsq
$ openssl ts -query -in req.tsq -text
Version: 1
Hash Algorithm: sha256
Message data: 08 3f 87 df 00 fd 5c 70 … da bd 69 df
Policy OID: unspecified
Nonce: 0x52E89C47FC426054
Certificate required: yes
```

Request size **69 bytes**; the nonce occupies 8 content octets at request
offset 58.

Submitted at **2026-08-02T19:26:54Z**, `https://freetsa.org/tsr`,
`Content-Type: application/timestamp-query`, `http=200`,
`bytes=4642`, response `sha256 =
0af3b868d6617d79dcd324b5d8821fa6700e4e20e26e7b4dc93e8639fb94f123`:

```
$ openssl ts -reply -in resp.tsr -text
Status: Granted.
Version: 1 · Policy OID: tsa_policy1 · Hash Algorithm: sha256
Message data: 08 3f 87 df … da bd 69 df
Serial number: 0x06B640ED
Time stamp: Aug  2 19:29:03 2026 GMT
Nonce: 0x52E89C47FC426054
TSA: DirName:/O=Free TSA/OU=TSA/…/CN=www.freetsa.org/…
```

Byte-level location inside the response DER:

```
response bytes                 : 4642
nonce (8 B)                    : 52e89c47fc426054
offset of nonce in response DER: 169
DER around it                  : 01ff 0208 52e89c47fc426054 a0820113
occurrences                    : 1
offset of nonce in request DER : 58 of 69 bytes
```

`01 ff` is `ordering BOOLEAN TRUE`; `02 08 …` is the `nonce INTEGER`;
`a0 82 01 13` opens the `[0] tsa GeneralName`. This is the `TSTInfo` nonce
field, in the signed eContent, inside the token §7.9 key 1 carries.

**What this establishes**: the echo is real on the project's own default TSA;
the value is signed; and any bundle carrying this token carries this nonce.

### 2. The registry rows, quoted

`docs/format/registry-v1.md` §7.9, the whole key table:

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (never trusted) |
| 1 | `token` | bstr | req | var — DER TimeStampResp/token, opaque |
| 2 | `intermediates` | array | req, may be empty | bstr elements — DER certs, opaque |
| 3 | `fetch_date` | uint | req | POSIX seconds (§3) |
| 4–23 | — | — | — | reserved |

There is no nonce key, no slot named for one, and the band rejects in v1.

### 3. Where in the seal sequence a capture-time mismatch fires

MVP-SPEC.md line 34 (normative order) and `tasks/U.md` U22 agree, and U22
states the insertion point in terms:

> Insert the anchor-submission stage into U13's pipeline **between consent
> and `pay`**

Line 34's own words: *"→ **permanence consent** … → **anchor submission with
the ≥1-TSA-or-abort gate** … → **`pay`**"*, and *"Anchoring fails cheaply and
reversibly (no money spent); only after the anchor gate passes does anything
paid or permanent happen"*.

So the mismatch fires **after** the user has consented to permanence and
**strictly before** the single irreversible paid step. A20's
`evaluate_seal_gate` then aborts pre-payment if the mismatch takes the
verified-TSA count to zero (its Accept row: *"Abort path demonstrably
precedes payment"*).

### 4. The dev machine's clock is 129 s slow — measured, and it forbids a check an implementer would otherwise add

Two independent public servers, read at **2026-08-02T19:27:37Z** local:

```
local_utc                 = 2026-08-02T19:27:37Z
freetsa.org  Date header  = Sun, 02 Aug 2026 19:29:46 GMT
www.google.com Date header= Sun, 02 Aug 2026 19:29:46 GMT
local_utc_after           = 2026-08-02T19:27:38Z
```

Local is **129 seconds behind** both. Applying that offset to Evidence 1:
the response was received at true ≈ 19:29:04Z and the token's `genTime` is
19:29:03Z — FreeTSA is accurate to about a second, and **this machine is
wrong by over two minutes**.

An `A10` implementer writing the obvious capture-time sanity check
`gen_time <= fetch_date` ("a token cannot be stamped after we received it")
would reject **every** FreeTSA token captured on this machine. Registry §7.8
already froze the wire-side non-rule — *"no ordering relation between
`fetch_date` and the header's own timestamp"*, binding §7.9's key 3
identically — and this is its capture-side dual, now measured rather than
argued. The Decision makes it a normative prohibition (§6).

### 5. Vault export: what actually leaves the machine

`docs/decisions/D47-vault-export-format.md` §Payload: the export carries
*"the full logical vault state: … every work record — journal state …,
**anchors**, receipts, paths, costs, bookkeeping"*. So anchor capture records
leave the machine whenever a user exports.

The A2 capture record's other fields are `anchor_digest`, the endpoint URL,
and the fetch date. Each of those is strictly more identifying than 8 random
bytes: `anchor_digest` is the join key a TSA's own logs are indexed by
alongside the token's `serialNumber` (`0x06B640ED` above), and both of those
ship in every bundle regardless. D47's residual risk already states the
governing fact — *"a stolen export ≡ a stolen vault (same passphrase, same
wrap factor)"*.

D50 is checked and is not engaged: it ships the keyfile wrap only and defers
the OS keystore, so nothing about the export's portability changes here.

**Marginal disclosure of persisting the nonce: zero**, in both the
shipped-token case (Correction 2 — it is already in the bundle) and the
failed-capture case (the record's other fields dominate it).

## Decision

### 1. The core-side contract (A8) — comparison is conditional, the field is verdict-inert

`antseal-core` exposes exactly one token-verification entry point, taking the
expected nonce as an **`Option`**:

```rust
expected_nonce: Option<&[u8]>
```

- **`Some(n)` (capture path only).** `TSTInfo.nonce` MUST be present and its
  DER INTEGER **content octets** MUST equal `n` byte-for-byte. Absent or
  unequal ⇒ the distinct error of §5 below. Byte comparison is exact
  value comparison here and needs no bignum: DER INTEGER encoding is
  canonical, A4 emits strict DER, and A5 rejects non-minimal encodings, so
  two encodings are equal iff the values are.

  **`n` is the encoded form, not the draw.** `expected_nonce` carries the
  DER INTEGER **content octets A4 emitted** — 8 bytes, or 9 when the sign
  prefix was needed (§4). A10 must pass those, never the raw 8 drawn bytes;
  passing the draw would make every high-bit nonce mismatch against a TSA
  that echoed correctly. This is the one place the two representations are
  observably different and it is the easiest thing in this record to get
  wrong.
- **`None` (every bundle path, always).** The field is **parsed** — a
  malformed `nonce` is a malformed token and fails A5's strict-DER class like
  any other field — and then **ignored**. Its presence, its absence, and its
  value have **no** effect on:
  - which of the seven `AnchorState` variants is produced
    (`crates/antseal-core/src/verify/report.rs:258`);
  - any error code;
  - `verified_time_unix`, `source`, `fetch_date`, or any other
    `AnchorResult` field (`report.rs:322`);
  - headline eligibility (R17's aggregation);
  - one byte of report v1.

  **No state is minted, renamed or respelled**, and no existing state changes
  meaning. `AnchorState::ALL` stays at 7 and registry §6.1's wire values stay
  `0..=6`.

**Presence is not meaningful, and must never be made meaningful.** The
decisive reason, stated so it is not re-opened: *any rule keyed on nonce
presence is a rule an adversary passes for free and an honest party can
fail.* A bundle assembler who wants a nonce present simply includes a token
that has one; a sealer who used a nonce-free request, or imported a token
from other tooling, would be rejected for a property that proves nothing.
That is the wrong direction for every rule in a design whose first premise is
that the sealer is the adversary (MVP-SPEC.md line 121).

**Do not mint a nonce-length cap.** Per A27/D84's F1–F4 contract, a limit is
only chosen where one is genuinely open; this one is not. The field is
already bounded by `MAX_TSA_TOKEN_BYTES = 1 048 576`
(`crates/antseal-core/src/codec/caps.rs`, D10-frozen, consumed by name) and
by A5's strict-DER parse. The nonce MUST be handled as an opaque content-octet
slice — **never converted to an arbitrary-precision integer**, which would be
an allocation vector over an attacker-chosen INTEGER length and would drag a
bignum crate into the WASM-safe graph for nothing.

### 2. The capture-side contract (A10) — a mismatch is a per-TSA failure that does not count

In `antseal-anchor`, per configured TSA, in the existing capture loop:

1. draw the nonce (§4), build the request via A4's
   `build_timestamp_req(anchor_digest, nonce)`;
2. POST, parse;
3. verify **in `antseal-core`** with `expected_nonce = Some(nonce)`, against
   the pinned roots and `anchor_digest`;
4. on mismatch, emit the **typed failure** of §5 for that endpoint.

Consequences, exactly:

- **It does not count toward A20's gate.** A10's contract — *"only a fully
  verifying token counts as a success toward the seal gate"* — already
  covers this, and a nonce mismatch is a verification failure on the capture
  path by construction.
- **The token is not stored as an anchor artifact.** It never reaches a
  bundle. The *failure* is recorded in the degradation report and in the work
  record's outcome list, with the endpoint named.
- **It does not abort the other endpoints.** A10 Accept row 2 — *"One TSA's
  failure never aborts or delays the others"* — binds here unchanged.
- **Payment position**: after permanence consent, strictly before `pay`
  (Evidence 3). If it takes the verified count to zero, `evaluate_seal_gate`
  aborts with the anchor-gate exit code and **no money is spent**;
  `--force-degraded` converts the abort to proceed-with-degradation exactly
  as for any other anchor failure. D59 grants nonce mismatch no special
  treatment in the gate — only a distinguishable *name* (§5), because the
  user-facing meaning differs sharply from "the token was malformed".

### 3. Persistence — YES, in the capture record; and what it is for

A2's capture-record struct carries the nonce. Concretely, the field is

```rust
/// The RFC 3161 request nonce, exactly as sent (DER INTEGER content
/// octets). PUBLIC BY CONSTRUCTION: the TSA echoes it into the signed
/// TSTInfo, so every bundle carrying this token already publishes it.
/// Never secret material; never derived from `W`.
pub request_nonce: [u8; 8],
```

persisted by U9 in the work record's `anchors/<slot>` payload alongside the
token, endpoint and fetch date.

**What it is good for, given it can never be re-checked from a bundle:**

1. **Exact request reconstruction.** A4 is deterministic and
   golden-vectorable by design (*"Nonce generation stays in `antseal-anchor`
   … so this function is deterministic and golden-vectorable"*), so
   `(anchor_digest, nonce)` reproduces the exact 69 bytes that were sent.
   Without the nonce the request is unreconstructable, and a dispute or a bug
   report about a TSA's behaviour has nothing to replay.
2. **The join key into a TSA's own records**, beside `serialNumber`, if a TSA
   is ever asked to confirm it issued a token.
3. **The only place the check is re-runnable.** `status` can re-execute the
   capture-time comparison over the stored token — an integrity check of the
   *vault*, not of the token, and the honest limit of what "we checked the
   nonce" can ever mean after the fact.
4. **Disambiguating two tokens for one digest** across a retry or a D45
   resume, where the same `anchor_digest` is submitted twice.

**Privacy cost: none.** Evidence 5. The record's `anchor_digest`, endpoint and
fetch date dominate it in every direction, and in the ordinary case the value
is already inside the shipped token.

**Three normative riders on persistence:**

- **The nonce is NOT secret material** under project rule 6. It may appear in
  `--json` output, in `status` detail, in logs and in a bug report. Wrapping
  it in a zeroizing type would be wrong, not merely wasteful — it is
  published by the protocol.
- **The nonce MUST NOT be derived from `W`, from any HKDF label, or from any
  vault secret.** It is drawn fresh from the OS CSPRNG, per capture. A
  "deterministic nonce" — the tempting `HKDF(W, "tsa-nonce", …)` — would
  publish a PRF output under the vault master secret inside every bundle,
  once per anchor, forever. This is the sharpest footgun D59 closes.
- **No `secret-guard` exclusion is needed** (Q2): no magic literal is
  introduced and no fixture carries a nonce that was ever paired with real
  vault material.

### 4. Generation — 8 bytes, OS CSPRNG, in `antseal-anchor`

- **Length: exactly 8 bytes (64 bits).** It satisfies A4's `≥ 64 bits` floor
  at the floor, deliberately. The property the nonce buys is that *this*
  response answers *this* request across one HTTP round trip lasting about a
  second (Evidence 1: 1 s wall clock); 2⁻⁶⁴ per blind attempt inside that
  window is ample, and against an attacker who can *see* the request the
  nonce provides nothing at any width. Against that, the value is echoed into
  a signed token that ships in every bundle forever, so every extra byte is a
  permanent wire cost and a wider permanent per-anchor tag. It is also the
  interoperable width: openssl's own default is 8 bytes (measured, Evidence
  1), which is what the project's default TSAs see from the rest of the
  world. **The 16-byte analogy to `unit_salt`/`path_salt`/`file_salt` does
  not apply** — those are secret and hiding-critical (MVP-SPEC.md line 121);
  this one is published.
- **Source: the OS CSPRNG via the already-pinned `getrandom =0.4.3`.** No new
  dependency, no second RNG generation in the graph.
- **Home: `antseal-anchor`.** Stated explicitly rather than left inferred:
  `antseal-anchor` is the network crate and carries **no WASM-safety
  constraint** — it is not in the WASM verifier's graph at all, and the
  `core-dep-graph` lane's I/O/RNG-free scan is scoped to `-p antseal-core`.
  The constraint that *does* bind is the opposite one: **no RNG may enter
  `antseal-core`**, which is exactly why A4 takes the nonce as a parameter
  and must keep doing so. The `core-dep-graph` lane already enforces this
  mechanically; D59 adds no lane.
- **DER encoding trap**: the nonce is carried as an ASN.1 `INTEGER`, so the
  encoder MUST produce a canonical DER INTEGER from the 8 drawn bytes —
  prepend `0x00` when the high bit is set (giving 9 content octets, as in
  Evidence 1's `0x52…` which does not need it), and strip redundant leading
  zero bytes otherwise. The stored `request_nonce` is the **8 drawn bytes**;
  the comparison in §1 is against the *decoded content octets*, so A10 must
  compare against the same encoding A4 emitted, not against the raw draw.
  A golden vector pins this (§7).

### 5. The error code and its owner

One new code, appended:

```
anchor-tsa-nonce-mismatch
```

- **Prefix**: `anchor-` is hereby the A domain's prefix. It is not currently
  in `docs/testing/error-code-contract.md` §2's table, which lists
  `cbor-`/`manifest-`/`bundle-`/`crypto-`/`content-` and unprefixed R while
  its own header claims to be *"Normative for every component domain
  (F/C/G/S/A/R)"*. That gap is a finding (Q80) and must be closed in the same
  wave, since A21/Q18's six anchor rows all need it.
- **Distinctness**: it collides with nothing — no existing code contains
  `nonce`.
- **It carries no tamper row, and takes the contract's other route: a named
  owner — A10.** A tamper row is impossible by construction: a tamper row
  mutates a *bundle*, and no bundle mutation can reach this code, because the
  comparison only runs with `expected_nonce = Some(_)` and no bundle path
  supplies one. Recording it as owner-backed rather than row-backed is the
  contract's own provision and must be written down at registration, or the
  Q7 sweep will read it as an unclaimed code.
- **Why it is distinct from a generic verification failure**: a nonce
  mismatch means *the TSA answered a different question*, which is evidence
  of an active MITM or a caching proxy — not of a malformed or untrusted
  token. The degradation report must be able to say so. This is the same
  reason A10's Notes give for tolerating DigiCert's plain HTTP: *"token
  validity is established cryptographically and the nonce prevents
  stale-token replay"* — a rationale that is only true if the mismatch is
  actually distinguishable and actually gates.

### 6. Two normative prohibitions

**(a) No capture-time ordering check between `genTime` and the fetch
instant.** A10 MUST NOT compare the token's `genTime` against its own clock
in any direction — not `genTime <= fetch_date`, not a skew window, not a
warning. Evidence 4 measured this machine at 129 s slow, which would make the
obvious form reject every FreeTSA token captured here. Registry §7.8's frozen
non-rules bind the wire field; this is the same rule one step earlier. The
sealer's clock is not evidence — the whole product rests on that
(project rule 3: *timestamps come from independent anchors*).

**(b) A bundle-side request-nonce field is a permanent non-rule, in v1 and in
every version after it.** v1 already forecloses it structurally (Correction
1). D59 additionally rules it out for v1.x, on `docs/format/registry-v1.md`
§7.6.1's own grounds — this is the **sixth** instance of the pattern that
section's five rows and the D8 §1 `source`-string removal already establish:
*do not carry a sealer's claim next to the thing it claims about.* A
bundle-carried request nonce would be exactly that. The bundle is unsigned,
so the sealer (or any relay) writes it freely; a verifier comparing it
against the TSA-signed copy would learn only that the sealer copied one field
into another, and "the two match" would look like evidence while being
trivially forgeable. The comparison's whole value comes from the two copies
having *independent* origins — one from the requester's RNG, one from the
TSA's signature — and a bundle can only ever hold the second.

**No registry edit.** §7.6.1's row count stays at **six** and the F8
checked-absence test set is untouched: `docs/format/registry-v1.md` and
`registry-v1.json` are byte-frozen (Q14), and adding a seventh row would be a
freeze violation for a rule the reserved band already enforces. **This
document is the record**; a future v1.x amendment that opens the registry for
other reasons may cite it.

### 7. Tests that must exist, and what makes each fail

| test | file | what makes it fail |
| --- | --- | --- |
| `nonce_presence_does_not_move_the_verdict` | `crates/antseal-core/tests/anchor_tsa_nonce.rs` | Two tokens over the same digest and chain, one whose `TSTInfo` carries a nonce and one that does not, verified with `expected_nonce = None`, must yield **byte-identical report v1 output** (`serde_json` of the `AnchorResult`) and the identical `AnchorState`. Fails the moment any code path branches on the field — which is the exact defect the register's "sign off" framing would have shipped. It is **not** vacuous: run it against a build whose `None` arm rejects a nonce-free token and it goes red immediately. **Fixture constraint, or the test fails for the wrong reason**: both tokens must be minted by A24's mock TSA with identical `genTime`, `serialNumber`, `policy` and signer, and be placed in §7.9 artifacts with identical `fetch_date`, differing **only** in the presence of the nonce field — two naturally-captured tokens differ in serial and genTime, which would move `verified_time_unix` and produce a spurious red that an implementer would then "fix" by weakening the assertion to `AnchorState` alone, i.e. to the claim that is not the one at issue. |
| `expected_nonce_some_requires_presence_and_equality` | same | Capture-path arm: `Some(n)` against a token echoing `n` verifies; against a token echoing `n'≠n` yields `anchor-tsa-nonce-mismatch`; against a token with **no** nonce yields the same code. Fails if the implementation treats absence as "nothing to compare". |
| `nonce_is_compared_as_bytes_not_as_a_bignum` | same | A token whose nonce INTEGER is 1 024 content octets is rejected by A5's strict-DER/limit path without any allocation proportional to a decoded integer, asserted on the `parser_caps_alloc.rs` counting allocator. Fails if someone reaches for a bignum. |
| `vector_tsa_request_nonce_high_bit` | `crates/antseal-core/tests/anchor_der_vectors.rs` | Golden vector: `build_timestamp_req` over a fixed digest and the fixed nonce `0x80_00_00_00_00_00_00_00` must emit the canonical DER INTEGER with the `0x00` sign prefix (9 content octets), byte-exact. Fails on the naive encoder that writes the 8 raw bytes. Complements A4's existing fixed-nonce vector, which (with `0x52…`) never exercises the sign byte. |
| `capture_records_the_nonce_and_status_can_recheck_it` | `crates/antseal-cli/tests/anchor_capture_record.rs` | Round-trips a capture record through U9's store and re-runs the `Some(nonce)` comparison over the stored token. Fails if the field is dropped, truncated, or stored as the DER encoding where the raw draw was expected (or vice versa). |
| `mismatch_does_not_count_toward_the_gate_and_precedes_payment` | `crates/antseal-cli/tests/seal_anchor_gate.rs` | Mock TSA returns a granted, well-formed, correctly-chaining token echoing the **wrong** nonce; `evaluate_seal_gate` must abort with the anchor-gate exit code and `MockBackend` must record **zero** `pay` calls. Fails if the nonce check is skipped, or runs after payment, or if the mismatch is silently downgraded to a success. |
| `no_gen_time_ordering_check_exists` | `crates/antseal-anchor/tests/tsa_capture.rs` | Mock TSA returns a token whose `genTime` is **300 s after** the harness's fetch instant; capture must succeed. Fails the moment anyone adds prohibition (a)'s check. This is Evidence 4 turned into a tripwire. |

## Rationale

**Why the conclusion survives while the reason does not.** The register's
"third-party verification checks messageImprint only" is right, and it is
right for a reason the entry does not give. It is not that the verifier lacks
the nonce (it has it, Correction 2); it is that the nonce's protocol job —
RFC 3161 §2.4.1's freshness check for a client with no reliable clock — is a
property only the *requester* wants. A bundle verifier wants the opposite of
freshness: it wants **oldness**, and it obtains that from `genTime` under a
signature chained to a pinned root. Nothing about a response's timeliness
relative to a request that the verifier did not make bears on that.

**Why v1 accepts it — and this is not "the register said sign off".** Work
through what a replay actually buys, against a `messageImprint` that is
`anchor_digest = SHA-256(full manifest bytes incl. signatures)` over a
manifest containing a random `seal_id` and the sealer's pubkeys:

1. A token for *this* digest can only exist if someone previously stamped
   *this* digest — i.e. the sealer, or someone who already held the sealer's
   manifest bytes.
2. A replayed token is still a genuine TSA statement that this digest existed
   at that `genTime`. Replay does not fabricate a time; it **reuses a true
   one**.
3. The only party with a motive to replay — a MITM holding an older token for
   this digest — can at most make the bundle carry a slightly *earlier* true
   time than the capture. That is a nuisance (the attacker chooses among true
   times), not a forgery, and the capture-time check closes even that.
4. The case people reach for — "a sealer stamps early and assembles the
   bundle later" — is not an attack at all. It is the product working:
   antseal proves existence and priority, not authorship or assembly time.

So the missing bundle-side comparison forecloses no attack that the shipped
evidence chain does not already handle. v1 accepts it because there is
nothing to accept.

**Why "sign off" was still the wrong instruction.** Left as a rubber stamp,
this entry would have shipped three defects, each of which the analysis above
found and none of which the entry names: an implementer free to make nonce
*presence* meaningful on the bundle path (Decision 1); a nonce derived from
`W` for reproducibility (Decision 3); and the `genTime`-vs-clock sanity check
that Evidence 4 shows would break against the project's own default TSA on the
project's own machine. The ruling and the sign-off agree on the headline and
disagree on everything an implementer would actually have had to guess.

## Consequences for the blocked tasks

- **A8 — unblocked.** Its Do already says *"nonce equality is checked when an
  expected nonce is supplied (capture path — bundle verification passes
  `None` per A-OD7)"*; D59 ratifies that and adds the inertness obligation,
  the byte-not-bignum rule, and the no-new-cap rule. Its Accept row *"wrong
  nonce on the capture path"* stays; **add** the `None`-arm differential row
  (§7 row 1), which the current Accept list does not contain and which is the
  only row that can witness inertness.
- **A10 — unblocked.** Generation length/source fixed (§4); the typed failure
  named (§5); prohibition (a) added to its Do. Its Notes' DigiCert-over-HTTP
  rationale is confirmed as sound *conditional on* the mismatch actually
  gating, which §2 makes explicit.
- **A2 — one field fixed.** The capture-record struct's `request_nonce` is
  `[u8; 8]` with the public-by-construction doc comment of §3, and A2's
  `wasm32` Accept row is unaffected (the struct is data; no RNG enters core).
- **A4 — unchanged in signature**, with the sign-byte golden vector added
  (§7 row 4). Its floor prose should record the ruling ("exactly 8 bytes,
  D59") so the next reader does not resolve the floor upward.
- **A21/Q18 — unaffected.** No anchor tamper row is added; §5 records why one
  is impossible, and the six M2 families are untouched.
- **U9/U22 — one field**, in the existing `anchors/<slot>` opaque payload;
  no store-schema change (U9's slot payload is opaque bytes by design).
- **U12/D47 — no format change.** The nonce rides inside the anchor record
  the export already carries; Evidence 5 records the zero marginal
  disclosure, and D47 needs no amendment.
- **R18/R-domain — one copy constraint.** The nonce check must never be
  rendered as part of the *proof*. It is a statement about the sealer's own
  capture process, unwitnessable from a bundle (Residual risk 1), and copy
  that implies otherwise would overclaim. Recorded here for R18's wording
  freeze at M3.
- **Q — the `anchor-` prefix registration** (§5), which A21/Q18 need anyway.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## Residual risks

1. **The check is unwitnessed, and that is permanent.** A bundle cannot
   demonstrate that the sealer performed the comparison. A patched CLI that
   skips it produces a byte-identical bundle. The guarantee is therefore
   about the sealer's own process and has **no evidentiary value to a
   recipient** — which is precisely why it must not appear in verdict copy
   (R18 consequence above). This is the honest form of the register's
   "capture-time property"; it is not a defect to be fixed, because no
   construction that keeps the TSA protocol unchanged can fix it.
2. **The nonce is a permanent 64-bit tag inside every shipped token.** It
   adds no linkability that `serialNumber` + `genTime` do not already
   provide — those are the join keys a TSA's logs are indexed by, and both
   ship regardless — but a bundle recipient who can also read a TSA's logs
   learns the request instant and source of that submission. Recorded, not
   eliminated: the token is what carries it, and the token is the evidence.
3. **A caching proxy in front of a TSA will now surface as a hard capture
   failure** rather than as a silently-accepted stale token. Correct, but it
   is a new way for a seal to abort on a network that previously "worked".
   `--force-degraded` is the escape hatch and the degradation report names
   the endpoint.
4. **8 bytes is a floor-hugging choice.** If a future TSA is found that
   requires or rejects a particular width, the width moves — it is a capture
   parameter, not a wire format, and nothing is frozen by this record. The
   revisit trigger is below.
5. **`anchor-` as A's prefix is being registered by a decision that is not
   the error-code contract's owner.** If Q80 lands a different prefix, this
   code's spelling moves with it; the *distinctness* and *named-owner*
   properties are what D59 actually fixes.

## Discovered-work candidates

- **A46** — the inertness differential test (§7 row 1) and the sign-byte
  golden vector (§7 row 4). Small, but it is the only row that can witness
  the ruling's central claim, and it belongs to no existing Accept list.
- **U46** — the capture record's nonce field, its public-by-construction
  documentation, and the `status` re-check path (§3 item 3).
- **Q80** — register the `anchor-` prefix in
  `docs/testing/error-code-contract.md` §2, whose table omits both A and S
  while the document's header claims to bind them; and record
  `anchor-tsa-nonce-mismatch` as an owner-backed (not row-backed) code so the
  Q7 sweep does not read it as unclaimed.

### Handed off — four facts about the real FreeTSA token that are A8/A9/A-OD8's, not D59's

Evidence 1's capture is the project's first real RFC 3161 token, and parsing
it produced four measured facts outside this record's scope. They are
recorded here because this is where the artifact came from; the owning
decisions are A-OD8 (crate pins) and the A8/A9 implementations. All four are
`openssl asn1parse` offsets into the 4 642-byte response.

1. **The token is signed `ecdsa-with-SHA512`** (offset 4528), over a
   `secp384r1` signer key (offsets 958/967). A8's Do says *"RSA PKCS#1 v1.5
   (SHA-256/384/512) and ECDSA P-384"* and does **not** name the ECDSA hash;
   an implementer pairing P-384 with SHA-384 by the usual curve/hash
   convention would fail against the project's own default TSA on its very
   first real token.
2. **Every certificate link is `sha512WithRSAEncryption`** (offsets 486,
   1566, 2122, 3617) — the P-384 signer cert is issued by an **RSA** CA. A9's
   Do says only *"per-link signature verification (RSA + ECDSA P-384)"*; the
   measured requirement is RSA-SHA512 on the links and ECDSA-SHA512 on the
   token, which are different code paths.
3. **The signing-certificate attribute is ESSCertID *v1***
   (`id-smime-aa-signingCertificate`, offset 4402) — not v2. RFC 2634's v1
   `certHash` is **SHA-1**, by definition and with no algorithm field. A8
   says *"ESSCertID and ESSCertIDv2 both supported"*, so this is in scope,
   but it means **`antseal-core` needs SHA-1 for this one comparison** — a
   new hash in the WASM-safe graph, with a pin, an advisory sweep and a
   `deny.toml` row, that A-OD8's crate list does not currently contain. This
   is the largest of the four and should reach A-OD8 before it picks pins.
4. **Signed attributes present, in order**: `contentType` = id-smime-ct-TSTInfo
   (4344/4357), `signingCertificate` (4402), `messageDigest` (4447) — exactly
   the three A8 requires, plus a signer cert carrying Basic Constraints, SKI,
   AKI, Key Usage, **Extended Key Usage** (1172), CRL Distribution Points and
   Certificate Policies. Two certificates total, so the bundle-side
   `intermediates` array for a FreeTSA anchor holds **one** entry, against
   `MAX_INTERMEDIATE_COUNT = 16`.

The captured request/response pair
(`req.tsq` 69 B, `resp.tsr` 4 642 B, sha256
`0af3b868d6617d79dcd324b5d8821fa6700e4e20e26e7b4dc93e8639fb94f123`) is in
this session's scratchpad at `…/scratchpad/d59-tsa/`. It is exactly the
"recorded real token fixture" A5/A8/A25 need, taken against a **committed
golden-vector digest**, and it will be lost when the scratchpad is cleared —
worth preserving under `testdata/anchors/` if the orchestrator wants it,
which is a `testdata/` write this planning round did not authorise.

## Revisit triggers

- **A25 finds a default or alternate TSA that mishandles an 8-byte nonce**
  (rejects it, silently drops the echo, or requires a different width) —
  the width moves in A10, with the measurement recorded; nothing else in this
  record changes.
- **A TSA is added whose responses are observed without a nonce echo** in
  violation of RFC 3161 §2.4.2 — that endpoint cannot be used for capture at
  all, since §1's `Some` arm requires presence. That is the correct outcome
  and needs no decision, but it should be recorded as a caveat row beside
  Sectigo's spacing and SwissSign's quota.
- **Any proposal to carry a request nonce in a v1.x bundle** — refused by
  Decision 6(b); reopening requires overturning §7.6.1's pattern, not just
  this record.
- **A revocation or long-term-validation feature that needs the original
  request** — the stored nonce is what makes the request reconstructable
  (§3 item 1); this is the one direction in which persistence could become
  load-bearing rather than merely useful.
