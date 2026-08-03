# D57 — Scope of the pinned TSA root store, and the provenance procedure that fills it

- **Status: RESOLVED — include the alternates, but the register's lean is
  confirmed on a reason it never gave, and the "list" is replaced by a
  closure rule: *a root is in the pinned store iff antseal NAMES a TSA
  endpoint — default or documented alternate — whose current production
  chain closes at it, verified by execution.* The decisive argument is not
  rendering: U26 makes a documented alternate configurable, and A20's gate
  is "proceed iff ≥1 TSA token passed full core verification", so a user who
  follows our own docs and configures `zeitstempel.dfn.de` as their TSAs
  with its root unpinned does not get a weaker bundle — they get a
  **pre-payment seal abort**. Documenting an alternate we cannot verify
  ships a trap. Store version 1 is therefore **four roots, 6 429 bytes of
  DER**, enumerated in §5. Two structural findings came out of fetching real
  tokens from all five TSAs, and neither could have been found with a
  hand-made test CA: **(1) two of the five chains (DigiCert, Sectigo)
  terminate at a CROSS-CERTIFICATE, not a self-signed root** — DigiCert
  supplies "DigiCert Trusted Root G4 issued by DigiCert Assured ID Root CA",
  Sectigo supplies "Sectigo Public Time Stamping Root R46 issued by USERTrust
  RSA CA" — so a path builder that consumes the supplied chain to its end
  would terminate at an unpinned anchor and render **the production default
  TSA** as `internally-consistent-only`; **(2) three of the five (FreeTSA,
  DFN, SwissSign) ship their own self-signed root inside the token**, and
  the five tokens arrive in three different certificate orders, so A9 may
  assume neither ordering nor that the last certificate is the anchor. The
  provenance procedure is executable because it was executed: FreeTSA and
  DigiCert are corroborated end-to-end here (Wayback snapshots ten and seven
  years old; Mozilla NSS), and the honest gap — DFN, Sectigo and SwissSign
  each still need one more channel — is stated as A7 work rather than
  papered over. Mandating "must appear in a browser root program" would have
  been unexecutable: **only 2 of the 5 candidates are in Mozilla NSS at
  all**, because timestamping-only roots are not in Mozilla's programme.**
- **Date: 2026-08-02** (M2 planning round; register `TODO.md:569`, "A-OD5")
- **Owning tasks: A6** (store format + injection API), **A7** (root
  collection), **A26** (versioning/update process); binding findings for
  **A8**, **A9**, **A21**, **A24**; new **A43**, **A44**
- **Blocks: A6, A7, A8, A9, A21, A24, A25, A26**

## Context — the register's lean, and what actually decides it

The register entry (`TODO.md:569`) reads "Pinned root-store scope: defaults
only vs + documented alternates (**recommended: include alternates**)".
The lean is confirmed. Its implied reasoning — a root omitted is a token
that cannot verify — is **too strong, and the brief repeats it**: "a pinned
root store … that omits a root makes previously-verifiable bundles render as
`internally-consistent-only` forever".

That is not what the design says. The root store is explicitly *versioned
and updatable* (spec line 109; A26 makes it append-only with a monotonic
version) and is **not part of the frozen v1 wire format**. Adding a root
later is always possible, and the format-stability guarantee (spec line 123)
binds *formats*, not the trust store. So an omitted root is not permanent:
the damage is scoped to bundles produced during the gap and to holders of
binaries built before the fix — real, bounded, repairable.

The argument that actually decides it is on the *sealing* side, not the
verifying side, and neither the register nor the brief makes it:

> `tasks/U.md` U26 activates a config slot where "a user-supplied TSA URL
> list **overrides** the built-in defaults", and "the ≥1-TSA-or-abort gate
> applies to the effective list"; `tasks/A.md` A20's gate is "proceed iff
> ≥1 TSA token passed **full core verification**; otherwise abort — before
> any payment", and `TODO.md`'s A10 line spells out what that means:
> "**only verifying tokens count toward the gate**". A token whose chain
> closes only outside the pinned store is not a verifying token — spec
> line 109 makes it `internally-consistent-only`, explicitly "never
> `proven`". Therefore a user who configures two documented alternates
> whose roots we did not pin gets **zero verified tokens and a hard
> pre-payment abort of every seal**.

Documenting `zeitstempel.dfn.de`, Sectigo and SwissSign as alternates (spec
line 108) while withholding their roots does not degrade those users'
evidence. It makes the documented configuration unusable. That is the
consequence in the "omit" direction, and it is worse than the register's.

The consequence in the "include" direction is real and should be stated
without softening: **each root is an organisation that can sign a false,
earlier time.** Five roots is five such organisations (§5). Since antseal's
whole claim is priority — "existed no later than T" — an earlier-signing
capability is precisely the capability that matters. The closure rule is
what keeps that set from growing by drift: a root enters only with a named
antseal-side consumer, so the store can never become "a copy of a browser
trust store", which at 177 roots (measured, §4) would be a 35× larger
attack surface for no capability.

## 1. Method — five real tokens, one probe digest

Every claim below rests on a live RFC 3161 exchange run for this decision.
One DER `TimeStampReq`, `certReq = 1`, nonce `0xF0F14E09C9F30B67`,
messageImprint = SHA-256 digest
`c76db11e7d95fb40c1ecfe98b74e4a3a59907d1f8da6a2ef10d399f5013b6999`, derived
from the documented fixed test seed per `testdata/README.md`
(`SHA-256("antseal/D57 roots-probe digest" ‖ W)`, `W = 00 01 … 1f`; the
`alternate_test_secret` formula at
`crates/antseal-core/src/test_util/mod.rs:261`). Sectigo's ~15 s spacing was
respected; one request per TSA, so SwissSign's ~10/day budget is untouched.

| TSA | URL | UTC | HTTP | bytes | status | genTime | nonce echoed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FreeTSA | `https://freetsa.org/tsr` | 19:25:47Z | 200 | 4 644 | Granted | `Aug 2 19:27:56 2026 GMT` | yes |
| DigiCert | `http://timestamp.digicert.com` | 19:25:48Z | 200 | 6 008 | Granted | `Aug 2 19:27:57 2026 GMT` | yes |
| DFN | `https://zeitstempel.dfn.de` | 19:31:00Z | 200 | 6 670 | Granted ("Operation Okay") | — | — |
| Sectigo | `http://timestamp.sectigo.com` | 19:31:17Z | 200 | 6 637 | Granted | — | — |
| SwissSign | `http://tsa.swisssign.net` | 19:31:33Z | 200 | 6 859 | Granted ("Operation Okay") | — | — |

All five URLs in spec line 108 are live and correct as written. Token sizes
4 644 – 6 859 B, comfortably inside `MAX_TSA_TOKEN_BYTES = 1 048 576`
(margin 153×).

## 2. Finding 1 — two of five chains end at a cross-certificate

The certificates supplied inside each token's CMS `SignedData`:

**DigiCert** (`http://timestamp.digicert.com`):

| # | subject | issuer | key | notAfter |
| --- | --- | --- | --- | --- |
| 0 | `DigiCert SHA256 RSA4096 Timestamp Responder 2025 1` | `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1` | RSA 4096 | 2036-09-03 |
| 1 | `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1` | **`DigiCert Trusted Root G4`** | RSA 4096 | 2038-01-14 |
| 2 | `DigiCert Trusted Root G4` | **`DigiCert Assured ID Root CA`** ← *not self-signed* | RSA 4096 | **2031-11-09** |

**Sectigo** (`http://timestamp.sectigo.com`):

| # | subject | issuer | key | notAfter |
| --- | --- | --- | --- | --- |
| 0 | `Sectigo Public Time Stamping Signer R37` | `Sectigo Public Time Stamping CA R41` | RSA 4096 | 2037-06-24 |
| 1 | `Sectigo Public Time Stamping CA R41` | **`Sectigo Public Time Stamping Root R46`** | RSA 4096 | 2041-03-24 |
| 2 | `Sectigo Public Time Stamping Root R46` | **`USERTrust RSA Certification Authority`** ← *not self-signed* | RSA 4096 | **2038-01-18** |

In both cases certificate 2 is a **cross-certificate**: same subject DN and
same public key as the self-signed root, different issuer and signature.
Verified by construction, not assumed:

```
Sectigo R46 self-signed  spki=a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795 der=1406 B
Sectigo R46 cross-signed spki=a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795 der=1670 B
SPKI EQUAL: True
```

and for DigiCert, self-signed G4 and the token's cross-signed G4 both carry
SPKI SHA-256 `59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c`.

Closure was then verified three ways with the real DigiCert token
(`openssl verify -purpose any`, `2026-08-02T19:27Z`):

| trust anchor | untrusted set | result |
| --- | --- | --- |
| self-signed `DigiCert Trusted Root G4` only | intermediate **only**, cross-cert withheld | `OK` |
| self-signed `DigiCert Trusted Root G4` only | intermediate **+ redundant cross-cert** | `OK` |
| `DigiCert Assured ID Root CA` only | intermediate + cross-cert | `OK` |
| — | `openssl ts -verify -CAfile DigiCertTrustedRootG4.pem` | `Verification: OK` |

**Ruling P1 (path termination) — normative for A9.** Path building stops at
the **first** certificate whose issuer DN matches a pinned root's subject DN
*and* whose signature verifies under that root's SPKI. Certificates supplied
beyond that point are ignored: never a trust anchor, never required to be
consumed, and their presence is not an error.

Without P1, the natural implementation — walk the supplied chain to its end,
then check whether the terminal certificate is pinned — terminates at
certificate 2, whose issuer is unpinned, and renders **the production
DigiCert default** and **the Sectigo alternate** as
`internally-consistent-only`. It is worth being explicit about why this
would have survived testing: A24's test CA issues a clean self-signed root
and no cross-certificate, so every fixture built from it would pass. This
class of defect is only reachable through a real token, which is why §7 adds
`A43`.

**Consequence for which certificate is pinned.** Pin the **self-signed**
root in both cases, never the cross-certificate:

- self-signed `DigiCert Trusted Root G4` expires **2038-01-15**; the
  cross-signed one, and `DigiCert Assured ID Root CA` behind it, expire
  **2031-11-09/10** — six years earlier.
- self-signed `Sectigo Public Time Stamping Root R46` expires
  **2046-03-21**; the cross-signed one, and `USERTrust RSA CA` behind it,
  expire **2038-01-18** — eight years earlier.

Since A9 evaluates chain validity **at the token's genTime**, pinning the
longer-lived self-signed root is not merely tidier: it is the only choice
that lets tokens issued after 2031 (DigiCert) and after 2038 (Sectigo) reach
`proven` at all.

## 3. Finding 2 — three of five tokens carry their own root, in three different orders

| TSA | certificate order inside the CMS `certificates` SET |
| --- | --- |
| FreeTSA | `[leaf, ROOT(self-signed)]` |
| DigiCert | `[leaf, CA, CA]` |
| DFN | `[ROOT(self-signed), leaf, CA]` |
| Sectigo | `[leaf, CA, CA]` |
| SwissSign | `[ROOT(self-signed), CA, leaf]` |

Two normative consequences:

**Ruling P2 (self-anchor rejection).** A bundle- or token-supplied
self-signed certificate is never a trust anchor, even when its bytes equal a
pinned root's. The store is consulted by its own pinned bytes; supplied
certificates are consumed *only* as intermediates. Spec line 109 and A6's
Accept already say this; the finding is that **three of the five real
production TSAs exercise it on every single token**, so the negative test
("a chain closing only against a bundle-supplied root can never reach
`proven`") now has a positive twin that must also pass: the FreeTSA, DFN and
SwissSign tokens must reach `proven` *while carrying a self-signed root*,
because their real chains do.

**Ruling P3 (no ordering assumption).** `certificates` is an ASN.1 `SET`;
three distinct orders appear across five real tokens. A9 builds paths by
subject/issuer matching over an unordered pool, never by position, and in
particular must not treat element 0 as the leaf (DFN and SwissSign put a CA
there) nor the last element as the anchor (§2).

## 4. Signature algorithms the real tokens actually use

Measured from the five `TimeStampToken`s (`openssl asn1parse`):

| TSA | SignerInfo signature | signer key | chain-link signature |
| --- | --- | --- | --- |
| FreeTSA | **`ecdsa-with-SHA512`** | **EC P-384** | `sha512WithRSAEncryption` (RSA-4096 root over the leaf) |
| DigiCert | `sha384WithRSAEncryption` | RSA 4096 | `sha384WithRSAEncryption` |
| DFN | `sha256WithRSAEncryption` | RSA 4096 | `sha256WithRSAEncryption` |
| Sectigo | `sha384WithRSAEncryption` | RSA 4096 | `sha384WithRSAEncryption` |
| SwissSign | `sha256WithRSAEncryption` | **RSA 3072** | `sha256WithRSAEncryption` |

Three findings for A8/A9 and D60:

1. **FreeTSA's P-384 signature uses SHA-512, not SHA-384.** A8's Accept says
   "ECDSA P-384" without naming a digest; an implementation wiring only
   P-384-with-SHA-384 fails the *default* TSA on its very first real token.
   The required set is ECDSA P-384 with SHA-512 (mandatory today) and
   SHA-384/SHA-256 (forward compatibility).
2. **FreeTSA's leaf is EC while its root is RSA-4096.** The token signature
   is ECDSA; the chain-link signature is RSA-PKCS#1-v1.5 with SHA-512. Both
   are required to verify one FreeTSA token, so "supports ECDSA P-384" is
   not sufficient on its own.
3. **SwissSign's leaf is RSA-3072.** The RSA verifier must accept arbitrary
   modulus sizes, not a `{2048, 4096}` allow-list.

FreeTSA's leaf `notBefore = Feb 15 19:44:22 2026 GMT` — this is the "2026
cert" spec line 109 names, and it is confirmed EC P-384, which is why P-384
support is normative.

## 5. Store version 1 — the roots admitted by the closure rule

> **Corrected 2026-08-03 at A7.** This section says *five roots, 7 937 bytes*; the
> gate in §6 admits **four, 6 429 bytes**. **SwissSign is QUARANTINED**: its C3
> now exists and C4 holds, but `www.swisssign.com` returns **403 to this host for
> every request** — both schemes, with and without a browser UA, and *including a
> deliberately nonexistent path under the same prefix*, so the block is on the
> client rather than the resource. Promoting C3 to stand in for a blocked C1
> substitutes one channel *class* for another, and the gated task would be
> rewriting its own admission rule to admit the root it was evaluating. Left to
> **A56**. Sectigo, by contrast, **completed**: CCADB's Microsoft feed now
> answers 200 / 220 193 B / 550 rows where this document measured a 404, which
> is exactly the revisit this document's own trigger pre-authorised.

| # | label | subject CN | serial | SHA-256 fingerprint | key | validity | DER |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `freetsa-root-ca` | `www.freetsa.org` (O=Free TSA, OU=Root CA) | `C1E986160DA8E980` | `A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC` | RSA 4096 | 2016-03-13 → **2041-03-07** | 2 051 B |
| 2 | `digicert-trusted-root-g4` | `DigiCert Trusted Root G4` | `059B1B579E8E2132E23907BDA777755C` | `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88` | RSA 4096 | 2013-08-01 → **2038-01-15** | 1 428 B |
| 3 | `dfn-verein-community-root-ca-2022` | `DFN-Verein Community Root CA 2022` | `01` | `3C:DC:2C:9E:9E:5A:36:CB:58:88:FD:17:96:CB:91:2F:84:62:53:B6:82:C1:B3:20:57:53:20:33:51:0C:7B:B6` | RSA 4096 | 2022-01-26 → **2042-01-21** | 1 544 B |
| 4 | `sectigo-public-time-stamping-root-r46` | `Sectigo Public Time Stamping Root R46` | `783D056CFA832E7E69F85622769F02B9` | `49:41:B0:01:B8:A9:7E:96:1B:78:17:C9:D9:E9:60:EC:4B:05:6B:FC:91:5A:8C:1A:AB:F6:EF:6B:3A:C0:46:A5` | RSA 4096 | 2021-03-22 → **2046-03-21** | 1 406 B |
| 5 | `swisssign-signature-services-root-2020-2` | `SwissSign Signature Services Root 2020 - 2` | `2FDBA9B88D001EBCE7B99C2D23EF4A` | `B8:7F:29:2A:4D:9F:EA:CE:2D:66:91:59:EB:26:F5:6D:85:EC:77:C1:9E:01:09:8C:D7:54:E8:AB:B3:10:CD:E5` | RSA 4096 | 2020-10-07 → **2050-09-30** | 1 508 B |

Every field above is read from the committed DER, not transcribed from a
vendor page. The `spki_sha256` values — which are what ruling P1 matches on
— are in `testdata/anchors/A25-bootstrap/roots-PROVENANCE.md` alongside
each root, and differ from the certificate fingerprints in this column.

**This table is the target set, and A7 is its gate, not a formality.** A6
builds the store with generated test roots; a real root enters only once
its §6 channels are complete. Three of these five are not yet complete
(§6), and `swisssign-signature-services-root-2020-2` currently rests on C4
alone, which is same-operator corroboration and never sufficient. No root
may be compiled in ahead of its provenance.

**Total **6 429 B** *(four roots — see §5's correction)*.** For scale, D87 measured `include_bytes!` carriage of the
v1 golden vectors at 28.15 % of a 2 MiB per-version budget; the whole root
store is ****0.31 %**** of that same budget. Store size is not a constraint on
this decision and no cost argument should be built on it.

Roots deliberately **not** pinned, with reasons:

- `DigiCert Assured ID Root CA` — the cross-certificate's issuer. Pinning it
  would add a second, older (2031) anchor for the same chain and a second
  organisation-scale trust anchor, for zero additional capability once P1
  holds.
- `USERTrust RSA Certification Authority` — same argument for Sectigo, and
  strictly worse: USERTrust anchors a very large general-purpose PKI.
- The `T-TeleSec GlobalRoot Class 2` / `DFN-Verein Certification Authority 2`
  hierarchy — this is DFN's *Global* PKI, a different hierarchy from the
  *Community* one `zeitstempel.dfn.de` actually uses. `tasks/A.md` A7 names
  "DFN-PKI/T-TeleSec for zeitstempel.dfn.de", which is **wrong**: the live
  token chains to `DFN-Verein Community Root CA 2022`, self-signed, no
  T-Systems involvement (§8).

**Who can sign an earlier time under this store**, stated plainly because
including a root is the whole cost: Free TSA (one operator in Würzburg, DE —
a self-signed root with a personal email address in its subject, no audit,
no root-programme membership), DigiCert Inc, DFN-Verein / DFN-CERT Services
GmbH (DE academic), Sectigo Limited (GB), SwissSign AG (CH).

## 6. Provenance procedure for A7 — the executable version, executed

"Fingerprint cross-checked over a second channel" is unimplementable as
prose because **the obvious second channel does not exist for most of these
roots.** Mozilla NSS `certdata.txt` (fetched `2026-08-02T19:27:07Z`,
1 403 601 B, **177 roots**) contains:

| candidate | in NSS? |
| --- | --- |
| `DigiCert Trusted Root G4` | **yes** — fingerprint `55:2F:…:99:88`, byte-identical to the vendor fetch |
| `USERTrust RSA Certification Authority` | yes (not pinned) |
| `DigiCert Assured ID Root CA` | yes (not pinned) |
| `Sectigo Public Time Stamping Root R46` | **no** (NSS carries Sectigo's *email* and *server-auth* R46 roots only) |
| `SwissSign Signature Services Root 2020 - 2` | **no** (NSS carries `SwissSign Gold CA - G2` only) |
| `DFN-Verein Community Root CA 2022` | **no** |
| Free TSA Root CA | **no** |

This is structural, not incidental: Mozilla's programme covers TLS and
S/MIME, so a timestamping-only root will never be in it. Any procedure
mandating root-programme membership would be unexecutable for 3 of 5 roots.

### The rule

Per root, obtain **channel C1, plus at least one of C2/C3, plus C4 always**:

- **C1 — vendor repository.** The CA's own published root, over HTTPS where
  the CA offers it.
- **C2 — public root-programme data.** Mozilla NSS `certdata.txt`. Available
  only for multipurpose commercial roots.
- **C3 — historical archive.** *(Corrected 2026-08-03 at A7: as written this
  channel is **unexecutable for two of the five roots**, because it required the
  snapshot to be **of the C1 URL** and no capture of those URLs exists at any
  date — for Sectigo, 624 archived `crt.sectigo.com` URLs contain no capture of
  this root, the two near-misses being cross-certificates under 12 months old.
  It must read: a snapshot that yields the candidate root's exact DER — from the
  C1 URL where one is archived, **otherwise from any other URL**. DFN was
  admitted on that reading, via two independent snapshots ≥12 months old, one of
  them under an operator independent of the vendor, which is stronger than the
  letter of the original rule.)* An Internet Archive Wayback `…id_/` raw
  snapshot of the C1 URL, **at least 12 months old**. Independent operator
  *and* independent in time: it defeats a present-day compromise of the
  vendor's web server, which is the threat C1 alone cannot address.
- **C4 — operational binding.** The live production TSA token: either the
  candidate root appears verbatim inside it, or the token's intermediate's
  signature verifies under the candidate root's SPKI. Independent *service*
  from the same operator — **never sufficient alone**, always required.

Record per root: subject DN, issuer DN, serial (hex), SHA-256 of the DER
certificate, SHA-256 of the SubjectPublicKeyInfo DER, notBefore, notAfter,
key algorithm and size, and for **every** channel used its URL, its retrieval
UTC and the fingerprint it yielded. A root enters the store only when every
recorded fingerprint is identical.

### Executed here

| root | C1 | C2 | C3 | C4 |
| --- | --- | --- | --- | --- |
| Free TSA | ✅ `https://freetsa.org/files/cacert.pem`, 19:24:16Z | ✖ not in NSS | ✅ **two** Wayback snapshots, `20160829015301` and `20190723200626` (fetched 19:25:31Z) — **both `A6:37:9E:…:AA:BC`, identical to C1** | ✅ root embedded in the live token, 19:25:48Z, identical; `openssl ts -verify -CAfile` → `Verification: OK` |
| DigiCert Trusted Root G4 | ✅ `https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem`, 19:26:40Z | ✅ NSS, identical fingerprint | not needed | ✅ intermediate verifies under it with the cross-cert withheld; `openssl ts -verify -CAfile DigiCertTrustedRootG4.pem` → `Verification: OK` |
| DFN Community Root CA 2022 | ✅ `https://pki.pca.dfn.de/dfn-verein-community-root-ca/pub/cacert/cacert.pem`, 19:35:11Z, and a second vendor path (`…/dfn-verein-community-ca/pub/cacert/chain.txt`) — **DER byte-identical to the token-embedded copy** | ✖ not in NSS | **⚠ NOT EXECUTED** | ✅ root embedded in the live token, 19:31:00Z, identical fingerprint |
| Sectigo Public Time Stamping Root R46 | ✅ `http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt`, 19:34:49Z | ✖ not in NSS | **⚠ NOT EXECUTED** | ✅ SPKI equality with the token's cross-certificate (`a4db8668…4795`) |
| SwissSign Signature Services Root 2020 - 2 | **⛔ ATTEMPTED AND BLOCKED (HTTP 403 to this host, incl. a nonexistent path under the same prefix — the block is on the client, not the resource; A56)** | ✖ not in NSS | **⚠ NOT EXECUTED** | ✅ root embedded in the live token, 19:31:33Z |

Two roots are complete; three carry a named gap. **That is A7's remaining
work, not a defect in the procedure** — and stating it beats the failure
mode this project keeps finding, where a procedure is specified and never
run. The procedure is proven executable by the two completed rows.

**A transport finding that changes Sectigo's requirements.** `crt.sectigo.com`
**fails TLS from this host** — `curl: (35) OpenSSL/3.0.20: error:0A000410:
SSL routines::sslv3 alert handshake failure`, on all three of `.crt`,
`.p7c` and the `crt.usertrust.com` mirror — and serves the root only over
**plain HTTP**. Sectigo's C1 channel is therefore *unauthenticated
transport*. For that root, a second non-C4 channel is **mandatory, not
elective**; C4's SPKI equality is what carries it today, and A7 must add C3.

## 7. Store format, layout and the injection API (A6)

### Files

```
crates/antseal-core/src/anchor/roots/
    mod.rs
    PROVENANCE.md                               # the A7 record, §6's table shape
    freetsa-root-ca.der
    digicert-trusted-root-g4.der
    dfn-verein-community-root-ca-2022.der
    sectigo-public-time-stamping-root-r46.der
    swisssign-signature-services-root-2020-2.der
```

**In the crate, not `testdata/`.** `testdata/` is the fixture tree
(`testdata/README.md`: "Fixture tree for antseal"); these are *production*
bytes compiled into a shipped library. **DER, not PEM**: `include_bytes!` of
DER is byte-exact and needs no base64 decoder in a crate that must stay
WASM-safe and dependency-minimal.

**`.gitattributes` must gain a rule.** The existing guard is `testdata/** -text`
and covers nothing outside it. Binary DER under `crates/` would be
CRLF-mangled on the `windows-latest` runner (which sets
`core.autocrlf=true` machine-wide — the exact hazard the existing rule
documents). Add:

```gitattributes
# Production trust anchors compiled into antseal-core (D57/A6). Same
# byte-exactness hazard as testdata/: the Windows CI image sets
# core.autocrlf=true, and a CRLF-mangled DER is an unparseable root.
crates/antseal-core/src/anchor/roots/*.der -text
```

### Types

```rust
/// One pinned trust anchor. Carries BYTES plus the two fingerprints R
/// displays — and nothing else. Subject, validity window and key
/// algorithm are PARSED from `der` on demand rather than duplicated
/// here: a duplicated field is a field that can drift from the bytes it
/// describes, and every one of them is derivable.
pub struct PinnedRoot {
    /// The self-signed root certificate, DER.
    pub der: &'static [u8],
    /// SHA-256 over `der`.
    pub cert_sha256: [u8; 32],
    /// SHA-256 over the DER SubjectPublicKeyInfo. This is the value P1
    /// matches on, and it is stable across a cross-certificate of the
    /// same root (D57 §2).
    pub spki_sha256: [u8; 32],
    /// Stable machine label for verdict data and PROVENANCE.md. Never
    /// parsed, never user-facing prose.
    pub label: &'static str,
}

pub struct TsaRootStore { /* private */ }

/// Monotonic; bumped on ANY change to the root set (A26).
pub const TSA_ROOT_STORE_VERSION: u32 = 1;
/// ISO-8601 date the store contents were last changed.
pub const TSA_ROOT_STORE_BUILD_DATE: &str = "2026-08-02";

impl TsaRootStore {
    /// The compiled-in production store. The ONLY constructor available
    /// in a default build.
    #[must_use] pub const fn pinned() -> &'static Self;
    #[must_use] pub const fn version(&self) -> u32;
    #[must_use] pub const fn build_date(&self) -> &'static str;
    #[must_use] pub fn roots(&self) -> &'static [PinnedRoot];

    /// Test-only injection (A6 Accept; A24's mock-CA suites).
    #[cfg(any(test, feature = "test-util"))]
    #[must_use] pub const fn from_static(roots: &'static [PinnedRoot]) -> Self;
}
```

`from_static` behind `#[cfg(any(test, feature = "test-util"))]` — the
crate's existing test-only convention (`crates/antseal-core/src/test_util/`)
— makes A6's "page/CLI production paths provably use `pinned()` only" a
**compile-time fact rather than a review checklist item**: in a default
build the symbol does not exist. `scripts/gate-features.sh` already builds
the default feature set and is the lane that witnesses it.

All verification entry points take `&TsaRootStore`; none reaches for
`pinned()` internally, so a caller cannot accidentally bypass an injected
store.

### Dependency impact: none

`include_bytes!` is a macro over bytes. **No new crate enters
`antseal-core`'s graph**, default or heavy, so the common brief's
package-count measurement has nothing to measure and `scripts/ci-lanes.sh
lane_dep_graph` needs no new rule — it asserts the *absence of specific
names* (D89), and this decision introduces no name.

## 8. Findings handed to other tasks

1. **`tasks/A.md` A7 `Do` is factually wrong about DFN.** It says "roots for
   the documented alternates (**DFN-PKI/T-TeleSec** for zeitstempel.dfn.de,
   Sectigo/USERTrust, SwissSign)". The live `zeitstempel.dfn.de` token chains
   to a **self-signed `DFN-Verein Community Root CA 2022`** with no
   T-Systems involvement; `T-TeleSec GlobalRoot Class 2` anchors DFN's
   *Global* hierarchy, a different PKI. Correct to "DFN-Verein Community
   Root CA 2022". Likewise "Sectigo/**USERTrust**" should read "Sectigo
   Public Time Stamping Root R46 (self-signed; the token supplies a
   USERTrust-issued cross-certificate of it, which is not what we pin)".
2. **`tasks/A.md` A8 Accept** — "Signature algorithms: RSA PKCS#1 v1.5
   (SHA-256/384/512) and ECDSA P-384" must name the ECDSA digest:
   FreeTSA signs with **`ecdsa-with-SHA512`** (§4). And the RSA verifier
   must accept **RSA-3072** (SwissSign), so no `{2048,4096}` allow-list.
3. **`tasks/A.md` A9 `Do`** — "single-path chain building from the signer
   cert through bundle-supplied intermediates to a pinned root" must carry
   rulings **P1** (stop at the first pinned match; ignore trailing
   certificates), **P2** (never anchor on a supplied self-signed cert) and
   **P3** (no ordering assumption). Without P1 the production DigiCert
   default fails.
4. **`tasks/A.md` A21** — the tamper matrix's row 3 ("well-formed token
   chaining to an untrusted root → `internally-consistent-only`") needs its
   **positive twin**: FreeTSA/DFN/SwissSign tokens reach `proven` *while
   carrying a self-signed root in the token*. A matrix with only the negative
   would pass an implementation that rejects all three real defaults.
5. **`tasks/A.md` A24** — the test CA must be extended to emit a
   cross-certificate, or A43's real-token fixtures must stand in; a
   single-hierarchy test CA cannot reach §2's defect class.
6. **`tasks/A.md` A26** — add "no pinned root may be within 365 days of
   `notAfter` at release time" as a mechanical check (A44). Earliest expiry
   in store v1 is `DigiCert Trusted Root G4`, **2038-01-15**.
7. **`MVP-SPEC.md` line 108** — the default pair is one audited commercial
   CA and one individual's unaudited self-signed root, and A20's gate
   requires only ≥1 verified token, so **a normal seal's offline headline can
   rest on FreeTSA alone** whenever DigiCert fails. This is a live product
   property, not a defect, but the A20 degradation report must name *which*
   TSA carried the gate so it is never invisible. Recorded here rather than
   ruled: line 108 is frozen scope and adding a third default would be a
   spec change.

## 9. Tests that must exist, and what makes each fail

| test | lives in | fails when |
| --- | --- | --- |
| `pinned_store_fingerprints_match_the_embedded_bytes` | `antseal-core` unit | any `cert_sha256`/`spki_sha256` literal drifts from `sha256(der)` — the one drift class the format permits, closed mechanically. |
| `pinned_store_is_exactly_four_roots_at_version_1` | `antseal-core` unit | a root is added or removed without bumping `TSA_ROOT_STORE_VERSION` and updating this record. Asserts the version, the count, and every `label`. |
| `real_digicert_token_reaches_proven_with_the_cross_cert_present` | `antseal-core` + `testdata/anchors/` | **P1 is not implemented.** Uses the committed real token, whose chain terminates at a cross-certificate. An implementation that walks to the end of the supplied chain returns `internally-consistent-only` and fails here. |
| `real_digicert_token_reaches_proven_with_the_cross_cert_REMOVED` | same | P1's other side: a two-certificate chain that closes directly on the pinned root must also pass, so the fixture proves the cross-cert is optional rather than load-bearing. |
| `real_sectigo_token_reaches_proven_with_the_cross_cert_present` | same | as above, second hierarchy — one TSA passing could be luck. |
| `token_carrying_its_own_self_signed_root_still_reaches_proven` | same | **P2's positive twin.** Real FreeTSA, DFN and SwissSign tokens, each shipping its own root. Fails if the implementation rejects a supplied self-signed certificate rather than ignoring it as a trust anchor. |
| `self_signed_root_in_the_token_is_not_a_trust_anchor` | `antseal-core` + A24 | **P2's negative.** A24 test-CA token whose root is *withheld from the injected store* but *present in the token* must render `internally-consistent-only`. Fails if the verifier anchors on supplied bytes. Cannot pass vacuously: the same fixture reaches `proven` when its root is injected. |
| `certificate_order_in_the_set_does_not_affect_the_verdict` | `antseal-core` | **P3.** Each real token's certificate SET is re-encoded in every permutation and every permutation must yield the identical verdict. Fails on any positional assumption. |
| `freetsa_p384_token_verifies_with_sha512` | `antseal-core` | the ECDSA digest is hardwired to SHA-384 — §4's finding, caught on the real default token. |
| `swisssign_rsa3072_token_verifies` | `antseal-core` | an RSA modulus-size allow-list. |
| `chain_valid_at_gentime_but_expired_now_is_headline_eligible` | `antseal-core` | A9's LTV rule regresses; driven by two `verify_at` values over one real token. |
| `root_expiry_horizon_flags_a_root_inside_the_window` | `antseal-core` unit | the horizon function is wrong: driven with synthetic `now` values either side of each pinned root's `notAfter − 365 d`, it must flag and not flag respectively. **It takes `now` as a parameter** (WASM determinism, A9's rule) and therefore proves the *function*, not the calendar. Stated explicitly because a unit test with a frozen clock cannot detect a real approaching expiry and must not be credited with doing so — that half is A44's, driven with the real clock from the scheduled lane. |
| `default_build_cannot_construct_a_non_pinned_store` | `scripts/gate-features.sh` | `from_static` escapes the `test-util` gate. |
| `store_version_appears_in_verdict_data` | `antseal-core` | A6/A26's Accept regresses and R loses the store version. |
| `appending_a_root_leaves_every_existing_anchor_vector_unchanged` | `antseal-core` + golden vectors | A26's append-only property: build a store with a sixth (test-CA) root and require every committed anchor vector's report bytes to be **byte-identical**. Fails if root-set membership leaks into a verdict beyond the version field. |

## 10. Evidence artefacts committed

Under `testdata/anchors/A25-bootstrap/` (`roots-` prefixed, so as not to
collide with the concurrent token capture):

```
roots-PROVENANCE.md          # §6's table, per root, per channel, with UTCs
roots-freetsa-root-ca.der
roots-digicert-trusted-root-g4.der
roots-dfn-verein-community-root-ca-2022.der
roots-sectigo-public-time-stamping-root-r46.der
roots-swisssign-signature-services-root-2020-2.der
roots-<tsa>-token.tsr        # the five raw TimeStampResp bodies of §1
roots-probe.tsq              # the TimeStampReq, so §1 is reproducible
```

No secret material: the probe digest derives from the documented fixed test
seed and the certificates are public trust anchors. A7 promotes the **four**
`.der` files into `crates/antseal-core/src/anchor/roots/` once its remaining
C1/C3 channels (§6) are executed.

## Revisit triggers

- Any pinned root within 365 days of `notAfter` (A44) → a reviewed append of
  its successor, never a silent swap.
- FreeTSA rotating its leaf again (its 2026 leaf arrived 2026-02-15) → the
  *root* is unaffected to 2041, but A25 must re-capture and §4's algorithm
  table must be re-measured.
- A default or documented-alternate TSA changing hierarchy → the closure
  rule fires: the new root enters via A7, the old one **stays** (append-only,
  A26), and the compatibility note names both.
- A proposal to drop the alternates → §"Context"'s A20-abort argument must be
  defeated first, and U26 plus spec line 108 would have to change together.
- CCADB publishing a machine-readable feed covering Microsoft's programme
  (its `AllCertificateRecordsCSVFormatv2` URL 404'd at
  `2026-08-02T19:34:22Z`) → that would give C2 coverage for Sectigo and
  SwissSign and should be added to the C2 menu.

## Index row (orchestrator applies at merge)

| [D57](D57-tsa-root-store-scope.md) | Pinned TSA root-store scope — **include the alternates, lean confirmed on a reason the register never gave, and the list replaced by a closure rule** (*a root is pinned iff antseal NAMES a TSA whose live chain closes at it*). The decider is the sealing side, not rendering: U26 makes alternates configurable and A20 aborts a seal on zero fully-verified tokens, so documenting an alternate whose root we withhold ships a **pre-payment abort**, not a weaker bundle. Store v1 = ****4 roots / 6 429 B**** (**0.31 %** of D87's per-version budget). Two findings from live tokens at all five TSAs, neither reachable with A24's test CA: **2 of 5 chains terminate at a CROSS-CERTIFICATE** (DigiCert→Assured ID, Sectigo→USERTrust; SPKI equality proven), so A9 must **stop at the first pinned match** or the production DigiCert default renders `internally-consistent-only`; and **3 of 5 tokens ship their own self-signed root**, in **3 different certificate orders**, so P2 needs a positive twin and P3 forbids any positional assumption. Also measured: FreeTSA signs **`ecdsa-with-SHA512`** (A8 names no digest) and SwissSign's leaf is **RSA-3072** (no size allow-list). The provenance procedure names four channel classes and was **executed** — Wayback snapshots from 2016 and 2019 corroborate FreeTSA, NSS corroborates DigiCert — with the three unfinished rows stated as A7 work; mandating root-programme membership would have been unexecutable, since **only 2 of 5 candidates are in Mozilla NSS**. Corrects A7's "DFN-PKI/T-TeleSec" (the live chain is a self-signed DFN Community Root 2022) and finds `crt.sectigo.com` serves its root over **plain HTTP only** (TLS handshake failure) | RESOLVED (A6/A7/A26 + new A43/A44 implement) | 2026-08-02 |
