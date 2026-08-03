# Pinned TSA root store — provenance record (task **A7**, procedure **D57 §6**)

**NON-SECRET.** Every artefact named here is a public trust anchor or a public
RFC 3161 response. No vault, wallet, or key material appears in this directory
or in anything it references.

This file is **normative for the store's contents**. `mod.rs`'s
`the_store_matches_the_provenance_record` test reads it: every root compiled
into `ROOTS_V1` must have a `### <label>` section here, and every root listed
under `- QUARANTINED: <label>` must be **absent** from the store. That is D57
§6's rule — *no root may be compiled in ahead of its provenance* — enforced by
a test rather than by review.

## The channel rule (D57 §6, unchanged)

Per root, obtain **C1, plus at least one of C2/C3, plus C4 always**:

- **C1 — vendor repository.** The CA's own published root, over HTTPS where
  the CA offers it.
- **C2 — public root-programme data.** A root programme's own machine-readable
  feed. Menu: Mozilla NSS `certdata.txt`; **CCADB's Microsoft feed**, added
  2026-08-03 under D57's own revisit trigger (see §"Procedure change" below).
- **C3 — historical archive.** An Internet Archive Wayback `…id_/` raw
  snapshot of the C1 URL, **at least 12 months old**. Independent operator
  *and* independent in time: it defeats a present-day compromise of the
  vendor's web server, which is the threat C1 alone cannot address.
- **C4 — operational binding.** The live production TSA token: either the
  candidate root appears verbatim inside it, or the token's intermediate's
  signature verifies under the candidate root's SPKI. Independent *service*
  from the same operator — **never sufficient alone**, always required.

Recorded per root: subject DN, issuer DN, serial, SHA-256 of the DER
certificate, SHA-256 of the DER `SubjectPublicKeyInfo`, notBefore, notAfter,
key algorithm and size, and for **every** channel its URL, its retrieval UTC,
and the fingerprint it yielded. A root enters the store only when every
recorded fingerprint is identical.

## Procedure change made here, and why it is not a loosening

D57 §"Revisit triggers" pre-authorises exactly one extension:

> CCADB publishing a machine-readable feed covering Microsoft's programme (its
> `AllCertificateRecordsCSVFormatv2` URL 404'd at `2026-08-02T19:34:22Z`) →
> that would give C2 coverage for Sectigo and SwissSign and should be added to
> the C2 menu.

Re-probed **2026-08-03T07:19:50Z**. `AllCertificateRecordsCSVFormatv2` still
404s and `…v3` now returns **401** (authenticated), but

```
https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV
```

returns **HTTP 200, 220 193 B, 550 rows**, over HTTPS, operated by CCADB — an
operator independent of every CA in this store. Microsoft's programme, unlike
Mozilla's, includes a `Time Stamping` EKU class, which is precisely why it
covers roots Mozilla structurally never will. The trigger's condition is met,
so the feed is added to the C2 menu. Retrieved copy:
`sha256(ccadb-msft.csv) = 3ec620f746c429b49019047018972cc06e6ad6f56c86d3481d994749ef2d706f`.

This changes **which sources count as C2**, not the rule "C1 + one of C2/C3 +
C4". No root below is admitted on fewer channels than D57 requires.

---

## The four admitted roots

### freetsa-root-ca

| field | value |
| --- | --- |
| subject | `O=Free TSA, OU=Root CA, CN=www.freetsa.org, emailAddress=busilezas@gmail.com, L=Wuerzburg, ST=Bayern, C=DE` |
| issuer | *(self-signed — identical to subject)* |
| serial | `C1E986160DA8E980` |
| validity | `2016-03-13T01:52:13Z` → `2041-03-07T01:52:13Z` |
| key | RSA 4096 |
| DER bytes | 2 051 |
| `cert_sha256` | `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` |
| `spki_sha256` | `52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5` |

| channel | source | UTC | result |
| --- | --- | --- | --- |
| C1 | `https://freetsa.org/files/cacert.pem` | 2026-08-02T19:24:16Z | ✅ fingerprint as above |
| C2 | Mozilla NSS `certdata.txt` | 2026-08-02T19:27:07Z | ✖ absent — no browser programme carries a timestamping-only root |
| C2 | CCADB Microsoft feed | 2026-08-03T07:20:23Z | ✖ absent |
| C3 | `https://web.archive.org/web/20160829015301id_/https://freetsa.org/files/cacert.pem` | fetched 2026-08-02T19:25:31Z, snapshot **2016-08-29** | ✅ identical |
| C3 | `https://web.archive.org/web/20190723200626id_/https://freetsa.org/files/cacert.pem` | fetched 2026-08-02T19:25:31Z, snapshot **2019-07-23** | ✅ identical |
| C4 | root embedded verbatim in `testdata/anchors/A25-bootstrap/roots-freetsa-token.tsr`; `openssl ts -verify -CAfile` → `Verification: OK` | 2026-08-02T19:25:48Z | ✅ |

**Complete** — C1 + C3(×2) + C4. Two archive snapshots ten and seven years
old, from an independent operator, agree with today's vendor fetch.

**Who this admits:** Free TSA — one operator in Würzburg, DE. A self-signed
root with a personal email address in its subject, no audit, no root-programme
membership. It is a MVP-SPEC.md line 108 **default**, and A20's gate needs only
one verified token, so a normal seal's offline headline can rest on it alone
whenever DigiCert fails (D57 §8.7).

### digicert-trusted-root-g4

| field | value |
| --- | --- |
| subject | `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4` |
| issuer | *(self-signed)* |
| serial | `059B1B579E8E2132E23907BDA777755C` |
| validity | `2013-08-01T12:00:00Z` → `2038-01-15T12:00:00Z` |
| key | RSA 4096 |
| DER bytes | 1 428 |
| `cert_sha256` | `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988` |
| `spki_sha256` | `59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c` |

| channel | source | UTC | result |
| --- | --- | --- | --- |
| C1 | `https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem` | 2026-08-02T19:26:40Z | ✅ |
| C2 | Mozilla NSS `certdata.txt`, label `DigiCert Trusted Root G4` | 2026-08-02T19:27:07Z | ✅ **identical**, 1 428 B |
| C2 | CCADB Microsoft feed, row `DigiCert / DigiCert Trusted Root G4` | 2026-08-03T07:20:23Z | ✅ `552F7BDC…C89988` — **identical**, third independent operator |
| C4 | the token's intermediate verifies under this root with the cross-certificate withheld; `openssl ts -verify -CAfile DigiCertTrustedRootG4.pem` → `Verification: OK` | 2026-08-02T19:27Z | ✅ |

**Complete** — C1 + C2(×2) + C4.

The live token additionally supplies a **cross-certificate** of this root
(subject `DigiCert Trusted Root G4`, issuer `DigiCert Assured ID Root CA`,
serial `0E9B188EF9D02DE7EFDB50E20840185A`, expires **2031-11-09**) with the
identical `spki_sha256`. It is deliberately **not** pinned: it and its issuer
expire six years earlier, so pinning it would strand every token issued after
2031 (D57 §2).

**Who this admits:** DigiCert Inc.

### dfn-verein-community-root-ca-2022

| field | value |
| --- | --- |
| subject | `C=DE, O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V., OU=DFN-PKI, CN=DFN-Verein Community Root CA 2022` |
| issuer | *(self-signed)* |
| serial | `01` |
| validity | `2022-01-26T14:08:41Z` → `2042-01-21T14:08:41Z` |
| key | RSA 4096 |
| DER bytes | 1 544 |
| `cert_sha256` | `3cdc2c9e9e5a36cb5888fd1796cb912f846253b682c1b32057532033510c7bb6` |
| `spki_sha256` | `e686263a55fc1d1d7e5952a2d708597816e1f462a6b1a5dae975ddd421a8a1b0` |

| channel | source | UTC | result |
| --- | --- | --- | --- |
| C1 | `https://pki.pca.dfn.de/dfn-verein-community-root-ca/pub/cacert/cacert.pem` | 2026-08-02T19:35:11Z | ✅ DER byte-identical to the token-embedded copy |
| C1 (2nd vendor path) | `https://pki.pca.dfn.de/dfn-verein-community-ca/pub/cacert/chain.txt` | 2026-08-02T19:35:11Z | ✅ same fingerprint |
| C2 | Mozilla NSS `certdata.txt` | 2026-08-02T19:27:07Z | ✖ absent |
| C2 | CCADB Microsoft feed (550 rows) | 2026-08-03T07:20:23Z | ✖ absent — zero DFN rows |
| **C3** | `https://web.archive.org/web/20220905132932id_/https://doku.tid.dfn.de/_media/de:dfnpki:ca:dfn-verein_community_root_ca_2022.cer` | fetched 2026-08-03T07:35:01Z, snapshot **2022-09-05** (47 months old) | ✅ 1 544 B, **DER byte-identical**, `3cdc2c9e…0c7bb6` |
| **C3** | `https://web.archive.org/web/20240720220435id_/https://www.pki.fraunhofer.de/cmsExtern/dfn/dfn-verein-community-root-ca/cacert/cacert.crt` | fetched 2026-08-03T07:35:01Z, snapshot **2024-07-20** (24 months old) | ✅ 1 544 B, **DER byte-identical** |
| corroborating (not a channel) | live `https://www.pki.fraunhofer.de/cmsExtern/dfn/dfn-verein-community-root-ca/cacert/cacert.crt` | 2026-08-03T07:35:01Z | ✅ byte-identical, from a non-DFN operator |
| C4 | root embedded verbatim in `testdata/anchors/A25-bootstrap/roots-dfn-token.tsr` | 2026-08-02T19:31:00Z | ✅ |

**Complete** — C1(×2) + C3(×2) + C4. Every digest above was recomputed here
from the retrieved bytes; none is transcribed from a page.

**Recorded deviation from C3's letter, because it is a deviation.** D57 §6
defines C3 as *"an Internet Archive Wayback `…id_/` raw snapshot **of the C1
URL**, at least 12 months old"*. The C1 URL has **no** Wayback capture at any
date — verified by CDX sweeps over `pki.pca.dfn.de*`, `cdp.pca.dfn.de*`,
`cdp1…`, `cdp2…`, which hold only bare Apache directory-listing pages. What the
archive does hold is the identical certificate under two other paths, and both
rows above are those.

The reason this is treated as C3 executed rather than C3 waived is D57's own
purpose clause for the channel, quoted in full: *"Independent operator **and**
independent in time: it defeats a present-day compromise of the vendor's web
server, which is the threat C1 alone cannot address."* A 2022-09-05 capture
held by the Internet Archive defeats a present-day compromise of DFN's web
tier completely; the URL within DFN's estate that the archive happened to
crawl does not bear on that. The second row is strictly stronger again — the
Internet Archive holding bytes served by **Fraunhofer**, an operator
independent of DFN — so the two rows are independent in *origin* as well as in
time. Both are 1 544 B DER and byte-equal, and the Internet Archive's own
content digest is identical across the two unrelated origin hosts.

**The honest limit of this evidence**, stated because a reader could over-read
it: Fraunhofer and Hochschule Trier redistribute DFN's root as DFN members.
They are independent **operators**, not an independent **source of truth**.
There is no CT-log, browser-root-programme or OS-bundle attestation for this
certificate and there never will be — `crt.sh` returns *"Certificate not
found"* (checked 2026-08-03T07:28Z), which is the expected answer for a
deliberately non-publicly-trusted community root. C3 never claimed source
independence, only operator-and-time independence, so this limit is inside
what the channel asserts.

**Naming correction carried from D57 §8.1**, repeated here because it is the
error most likely to recur: `tasks/A.md` A7 named
"DFN-PKI/**T-TeleSec** for zeitstempel.dfn.de". The live chain terminates at
this **self-signed** root with **no T-Systems involvement**;
`T-TeleSec GlobalRoot Class 2` anchors DFN's separate *Global* hierarchy, a
different PKI. The token's own bag confirms it: `PN: Zeitstempel 2026` →
`DFN-Verein Community Issuing CA 2022` → this root.

**Who this admits:** DFN-Verein / DFN-CERT Services GmbH (DE academic).

### sectigo-public-time-stamping-root-r46

| field | value |
| --- | --- |
| subject | `C=GB, O=Sectigo Limited, CN=Sectigo Public Time Stamping Root R46` |
| issuer | *(self-signed)* |
| serial | `783D056CFA832E7E69F85622769F02B9` |
| validity | `2021-03-22T00:00:00Z` → `2046-03-21T23:59:59Z` |
| key | RSA 4096 |
| DER bytes | 1 406 |
| `cert_sha256` | `4941b001b8a97e961b7817c9d9e960ec4b056bfc915a8c1aabf6ef6b3ac046a5` |
| `spki_sha256` | `a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795` |

| channel | source | UTC | result |
| --- | --- | --- | --- |
| C1 | `http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt` | re-executed 2026-08-03T07:24:59Z | ✅ 1 406 B, DER **byte-identical** to the committed copy — **plain HTTP only**, see the transport finding |
| C2 | Mozilla NSS `certdata.txt` | 2026-08-02T19:27:07Z | ✖ absent (NSS carries Sectigo's *email* and *server-auth* R46 roots only) |
| C2 | CCADB Microsoft feed, row `Sectigo / Sectigo Public Time Stamping Root R46`, Microsoft status `Included`, EKU `Time Stamping` | 2026-08-03T07:20:23Z | ✅ `4941B001B8A97E961B7817C9D9E960EC4B056BFC915A8C1AABF6EF6B3AC046A5` — **identical** |
| C3 | Internet Archive | searched 2026-08-03T07:16Z | ✖ **no snapshot exists at any age** — see below |
| C4 | `spki_sha256` equality with the USERTrust-issued cross-certificate inside `roots-sectigo-token.tsr` | 2026-08-02T19:31:17Z | ✅ `a4db8668…4795` |

**Complete** — C1 + C2 + C4. This is the root D57 §6 singled out as needing a
mandatory second non-C4 channel; the CCADB Microsoft feed is it.

**Transport finding, re-measured today and unchanged.** `https://crt.sectigo.com/…`
still fails TLS from this host —
`curl: (35) OpenSSL/3.0.20: error:0A000410:SSL routines::sslv3 alert handshake failure`
— and the root is served only over **plain HTTP**. C1 for this root is
therefore *unauthenticated transport*, which is exactly why D57 made a second
non-C4 channel mandatory rather than elective here.

**The C3 route does not exist for this root, and the near-misses are traps.**
The Wayback CDX index over `crt.sectigo.com*` (624 distinct URLs, queried
2026-08-03T07:16Z) holds **no snapshot of `SectigoPublicTimeStampingRootR46.crt`
at any date**. It does hold
`SectigoPublicTimeStampingRootR46_USERTrust.crt` (2025-12-30) and
`…_AAA.crt` (2026-01-01) — but those are **cross-certificates**, not this
root: same SPKI, different DER, different `cert_sha256`, and both are under
12 months old in any case. Recorded so a later attempt does not mistake one
for a completed C3.

The token supplies a **cross-certificate** of this root (issuer
`USERTrust RSA Certification Authority`, serial `36C2B0BD7C1B3AE7A3B3DD36CBC97568`,
expires **2038-01-18**), same SPKI. Not pinned; USERTrust anchors a very large
general-purpose PKI and the cross-certificate expires eight years before this
root does (D57 §2).

**Who this admits:** Sectigo Limited (GB). Note that
`timestamp.entrust.net` is **served by Sectigo** — byte-identical signer
certificate, measured at A46 — so pinning this root also covers Entrust, and
the two endpoints are *not* two independent anchors.

---

## Quarantine

These roots are named in D57 §5's target set and are **deliberately not
compiled in**. Each line is read by `mod.rs`'s
`the_store_matches_the_provenance_record` test, which fails if any of them
appears in `ROOTS_V1`.

- QUARANTINED: swisssign-signature-services-root-2020-2

The cost of a quarantine is stated rather than implied: MVP-SPEC.md line 108
documents both TSAs as configurable alternates, and U26 lets a user select
them. Because A20's gate is "proceed iff ≥1 TSA token passed **full core**
verification", a user who configures only quarantined TSAs gets a **hard
pre-payment seal abort**, not a weaker bundle. That is loud and recoverable;
compiling a root in on evidence we do not have is neither. Promotion is an
A26 append: one `PinnedRoot` block, one version bump, one section moved out of
this list.

### swisssign-signature-services-root-2020-2

| field | value |
| --- | --- |
| subject | `C=CH, O=SwissSign AG, CN=SwissSign Signature Services Root 2020 - 2, organizationIdentifier=NTRCH-CHE-109.357.012` |
| issuer | *(self-signed)* |
| serial | `2FDBA9B88D001EBCE7B99C2D23EF4A` |
| validity | `2020-10-07T10:19:32Z` → `2050-09-30T10:19:32Z` |
| key | RSA 4096 |
| DER bytes | 1 508 |
| `cert_sha256` | `b87f292a4d9feace2d669159eb26f56d85ec77c19e01098cd754e8abb310cde5` |
| `spki_sha256` | `dff8cab3df2b7d27e9ed6533a77712ca8cc6ecf1c64282c4b501ded283965dfd` |

| channel | source | UTC | result |
| --- | --- | --- | --- |
| C1 | `https://www.swisssign.com/dam/jcr:1e0bd04a-23dd-4f31-8ce6-32a2b70b9896/SwissSign_Signature_Services_Root_2020_-_2.pem` | 2026-08-03T07:23:09Z | ✖ **HTTP 403** from the vendor's edge — see the transport finding |
| C1 (alternate host) | `https://swisssign.net/cgi-bin/authority/download/425419CD83663AE8815437BBEEF09B15E3723E39.pem` | 2026-08-03T07:24:09Z | ✖ HTTP 404 (the host answers, this root is not published there) |
| C2 | Mozilla NSS `certdata.txt` | 2026-08-02T19:27:07Z | ✖ absent (NSS carries `SwissSign Gold CA - G2` only) |
| C2 | CCADB Microsoft feed, 8 SwissSign rows | 2026-08-03T07:20:23Z | ✖ **absent** — Gold/Platinum/Silver G2–G3 and the 2022 TLS/SMIME roots only; this root is not in the programme |
| C3 | `https://web.archive.org/web/20250420035940id_/https://www.swisssign.com/dam/jcr:1e0bd04a-23dd-4f31-8ce6-32a2b70b9896/SwissSign_Signature_Services_Root_2020_-_2.pem` | fetched 2026-08-03T07:23:50Z, snapshot **2025-04-20** (15.5 months old) | ✅ **DER byte-identical** to the committed copy, `b87f292a…10cde5` |
| C4 | root embedded verbatim in `roots-swisssign-token.tsr` | 2026-08-02T19:31:33Z | ✅ |

**Blocked on: C1.** C3 and C4 are executed and agree byte-for-byte, so this
root is materially better attested than it was under D57 (which recorded it as
resting on C4 alone). What is missing is a *live* vendor fetch.

**Transport finding.** `www.swisssign.com` returns **HTTP 403** from this host
to every request — `https` and `http`, with and without a browser
`User-Agent`, with and without `www`, and to a deliberately nonexistent path
under the same `/dam/` prefix, which shows the block is on the *client* rather
than the resource. The independent fetch tool available in this environment
also received 403. This is the same class of finding as Sectigo's TLS failure:
a channel that is unexecutable **from this host**, not a channel that does not
exist.

**Why C3 is not silently promoted to stand in for C1.** It is tempting: the
C3 snapshot *is* a capture of the vendor's own URL, so it answers C1's
question ("did the CA publish these bytes?") with an added property C1 lacks
(immunity to a present-day compromise of the vendor's server), and C4 supplies
the currency C1 would otherwise contribute. That is a real argument — and it
is an argument for **amending D57's procedure**, which is a decision, not a
judgement call for the implementing task. Making it here would mean this task
had rewritten its own admission rule to admit the root it was evaluating.
**A56** owns it: either execute C1 from a host SwissSign does not block, or
carry the amendment as a reviewed decision.

---

## Roots deliberately never pinned

- `DigiCert Assured ID Root CA` — issuer of DigiCert's cross-certificate.
  Pinning it would add a second, six-years-earlier-expiring anchor and a
  second organisation-scale trust anchor for **zero** additional capability
  once D57's ruling P1 holds.
- `USERTrust RSA Certification Authority` — the same argument for Sectigo, and
  strictly worse: USERTrust anchors a very large general-purpose PKI.
- The `T-TeleSec GlobalRoot Class 2` / `DFN-Verein Certification Authority 2`
  hierarchy — DFN's *Global* PKI, a different hierarchy from the *Community*
  one `zeitstempel.dfn.de` actually uses.

## Reproducing the fingerprints

```sh
sha256sum crates/antseal-core/src/anchor/roots/<label>.der          # cert_sha256
openssl x509 -inform DER -in <label>.der -noout -pubkey \
  | openssl pkey -pubin -outform DER | sha256sum                    # spki_sha256
```

`mod.rs`'s `pinned_store_fingerprints_match_the_embedded_bytes` runs the same
two computations in-tree on every `cargo test`.
