# TSA root provenance record (D57 / A7 bootstrap)

**NON-SECRET.** Every artefact here is a public trust anchor, a public
RFC 3161 response, or a request built from the documented fixed test seed
(`testdata/README.md`: `W = 00 01 … 1f`). No vault, wallet or key material.

Produced during the M2 planning round for
`docs/decisions/D57-tsa-root-store-scope.md`. A7 promotes these `.der`
files into `crates/antseal-core/src/anchor/roots/` once the channels marked
**NOT EXECUTED** below have been run. Nothing here is a golden vector; the
files are evidence and development fixtures.

## The probe request

`roots-probe.tsq` — one DER `TimeStampReq`, `certReq = 1`, nonce
`0xF0F14E09C9F30B67`, `messageImprint` = SHA-256
`c76db11e7d95fb40c1ecfe98b74e4a3a59907d1f8da6a2ef10d399f5013b6999`
= `SHA-256("antseal/D57 roots-probe digest" ‖ W)`, the
`alternate_test_secret` formula
(`crates/antseal-core/src/test_util/mod.rs:261`). Reproduce with:

```
openssl ts -query -digest c76db11e7d95fb40c1ecfe98b74e4a3a59907d1f8da6a2ef10d399f5013b6999 \
  -sha256 -cert -out roots-probe.tsq
```

(the nonce is freshly drawn per invocation, so a regenerated `.tsq` will
differ from the committed one in that field only).

## The five responses

One request per TSA; Sectigo's ~15 s spacing respected, SwissSign's
~10/day budget untouched (one request).

| file | endpoint | UTC | HTTP | bytes | status |
| --- | --- | --- | --- | --- | --- |
| `roots-freetsa-token.tsr` | `https://freetsa.org/tsr` | 2026-08-02T19:25:47Z | 200 | 4 644 | Granted, genTime `Aug 2 19:27:56 2026 GMT`, nonce echoed |
| `roots-digicert-token.tsr` | `http://timestamp.digicert.com` | 2026-08-02T19:25:48Z | 200 | 6 008 | Granted, genTime `Aug 2 19:27:57 2026 GMT`, nonce echoed |
| `roots-dfn-token.tsr` | `https://zeitstempel.dfn.de` | 2026-08-02T19:31:00Z | 200 | 6 670 | Granted ("Operation Okay") |
| `roots-sectigo-token.tsr` | `http://timestamp.sectigo.com` | 2026-08-02T19:31:17Z | 200 | 6 637 | Granted |
| `roots-swisssign-token.tsr` | `http://tsa.swisssign.net` | 2026-08-02T19:31:33Z | 200 | 6 859 | Granted ("Operation Okay") |

## The five roots

All values below read from the committed `.der` bytes, not transcribed.

### 1. `roots-freetsa-root-ca.der`

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
| C1 vendor | `https://freetsa.org/files/cacert.pem` | 2026-08-02T19:24:16Z | ✅ fingerprint as above |
| C2 root programme | Mozilla NSS `certdata.txt` | 2026-08-02T19:27:07Z | ✖ **absent** — not in any browser root programme |
| C3 archive | `https://web.archive.org/web/20160829015301id_/https://freetsa.org/files/cacert.pem` | fetched 2026-08-02T19:25:31Z, snapshot **2016-08-29** | ✅ identical |
| C3 archive | `https://web.archive.org/web/20190723200626id_/https://freetsa.org/files/cacert.pem` | fetched 2026-08-02T19:25:31Z, snapshot **2019-07-23** | ✅ identical |
| C4 operational | root embedded verbatim in `roots-freetsa-token.tsr`; `openssl ts -verify -CAfile` → `Verification: OK` | 2026-08-02T19:25:48Z | ✅ |

**Complete.** Two archive snapshots ten and seven years old, from an
independent operator, agree with today's vendor fetch.

### 2. `roots-digicert-trusted-root-g4.der`

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
| C1 vendor | `https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem` | 2026-08-02T19:26:40Z | ✅ |
| C2 root programme | Mozilla NSS `certdata.txt`, label `DigiCert Trusted Root G4` | 2026-08-02T19:27:07Z | ✅ **identical fingerprint**, 1 428 B |
| C4 operational | the token's intermediate verifies under this root with the cross-certificate withheld; `openssl ts -verify -CAfile DigiCertTrustedRootG4.pem` → `Verification: OK` | 2026-08-02T19:27Z | ✅ |

**Complete.**

The token additionally supplies a **cross-certificate** of this root
(subject `DigiCert Trusted Root G4`, issuer `DigiCert Assured ID Root CA`,
serial `0E9B188EF9D02DE7EFDB50E20840185A`, expires **2031-11-09**) whose
`spki_sha256` is identical to the value above. It is **not** pinned; see
D57 §2.

### 3. `roots-dfn-verein-community-root-ca-2022.der`

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
| C1 vendor | `https://pki.pca.dfn.de/dfn-verein-community-root-ca/pub/cacert/cacert.pem` | 2026-08-02T19:35:11Z | ✅ **byte-identical DER** to the token-embedded copy |
| C1 vendor (2nd path) | `https://pki.pca.dfn.de/dfn-verein-community-ca/pub/cacert/chain.txt` | 2026-08-02T19:35:11Z | ✅ same fingerprint |
| C2 root programme | Mozilla NSS | 2026-08-02T19:27:07Z | ✖ absent |
| C3 archive | — | — | **⚠ NOT EXECUTED — A7 must run this** |
| C4 operational | root embedded verbatim in `roots-dfn-token.tsr` | 2026-08-02T19:31:00Z | ✅ |

**Note**: `tasks/A.md` A7 names "DFN-PKI/T-TeleSec" for this TSA. That is
wrong — the live chain is `DFN-Verein Community Root CA 2022`, self-signed,
with no T-Systems involvement. `T-TeleSec GlobalRoot Class 2` anchors DFN's
separate *Global* hierarchy. See D57 §8.1.

### 4. `roots-sectigo-public-time-stamping-root-r46.der`

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
| C1 vendor | `http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt` | 2026-08-02T19:34:49Z | ✅ — **plain HTTP only**, see below |
| C2 root programme | Mozilla NSS | 2026-08-02T19:27:07Z | ✖ absent (NSS carries Sectigo's *email* and *server-auth* R46 roots, not the timestamping one) |
| C3 archive | — | — | **⚠ NOT EXECUTED — A7 must run this, and here it is MANDATORY** |
| C4 operational | `spki_sha256` equality with the cross-certificate inside `roots-sectigo-token.tsr` (`a4db8668…4795`) | 2026-08-02T19:31:17Z | ✅ |

**Transport finding**: `https://crt.sectigo.com/...` and
`https://crt.usertrust.com/...` both fail with
`curl: (35) OpenSSL/3.0.20: error:0A000410:SSL routines::sslv3 alert handshake failure`
(measured 2026-08-02T19:34:27Z). The vendor channel for this root is
therefore **unauthenticated transport**, which makes a second non-C4
channel mandatory rather than elective.

The token supplies a **cross-certificate** of this root (issuer
`USERTrust RSA Certification Authority`, serial
`36C2B0BD7C1B3AE7A3B3DD36CBC97568`, expires **2038-01-18**), same SPKI.
Not pinned; see D57 §2.

### 5. `roots-swisssign-signature-services-root-2020-2.der`

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
| C1 vendor | — | — | **⚠ NOT EXECUTED — A7 must run this** |
| C2 root programme | Mozilla NSS | 2026-08-02T19:27:07Z | ✖ absent (NSS carries `SwissSign Gold CA - G2` only) |
| C3 archive | — | — | **⚠ NOT EXECUTED** |
| C4 operational | root embedded verbatim in `roots-swisssign-token.tsr` | 2026-08-02T19:31:33Z | ✅ |

**This root currently rests on C4 alone and must not enter the compiled
store until C1 and one of C2/C3 are executed.** C4 alone is same-operator
corroboration and is never sufficient (D57 §6).

## Totals

Five roots, **7 937 bytes** of DER.

## Certificate ordering inside the CMS `certificates` SET

Recorded because A9 must not assume any order (D57 §3):

| token | order |
| --- | --- |
| `roots-freetsa-token.tsr` | `[leaf, ROOT(self-signed)]` |
| `roots-digicert-token.tsr` | `[leaf, CA, CA]` |
| `roots-dfn-token.tsr` | `[ROOT(self-signed), leaf, CA]` |
| `roots-sectigo-token.tsr` | `[leaf, CA, CA]` |
| `roots-swisssign-token.tsr` | `[ROOT(self-signed), CA, leaf]` |

## Signature algorithms observed

| token | SignerInfo signature | signer key | chain-link signature |
| --- | --- | --- | --- |
| FreeTSA | `ecdsa-with-SHA512` | **EC P-384** | `sha512WithRSAEncryption` |
| DigiCert | `sha384WithRSAEncryption` | RSA 4096 | `sha384WithRSAEncryption` |
| DFN | `sha256WithRSAEncryption` | RSA 4096 | `sha256WithRSAEncryption` |
| Sectigo | `sha384WithRSAEncryption` | RSA 4096 | `sha384WithRSAEncryption` |
| SwissSign | `sha256WithRSAEncryption` | **RSA 3072** | `sha256WithRSAEncryption` |
