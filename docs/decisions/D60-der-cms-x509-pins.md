# D60 — DER/CMS/X.509/signature crate pins, and P-256 TSA support

- **Status: RESOLVED — seven new exact pins land in `antseal-core`, one
  existing pin gains a feature, and `p256` is NOT among them. The set is
  `der =0.8.1`, `const-oid =0.10.2`, `x509-cert =0.3.0`, `cms =0.3.0-pre.2`,
  `p384 =0.14.0`, `rsa =0.10.0-rc.18`, `sha1 =0.11.0`, plus `oid` added to
  the existing `sha2 =0.11.0`. Measured: `antseal-core`'s normal graph goes
  **55 → 82 packages**, **zero** new duplicate-version pairs, **zero**
  `getrandom`/`rand` (the `core-dep-graph` lane stays green), and the whole
  set `cargo check`s for `wasm32-unknown-unknown`. Two of the register's five
  nominees survive only off their stable lines, and its second question is
  answered no: `rsa` at its *stable* line (0.9.10) is
  **structurally impossible** — it drags `rand 0.8.7` + `rand_chacha 0.3.1`
  into the normal graph, which the dep-graph lane's own forbidden-name regex
  fails red, plus 8 new duplicate pairs including a second `signature`, `digest`,
  `der`, `spki` and `pkcs8`; `cms` at its *stable* line (0.2.3) forks the DER
  stack into two generations including a **second `x509-cert`**; and `p256`
  is dropped outright. Two crates the register never named are **required**:
  `sha1` (ESSCertID v1's `certHash` is SHA-1 *by definition*, and FreeTSA —
  the normative ECDSA TSA — sends v1 and nothing else) and `const-oid` with
  its `db` feature. The strictness rule I nearly shipped —
  "`to_der(from_der(x)) == x`" — is **rejected on measurement**: 6 of 9 live
  TSAs, DigiCert among them, emit a non-DER-sorted `certificates` SET, so
  that rule would make A5/A8/A9's DigiCert Accept rows unsatisfiable.**
- **Date: 2026-08-02** (M2 planning round; register `TODO.md:572`, "A-OD8")
- **Owning task: A5**, with A8 (algorithm registry), A9 (chain limits) and
  P7 (pin governance) as the consuming tasks
- **Blocks: A5, A8, A9; also A6, A24, A28** — none of them can start until
  this is settled

---

## Context — what the register claimed, and what survived

`TODO.md:572` and `tasks/A.md` A-OD8 both frame the decision as:

> **A-OD8 — DER/CMS/X.509/signature crate selection + exact pins** (`der`,
> `cms`, `x509-cert`, `rsa`, `p384`; whether to also support ECDSA P-256 TSA
> certs beyond the normative P-384+RSA), decided with P's pin process.

Five nominees, one question. After measurement:

| register nominee | verdict |
| --- | --- |
| `der` | **survives** — at `=0.8.1`, the generation the project already locks |
| `cms` | **survives only at `=0.3.0-pre.2`**; the stable `0.2.3` is disqualified (§1.3) |
| `x509-cert` | **survives** at `=0.3.0` |
| `rsa` | **survives only at `=0.10.0-rc.18`**; the stable `0.9.10` is disqualified (§1.4) |
| `p384` | **survives** at `=0.14.0` |
| `p256` | **out of v1** (§4) |
| — | **`sha1 =0.11.0` added** — the register's list is incomplete (§3.4) |
| — | **`const-oid =0.10.2` + `db` added**; `sha2` gains `oid` (§1.2) |
| — | `spki`, `ecdsa`, `signature` deliberately **not declared** (§1.5) |

The spec's own claim at line 108 — *"no turnkey pure-Rust CMS verifier
exists (`cms` parses only; `x509-cert` has no path validation)"* — **holds at
these exact versions and is now measured, not inherited**:

```
$ grep -rn "TstInfo|TSTInfo|TimeStampReq|MessageImprint" cms-0.3.0-pre.2/src x509-cert-0.3.0/src
(no output)
$ grep -rn "fn verify|verify_signature|PathValidation" x509-cert-0.3.0/src/*.rs
(no output)
$ ls cms-0.3.0-pre.2/src/ | grep -c tsp
0
```

There is no RFC 3161 type anywhere in the closure and no path-validation
entry point in `x509-cert`. A5/A8/A9 remain the budgeted work the spec says
they are.

---

## 1. The pin set

### 1.1 The declarations, verbatim

Add to `[workspace.dependencies]` in `/home/deb/Documents/code0/Cargo.toml`:

```toml
const-oid = { version = "=0.10.2", default-features = false, features = ["db"] }
der = { version = "=0.8.1", default-features = false, features = ["alloc", "derive", "oid"] }
x509-cert = { version = "=0.3.0", default-features = false }
cms = { version = "=0.3.0-pre.2", default-features = false }
p384 = { version = "=0.14.0", default-features = false, features = ["ecdsa", "pkcs8"] }
rsa = { version = "=0.10.0-rc.18", default-features = false, features = ["encoding"] }
sha1 = { version = "=0.11.0", default-features = false }
```

and change the existing `sha2` line — the **only** edit to an existing pin —
from

```toml
sha2 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }
```

to

```toml
sha2 = { version = "=0.11.0", default-features = false, features = ["oid", "zeroize"] }
```

`oid` is load-bearing, not tidiness: `rsa::pkcs1v15::VerifyingKey::<D>::new`
requires `D: AssociatedOid`, which `sha2`'s `oid` feature supplies. Without
it the DigiCert path does not compile:

```
error[E0599]: the function or associated item `new` exists for struct
              `rsa::pkcs1v15::VerifyingKey<Sha256>`, but its trait bounds
              were not satisfied
   = note: `Sha256: AssociatedOid` is not satisfied
```

`zeroize` stays — D88 is untouched (`sha2`'s `zeroize` and `oid` are
independent features; adding `oid` activates only `digest/oid`).

Every one of these is declared in `crates/antseal-core/Cargo.toml` as
`<name>.workspace = true`. **None of them may be declared by
`antseal-anchor`, `antseal-net` or `antseal-cli`** — all anchor verification
lives in core (spec lines 47–53, 106) and a second declaration site is how
the containment erodes. A30 makes that a lane rule.

### 1.2 What each pin is for, and where it lands

| crate | pin | what antseal uses it for | crate |
| --- | --- | --- | --- |
| `der` | `=0.8.1` | the DER reader/writer and the `Sequence`/`Choice` derives A5's hand-written RFC 3161 types are built on; the strictness guarantees of §2 | `antseal-core` |
| `const-oid` | `=0.10.2` | named OID constants (`db::rfc5280::ID_KP_TIME_STAMPING`, the digest and signature OIDs of §3.3). Declared for the **`db` feature**, which today is switched on only by `cms`'s own requirement — depending on a third party's feature activation is how a `cms` drop silently breaks the build | `antseal-core` |
| `x509-cert` | `=0.3.0` | `Certificate`/`TbsCertificate` parsing, `Name` comparison, the `ext::pkix` extension types (BasicConstraints, KeyUsage, ExtendedKeyUsage) A9 reads. **Supplies no path validation** — A9 writes that | `antseal-core` |
| `cms` | `=0.3.0-pre.2` | the RFC 5652 model: `ContentInfo`, `SignedData`, `SignerInfo`, `SignedAttributes`, `CertificateChoices`. Parse only — every check in §3 is antseal's | `antseal-core` |
| `p384` | `=0.14.0` | ECDSA P-384 signature verification over a supplied prehash | `antseal-core` |
| `rsa` | `=0.10.0-rc.18` | RSA PKCS#1 v1.5 signature verification (`encoding` gives `pkcs1`, needed to read an `RSAPublicKey` out of an SPKI) | `antseal-core` |
| `sha1` | `=0.11.0` | **ESSCertID v1 `certHash` only** (§3.4). Never a signature digest, never a messageImprint algorithm, never a cert-link digest | `antseal-core` |

### 1.3 `cms` — why the pre-release, and what taking it costs

Measured against the exact antseal-core normal graph (probe reproduced from
`crates/antseal-core/Cargo.toml`'s dependency block; verified identical to
`cargo tree -p antseal-core -e normal --locked` modulo `hybrid-array`
0.4.13/0.4.14, which is a lockfile artefact, not a resolution difference):

```
cms =0.2.3   (STABLE)        +8 packages, 5 NEW duplicate pairs:
    added:  base64ct 1.8.3, cms 0.2.3, const-oid 0.9.6, der 0.7.10,
            der_derive 0.7.3, pem-rfc7468 0.7.0, spki 0.7.3, x509-cert 0.2.5
    dupes:  const-oid 0.9.6 | 0.10.2      der 0.7.10 | 0.8.1
            der_derive 0.7.3 | 0.8.0      spki 0.7.3 | 0.8.0
            x509-cert 0.2.5 | 0.3.0
            (`cargo tree -d` reports 6 names; the 6th is the pre-existing
             syn 2.0.119 | 3.0.3 proc-macro pair deny.toml already records)

cms =0.3.0-pre.2             +1 package (cms itself), 0 new duplicate pairs
```

A second `x509-cert` in one binary is not bloat, it is a confusion hazard: two
`Certificate` types that do not interconvert, in the crate whose whole job is
deciding which certificate signed a timestamp. **`cms 0.2.3` is rejected.**

The pre-release costs two things, both named rather than hidden:

1. **It enables `der`'s `ber` feature** for the whole graph
   (`cms 0.3.0-pre.2`'s manifest: `der = { version = "0.8.0-rc.10", features
   = ["ber", "derive", "oid"] }`), which cargo unifies. Measured resolved
   features: `der v0.8.1|alloc,ber,derive,flagset,oid,zeroize`.
   **Proven harmless to `from_der`** — §2 runs real BER through it and gets
   `IndefiniteLength` — but it makes `Decode::from_ber` *reachable from
   antseal source*, which is a footgun with no legitimate caller here. A30
   bans the token at lane level.
2. **It is a pre-release pin.** The project already carries two
   (`argon2 =0.6.0-rc.8`, `blake2 =0.11.0-rc.6`), so the precedent and the
   governance exist; P23 records the stabilisation watch and the yank risk.

The alternative — hand-writing the RFC 5652 structs on `der`'s derives — was
evaluated and rejected: it is ~250 lines of ASN.1 model whose correctness
antseal would own forever, against +1 package for a model that parses all
nine real tokens tested here and re-encodes both `ContentInfo`s byte-identically
(4634→4634, 5998→5998). The hand-written boundary belongs at RFC 3161, where
no crate exists at all (§3.1) — not at RFC 5652, where one does.

### 1.4 `rsa` — the stable line is structurally impossible

```
rsa =0.9.10  (STABLE)        +22 packages, 8 NEW duplicate pairs:
    added:  const-oid 0.9.6, crypto-common 0.1.7, der 0.7.10, digest 0.10.7,
            generic-array 0.14.7, lazy_static 1.5.0, libm 0.2.16,
            num-bigint-dig 0.8.6, num-integer 0.1.46, num-iter 0.1.46,
            pkcs1 0.7.5, pkcs8 0.10.2, ppv-lite86 0.2.21, rand 0.8.7,
            rand_chacha 0.3.1, rand_core 0.6.4, rsa 0.9.10, signature 2.2.0,
            smallvec 1.15.2, spin 0.9.9, spki 0.7.3, zerocopy 0.8.55
    dupes:  signature 2.2.0 | 3.0.0     digest 0.10.7 | 0.11.3
            der 0.7.10 | 0.8.1          spki 0.7.3 | 0.8.0
            const-oid 0.9.6 | 0.10.2    pkcs8 0.10.2 | 0.11.0
            crypto-common 0.1.7 | 0.2.2 rand_core 0.6.4 | 0.10.1
            (`cargo tree -d` reports 9 names; the 9th is the pre-existing
             syn 2.0.119 | 3.0.3 proc-macro pair)

rsa =0.10.0-rc.18            +2 packages (rsa, crypto-primes 0.7.2),
                             0 new duplicate pairs
```

The duplicate `signature`/`digest` pair is a major finding on its own — but
the decisive fact is mechanical. `scripts/ci-lanes.sh`'s `dep_graph` lane
asserts:

```sh
local forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) '
tree="$(cargo tree -p antseal-core -e normal --prefix none --locked)"
```

and `rsa 0.9.10` puts `rand v0.8.7` and `rand_chacha v0.3.1` in exactly that
tree, as a **normal** dependency:

```
$ cargo tree -e normal -i rand
rand v0.8.7
└── num-bigint-dig v0.8.6
    └── rsa v0.9.10
        └── probe-rsa-stable v0.0.0
```

`^rand ` matches `rand v0.8.7`. The lane goes red. `rsa 0.9.10` in
`antseal-core` is not a trade-off, it is a build that cannot pass CI.
There is no escape hatch in `antseal-anchor` either: all anchor verification
lives in core by spec mandate.

**`crypto-primes 0.7.2`** is a non-optional dependency of `rsa 0.10.0-rc.18`
(prime generation, used only by keygen, which antseal never calls). It cannot
be feature-gated away; it is 1 of the 2 added packages and is recorded here so
it is not later mistaken for a mistake.

### 1.5 What is deliberately NOT declared

- **`spki`** — `x509-cert 0.3.0`'s manifest requires it as
  `spki = { version = "0.8", features = ["alloc"] }` **unconditionally**, so
  the feature is ours through our own edge. Reach it as `x509_cert::spki`.
- **`ecdsa`** — reached as `p384::ecdsa`. A direct edge would add a pin that
  must move in lockstep with `p384` for no benefit.
- **`signature`** — reached as `p384::ecdsa::signature` / `rsa::signature`.
  `antseal-core` does not declare it today (it arrives via `ed25519-dalek
  =3.0.0` and `ml-dsa =0.1.1`) and this decision does not change that.

### 1.6 The measured graph

| graph | packages | forbidden names | new duplicate pairs |
| --- | --- | --- | --- |
| `antseal-core` normal, today | 55 | none | none |
| `antseal-core` normal, with the §1.1 set | **82** (+27) | **none** | **none** |

Added: `base16ct 1.0.0`, `base64ct 1.8.3`, `cms 0.3.0-pre.2`,
`const-oid 0.10.2`, `cpubits 0.1.1`, `crypto-bigint 0.7.5`,
`crypto-primes 0.7.2`, `der 0.8.1`, `der_derive 0.8.0`, `ecdsa 0.17.0`,
`elliptic-curve 0.14.1`, `ff 0.14.0`, `flagset 0.4.7`, `group 0.14.0`,
`p384 0.14.0`, `pem-rfc7468 1.0.0`, `pkcs1 0.8.0-rc.4`, `pkcs8 0.11.0`,
`primefield 0.14.0`, `primeorder 0.14.0`, `rfc6979 0.6.0`,
`rsa 0.10.0-rc.18`, `sec1 0.8.1`, `sha1 0.11.0`, `spki 0.8.0`,
`wnaf 0.14.0`, `x509-cert 0.3.0`.

`cargo tree -d -e normal` reports only the pre-existing `syn 2.0.119 |
3.0.3` proc-macro pair that `deny.toml` already records. **No second copy of
`sha2`, `digest`, `signature`, `der`, `spki`, `const-oid` or `pkcs8`.**

**Both feature graphs, as the architecture constraint requires.** Measured
today on the real crate:

```
$ cargo tree -p antseal-core -e normal --prefix none --locked            | sort -u | wc -l
56
$ cargo tree -p antseal-core -e normal --all-features --prefix none --locked | sort -u | wc -l
80
```

(56 and 80 include `antseal-core` itself; the 55 above does not. The 24-package
spread is `test-util`'s `dep:proptest` edge —
`crates/antseal-core/Cargo.toml:36` — and this decision does not touch it.)

**None of the seven pins is optional and none is activated by a feature**, so
the delta is the same in both: default **56 → 83**, all-features
**80 → 107** *(derived: 80 + 27, since the added closure is identical in both
graphs)*. The all-features graph is the one `deny.toml`'s
`[graph] all-features = true` scans, so §1.7's advisory sweep covers it.

`wasm32-unknown-unknown`, the whole set including antseal-core's existing
dependencies:

```
$ cargo check --lib --target wasm32-unknown-unknown
    Checking sha1 v0.11.0
    Checking minicbor v2.3.0
    Checking final v0.0.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 32.86s
```

### 1.7 Advisories, licences, upstream state

Sweep run **2026-08-02T19:39Z** against `api.osv.dev` (which unions RUSTSEC
and GHSA — D19 records that RUSTSEC alone is known-incomplete), over every
package in the added closure:

| package | advisories |
| --- | --- |
| `der`, `const-oid`, `spki`, `x509-cert`, `cms`, `p384`, `p256`, `ecdsa`, `signature`, `elliptic-curve`, `crypto-bigint`, `crypto-primes`, `sec1`, `pkcs1`, `pkcs8`, `der_derive`, `base16ct`, `ff`, `group`, `primefield`, `primeorder`, `wnaf`, `rfc6979`, `cpubits`, `flagset`, **`sha1`** | **0** |
| `rsa` | **4**: `RUSTSEC-2023-0071` = `CVE-2023-49092` = `GHSA-4grx-2x9w-596c` = `GHSA-c38w-74pg-36hr` (Marvin attack, one advisory under four ids); `GHSA-9c48-w39g-hm26` = `CVE-2026-21895` |

Verified with the project's own pinned tool, `cargo-deny 0.19.8`, against the
ruled set:

```
error[vulnerability]: Marvin Attack: potential key recovery through timing sidechannels
   ├ ID: RUSTSEC-2023-0071
   ├ Solution: No safe upgrade is available!
   ├ rsa v0.10.0-rc.18
advisories FAILED
```

**An `[advisories].ignore` entry is therefore mandatory**, not optional —
`cargo deny check advisories` is a per-PR required job (`audit-deny`) plus a
weekly cron. The RUSTSEC range is `introduced: 0.0.0-0` with **no** fixed
version, so no `rsa` release escapes it. The exact entry is in §7.5.

`GHSA-9c48-w39g-hm26` (panic on a prime equal to 1, LOW) is bounded
`fixed: 0.9.10`; `0.10.0-rc.18` is outside the range, and the affected path is
key generation, which antseal never calls. **No ignore entry is needed and
none may be added** — an ignore for an inapplicable advisory is dead config,
the shape `deny.toml`'s header already rejects.

**Licences.** Every added package is `Apache-2.0 OR MIT` (the RustCrypto
ecosystem's uniform terms). The `licenses` check is stubbed until Q29
(`deny.toml`, bottom), so nothing goes red today; the Q29 allowlist needs no
new entry beyond the `MIT`/`Apache-2.0` pair D6 already names. **This set adds
no copyleft** — a fact worth stating because `antseal-core` is the crate D6
flags as the one that must never acquire GPL.

**Upstream state**, `crates.io` API, 2026-08-02T19:24Z:
`der` 0.8.1 (2026-07-09), `const-oid` 0.10.2 (2026-01-07),
`spki` 0.8.0 (2026-04-04), `x509-cert` 0.3.0 (2026-07-09),
`cms` max_stable 0.2.3 / max 0.3.0-pre.2 (2026-01-25),
`rsa` max_stable 0.9.10 / max 0.10.0-rc.18 (2026-04-27),
`p384` 0.14.0 (2026-07-06), `p256` 0.14.0 (2026-07-03),
`ecdsa` 0.17.0 (2026-07-02), `signature` 3.0.0 (2026-05-02),
`sha1` 0.11.0 (2026-07-10).

---

## 2. Strict-DER capability, proven

Every result below is `der 0.8.1` **with the `ber` feature ON** (as `cms`
forces it), through the `Decode::from_der` entry point. Source of the
guarantee: `from_der` builds `SliceReader::new(bytes)`, whose
`EncodingRules` defaults to `Der`; `Length::decode`'s BER branch is taken
only when `reader.encoding_rules()` is `Ber`.

### 2.1 What `der 0.8.1` rejects for free

| case | input | result |
| --- | --- | --- |
| indefinite length | `30 80 05 00 00 00` | `IndefiniteLength` |
| non-minimal long-form length | `30 81 02 05 00` | `Length { tag: SEQUENCE }` |
| non-minimal 2-octet length | `30 82 00 02 05 00` | `Length { tag: SEQUENCE }` |
| 5-octet length prefix | `30 85 …` | `Length { tag: SEQUENCE }` |
| trailing data after the TLV | `05 00 FF` | `TrailingData { decoded: 2, remaining: 1 }` |
| truncation | `30 05 00` | `Incomplete { expected: 4, actual: 3 }` |
| **redundant** INTEGER leading zero | `02 02 00 05` | `Noncanonical { tag: INTEGER }` |
| redundant INTEGER leading `FF` | `02 02 FF 80` | `Noncanonical { tag: INTEGER }` |
| empty INTEGER | `02 00` | `Noncanonical { tag: INTEGER }` |
| BER BOOLEAN `TRUE` | `01 01 01` | `Noncanonical { tag: BOOLEAN }` |
| 2-octet BOOLEAN | `01 02 FF FF` | `Length { tag: BOOLEAN }` |
| constructed OCTET STRING (BER) | `24 06 04 01 AA 04 01 BB` | `TagUnknown { byte: 36 }` |
| BIT STRING `unused = 8` | `03 02 08 AA` | `Value { tag: BIT STRING }` |
| GeneralizedTime, fractional secs | `20260802192227.5Z` | `Value { tag: GeneralizedTime }` |
| GeneralizedTime, no seconds | `202608021922Z` | `Value { tag: GeneralizedTime }` |
| GeneralizedTime, `+0100` offset | `20260802192227+0100` | `Value { tag: GeneralizedTime }` |
| GeneralizedTime, no `Z` | `20260802192227` | `Value { tag: GeneralizedTime }` |
| nesting depth > 63 | 64 nested SEQUENCEs | `NestingDepth` |

**The one that would have bitten**: a leading `00` octet in an INTEGER is
*required*, not redundant, when the next octet's high bit is set. DigiCert's
real `TSTInfo.serialNumber` is exactly that shape —
`02 11 00 D5 8D 33 F1 …` (17 octets) — and `der` **accepts** it while
rejecting `02 02 00 05`. A hand-rolled "reject any leading zero" strictness
check would reject every DigiCert token. Pinned as a test in §7.4.

### 2.2 What `der 0.8.1` does NOT give, measured

| gap | evidence |
| --- | --- |
| **non-minimal OID subidentifier** | `06 04 2A 80 03 04` (leading `0x80` in a subidentifier, X.690 §8.19.2) is **ACCEPTED** |
| **SET OF ordering** | `SetOfVec::decode_value` calls `der_sort(...)` on DER input — it silently **canonicalises** rather than rejecting. `31 05 01 01 00 05 00` and `31 05 05 00 01 01 00` both decode, and both re-encode to `31 05 01 01 00 05 00` |
| **SET OF duplicates** | `31 04 05 00 05 00` is **ACCEPTED**; `der`'s own test is named `der_sort_preserves_duplicates` |

Consequence, measured on real material: a FreeTSA token whose four
`signedAttrs` are reversed in place
(`testdata/anchors/A25-bootstrap/D60-ber-unsorted-setof-freetsa.tsr`) decodes
to the same attribute order as the pristine token, re-encodes to a
byte-identical 187-octet `SET OF`, and **its ECDSA signature still verifies**.

That is correct per RFC 5652 §5.4 (the signature is over "the DER encoding of
the SignedAttrs", which is the canonical order), and it is not a soundness
break for antseal — nothing binds the token *bytes* to anything;
`anchor_digest` is the manifest digest and the token commits to it through
`messageImprint`. It is recorded because it means **TSA token bytes are
malleable under SET OF reordering**, which A22's golden vectors must not
assume away.

### 2.3 The rule I rejected, and why

The obvious total strictness rule is `to_der(from_der(x)) == x`: one check,
one error code, no hand-written walker, and it closes §2.2's whole list at a
stroke. At the `TimeStampResp` level it looked perfect —

```
freetsa    parse=OK  re-encode BYTE-IDENTICAL (4643 -> 4643 bytes)
digicert   parse=OK  re-encode BYTE-IDENTICAL (6007 -> 6007 bytes)
…all nine live TSAs BYTE-IDENTICAL…
```

— and it is **vacuous**. `ContentInfo.content` is an `Any`; `to_der` re-emits
its captured bytes verbatim and never re-encodes the `SignedData` inside. The
reordered-attribute fixture passes the top-level round-trip too.

Applied at the level where it is *not* vacuous — decode the `[0]` content as
`SignedData` and re-encode — it catches the tamper, and it also **rejects six
of nine real TSAs**:

| TSA | `SignedData` re-encode == wire slice |
| --- | --- |
| freetsa | true |
| dfn | true |
| swisssign | true |
| **digicert** | **false** (first diff at offset 163) |
| **sectigo** | **false** (offset 294) |
| **apple** | **false** (offset 147) |
| **globalsign** | **false** (offset 269) |
| **certum** | **false** (offset 247) |
| **entrust** | **false** (offset 293) |

Cause: the CMS `certificates` field is `[0] IMPLICIT CertificateSet`, a
SET OF, and DER requires it sorted by encoding. Real TSAs emit it in **chain
order** (leaf first). `der` re-sorts on decode, so the re-encode differs. DFN
and SwissSign pass only because their wire order happens to coincide with DER
order (both emit root-first). FreeTSA passes because it carries two
certificates whose order happens to be the DER order.

**Ruling: no re-encode/byte-compare strictness rule.** It would make A5's
Accept row *"Real FreeTSA and DigiCert responses parse successfully"* and
A8's *"Real … DigiCert (RSA) fixtures verify"* unsatisfiable. antseal's DER
strictness is exactly what §2.1 lists, plus §7.2's error-class mapping, and
the §2.2 gaps are **documented deviations with a stated reason**, not
oversights.

### 2.4 The recursion hazard antseal must not create

`der`'s depth guard lives in `Reader::split_nested`
(`der-0.8.1/src/reader/position.rs:76-79`, `MAX_DEPTH = 64`) and covers only
`der`'s own descent. It is per parse invocation: `TSTInfo::from_der(econtent)`
and `Extension::extn_value` re-parses start a fresh budget.

Any recursive DER walker **antseal** writes is unguarded by construction, and
that is not theoretical:

```
$ ./depth 20000
depth=20000 bytes=83407
thread 'main' has overflowed its stack
fatal runtime error: stack overflow, aborting        (exit 134, SIGABRT)
$ ./depth 200000
(exit 137, SIGKILL)
```

A stack overflow aborts the process; it is not catchable by `catch_unwind`,
and on `wasm32` it traps. A5's *"Adversarial input returns typed errors —
never panics"* is therefore violated by any hand-written recursive prescan.

**Ruling: `antseal-core` contains no recursive DER walker.** Depth is
enforced by `der`'s guard, consumed by name (§6, limit b1). Should a future
task need its own traversal, it is iterative with an explicit depth counter,
and the fixture above is its regression test.

---

## 3. The hand-written boundary

### 3.1 What comes from a crate and what antseal writes

| piece | source |
| --- | --- |
| DER reader/writer, strictness of §2.1, `NestingDepth` guard | **`der`** |
| `ContentInfo`, `SignedData`, `SignerInfo`, `SignedAttributes`, `Attribute`, `CertificateChoices`, `SignerIdentifier` | **`cms`** |
| `Certificate`, `TbsCertificate`, `Name`, `SubjectPublicKeyInfo`, `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `Validity` | **`x509-cert`** / `spki` |
| ECDSA P-384 verification over a prehash | **`p384`** |
| RSA PKCS#1 v1.5 verification, `RSAPublicKey` from SPKI | **`rsa`** |
| SHA-256/384/512; SHA-1 for `certHash` only | **`sha2`**, **`sha1`** |
| `TimeStampReq`, `TimeStampResp`, `PKIStatusInfo`, `PKIFailureInfo`, `TSTInfo`, `MessageImprint`, `Accuracy` | **antseal (A4/A5)** — no crate in the closure defines them |
| signed-attribute set parsing; `content-type`, `message-digest`, `signing-time` checks | **antseal (A8)** |
| `messageImprint` == `anchor_digest`; nonce match | **antseal (A8)** |
| ESSCertID / ESSCertIDv2 binding | **antseal (A8)** — `cms` models `Attribute` but neither crate defines `SigningCertificate` |
| critical-EKU `id-kp-timeStamping` enforcement | **antseal (A8)** |
| algorithm dispatch (§3.3) | **antseal (A8)** |
| single-path chain building, name chaining, BasicConstraints, KeyUsage, validity at `genTime` | **antseal (A9)** — `x509-cert` has none of it |

The RFC 3161 shell is small. This is the complete `TimeStampResp` type,
compiled and run against all nine real responses in §5:

```rust
#[derive(Debug, Sequence)]
struct PkiStatusInfo {
    status: Int,
    #[asn1(optional = "true")] status_string: Option<Any>,
    #[asn1(optional = "true")] fail_info: Option<BitString>,
}
#[derive(Debug, Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")] time_stamp_token: Option<ContentInfo>,
}
```

### 3.2 Facts from real tokens that change what A8 must do

Every row measured on the nine responses in §5. Each is a rule an
implementer working from `tasks/A.md` alone would get wrong.

1. **`SignerInfo.signatureAlgorithm` carries two legal spellings for RSA.**
   Five of nine TSAs — DigiCert, Sectigo, Apple, Certum, Entrust — put bare
   `rsaEncryption` (`1.2.840.113549.1.1.1`, parameters `NULL`) there and
   leave the digest to `SignerInfo.digestAlgorithm` (RFC 5754 §3.2). Three —
   DFN, SwissSign, GlobalSign — use explicit `shaNNNWithRSAEncryption`.
   Accepting only one form breaks the majority, DigiCert included.
2. **FreeTSA signs `ecdsa-with-SHA512` (`1.2.840.10045.4.3.4`) on a P-384
   key** — not the SHA-384 the usual pairing suggests. `p384`'s
   `VerifyingKey::verify_prehash` accepts the full 64-byte SHA-512 hash
   directly and handles FIPS 186-5 §6.4 leftmost-bits truncation internally
   (verified: `ECDSA-P384/SHA-512 signature VERIFIES`).
3. **Certificates in the `certificates` bag are not in a guaranteed order.**
   The signer is `c1` for six TSAs, `c2` for DFN and `c3` for SwissSign. A
   chain builder that assumes leaf-first is wrong for two of the spec's
   three documented alternates.
4. **Every one of the nine signer certificates has `EKU` marked
   `critical`** with `id-kp-timeStamping` — A8's criticality rule is safe.
   But DigiCert's **intermediate** carries a *non-critical* EKU, so the
   criticality requirement applies to the signer certificate **only**; a
   rule applied to CA certificates rejects DigiCert.
5. **SwissSign's signer certificate has no `BasicConstraints` extension at
   all.** RFC 5280 §4.2.1.9 permits that for an end entity. A9 must require
   `cA = TRUE` on every CA in the path and must **not** require the extension
   to be present on the signer.
6. **`SignerInfo.sid` is not covered by the signature** (RFC 5652 §5.4 signs
   only `signedAttrs`). That is precisely why the SigningCertificate
   attribute exists and why §3.4's binding is load-bearing rather than
   ceremonial. The same is true of `SignerInfo.digestAlgorithm`, which is
   self-checking in both of its uses (a flipped value breaks the
   message-digest length comparison and the signature simultaneously) — but
   A8 must take no other decision from it.
7. **A self-signed root may be embedded in the token.** FreeTSA ships its own
   root as `c2`. A6's *"bundle-embedded certificates are consumed strictly as
   intermediates — never as trust anchors"* is not hypothetical: the
   candidate is in the bytes.
8. **A pinned root's self-signature is never verified.** Apple's root
   self-signs with `sha1WithRSAEncryption`; a rule requiring the anchor's own
   signature to verify would need SHA-1 as a *signature* digest, which §3.3
   rejects. The trust anchor is trusted for its SPKI and subject, not for its
   self-signature.
9. **Two "different" TSAs can be one TSA.** `timestamp.entrust.net` returned a
   token whose signer certificate is byte-identical to `timestamp.sectigo.com`'s
   (issuer `CN=Sectigo Public Time Stamping CA R41`, serial
   `0xE74EF255B0504FFADBA6DFF7FC8BA315`). Two tokens from those two endpoints
   are one anchor's worth of independence. → **A31**.

### 3.3 The accepted-algorithm registry (A8 implements as data, not `match` arms)

**Digest algorithms** — accepted wherever antseal chooses a hash:

| OID | name | accepted in |
| --- | --- | --- |
| `2.16.840.1.101.3.4.2.1` | SHA-256 | `digestAlgorithms`, `SignerInfo.digestAlgorithm`, cert-link digests, `messageImprint` |
| `2.16.840.1.101.3.4.2.2` | SHA-384 | as above except `messageImprint` |
| `2.16.840.1.101.3.4.2.3` | SHA-512 | as above except `messageImprint` |

`TSTInfo.messageImprint.hashAlgorithm` MUST be **SHA-256 exactly** — A4
always requests it and `anchor_digest` is SHA-256 (spec line 109). Anything
else → `anchor-digest-alg-unsupported`.

**SHA-1 (`1.3.14.3.2.26`) is rejected in every one of those positions.** This
is not defensive theatre: Apple's TSA really does sign with
`SignerInfo.digestAlgorithm = sha1`, so the check has a live positive case
and a committed fixture (`D60-tsa-apple-resp.tsr`).

**Signature algorithms:**

| OID | name | accepted in |
| --- | --- | --- |
| `1.2.840.10045.4.3.2` | ecdsa-with-SHA256 | `SignerInfo.signatureAlgorithm`, cert links |
| `1.2.840.10045.4.3.3` | ecdsa-with-SHA384 | as above |
| `1.2.840.10045.4.3.4` | ecdsa-with-SHA512 | as above |
| `1.2.840.113549.1.1.11` | sha256WithRSAEncryption | as above |
| `1.2.840.113549.1.1.12` | sha384WithRSAEncryption | as above |
| `1.2.840.113549.1.1.13` | sha512WithRSAEncryption | as above |
| `1.2.840.113549.1.1.1` | rsaEncryption (digest from `digestAlgorithm`) | **`SignerInfo.signatureAlgorithm` ONLY — never a certificate's** |

The last row's restriction is the point: in a certificate, `signatureAlgorithm`
is the only statement of which digest the issuer used, so a bare
`rsaEncryption` there leaves the digest unbound and must be rejected.
Measured: **all 27** certificates embedded across the nine tokens
(2+3+3+3+3+3+4+3+3) carry an explicit `shaNNNWithRSAEncryption`; **not one**
uses the bare form. The restriction therefore costs no real TSA anything.

**Curves:** `secp384r1` (`1.3.132.0.34`) only — see §4.

**Explicitly rejected, with reasons:** RSASSA-PSS (`1.2.840.113549.1.1.10`) —
not served by any of the nine; a residual, not an omission.
`sha1WithRSAEncryption` (`1.2.840.113549.1.1.5`) — observed only on Apple's
root self-signature, which §3.2.8 says is never verified. Ed25519 / Ed448 —
not served by any TSA reachable today.

### 3.4 SHA-1, and the objection a reviewer will raise

**The fact, verified on two independent captures.** `SigningCertificate`
(`1.2.840.113549.1.9.16.2.12`, RFC 2634 §5.4) carries `ESSCertID`, whose
`certHash` is *defined* as the SHA-1 hash of the whole certificate. Measured
against the real signer certificate on my own capture **and** on the
committed `testdata/anchors/A25-bootstrap/freetsa-D59-resp.tsr`:

```
freetsa signer cert 1636 bytes
    SHA-1(cert)  = 481fd53c534d384180c0286519a036f988544766
    attr 1.2.840.113549.1.9.16.2.12  SHA-1  481fd53c…544766 -> matches signer cert: true
```

The cross-lane report was **correct**. `sha1` is unavoidable, because
avoiding it means one of two things, both rejected:

- **Require ESSCertIDv2.** Four of nine TSAs send **v1 only** — FreeTSA,
  Sectigo, Apple, Entrust. FreeTSA is the *normative* ECDSA P-384 TSA
  (spec line 109). Rejecting v1-only tokens rejects it.
- **Don't check the attribute.** It is the only *signed* statement of which
  certificate the TSA used (§3.2.6), and antseal evaluates chain validity at
  `genTime`, so an unchecked certificate identity is exactly the lever an
  attacker would use to swap in a certificate with a wider validity window
  and turn `valid-at-stamping-cert-since-expired` into `proven`.

**The objection, answered.** SHA-1 is broken for collision resistance
(SHAttered 2017; chosen-prefix 2020), and X.509 certificate collisions are
the demonstrated application. Two things make its use here sound, and both
must be written into the module's doc comment so a reviewer meets the
reasoning before the code:

1. **SHA-1 is a selector here, never the trust decision.** The trust decision
   is A9's path validation to a *pinned, compiled-in* root: name chaining,
   per-link signature verification under §3.3's algorithms, `cA = TRUE` on
   every CA, KeyUsage, critical EKU on the signer, and validity at `genTime`.
   A colliding certificate must additionally satisfy all of that against a
   pinned root — i.e. the attacker needs a real CA to issue it. The SHA-1
   comparison never widens the trusted set; it can only *narrow* it.
2. **It is a redundant check, not the only one.** The signer certificate is
   located by `SignerInfo.sid`'s issuerAndSerialNumber *and* must satisfy
   the certHash; where ESSCertIDv2 is present it is checked too, under
   SHA-256; where `ESSCertID.issuerSerial` is present it must equal `sid`.
   Removing the SHA-1 leg leaves the chain validation intact.

**And two rules the RFC states that the measurements make concrete.** RFC
5035 §5.4: *"The first certificate identified in the sequence of certificate
identifiers MUST be the certificate used to verify the signature."*
Sectigo and Entrust send **three** `ESSCertID` entries — signer, CA, root:

```
sectigo  attr …16.2.12  SHA-1 e97818a9…eeeac -> matches signer cert: true
         attr …16.2.12  SHA-1 65c32869…bf74f -> matches signer cert: false
         attr …16.2.12  SHA-1 853d632d…2dac7 -> matches signer cert: false
```

So "any entry matches" is too weak and "all entries match" rejects Sectigo.
**Only the first is checked against the signer.** And ESSCertIDv2's
`hashAlgorithm` is a DER `DEFAULT id-sha256`: DigiCert and DFN omit it
entirely, so absent ⇒ SHA-256, and an *explicitly encoded* `id-sha256` there
is a DER violation (DER forbids encoding a DEFAULT value) → `anchor-der-not-strict`.

**Containment.** `sha1 =0.11.0` costs exactly **+1 package**, has **zero**
advisories, and is on the `digest 0.11` generation the project already pins.
`default-features = false` drops `alloc` and `oid` — antseal calls only
`Sha1::digest`, never uses SHA-1 through an `AssociatedOid` bound, and the
absence of `oid` is itself a small structural guard against SHA-1 ever being
selected as a signature digest. A30 makes the confinement a lane rule.

---

## 4. P-256: out of v1

**The measurement.** Nine live public TSAs, one request each, 2026-08-02:

| TSA | endpoint | signer key | signature algorithm |
| --- | --- | --- | --- |
| FreeTSA | `https://freetsa.org/tsr` | **EC P-384** | ecdsa-with-SHA512 |
| DigiCert | `http://timestamp.digicert.com` | RSA 4096 | rsaEncryption / SHA-256 |
| DFN | `http://zeitstempel.dfn.de` | RSA 4096 | sha256WithRSA |
| Sectigo | `http://timestamp.sectigo.com` | RSA 4096 | rsaEncryption / SHA-384 |
| SwissSign | `http://tsa.swisssign.net` | RSA 4096 | sha256WithRSA |
| Apple | `http://timestamp.apple.com/ts01` | RSA 2048 | rsaEncryption / **SHA-1** |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | RSA 3072 | sha384WithRSA |
| Certum | `http://time.certum.pl` | RSA 4096 | rsaEncryption / SHA-384 |
| Entrust | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | RSA 4096 | rsaEncryption / SHA-384 |

**Exactly one TSA uses ECDSA at all, and it is P-384. Zero serve P-256.**
That covers both spec defaults and all three documented alternates.

**Ruling: P-256 is not supported in v1.** The argument is not the dependency
graph — `p256 =0.14.0` costs exactly **+1 package**, measured. It is that a
verification path no real TSA exercises can never be validated against a real
token, so a defect in it is undetectable until the day it matters. The
project's own standard is that a test which cannot fail is a defect; an
algorithm branch whose only fixture is one antseal generated for itself is
the same defect wearing a crypto hat. Each supported algorithm also costs an
A21 tamper row, an A22 golden vector and an A24 mock-TSA signer variant.

**Revisit trigger, with its cost priced.** If any *default or documented
alternate* TSA rotates to a P-256 certificate, add it: one workspace pin line
(`p256 = { version = "=0.14.0", default-features = false, features =
["ecdsa", "pkcs8"] }`, +1 package), two rows in §3.3's curve and signature
tables, one recorded fixture, one A21 row. Nothing in this decision is shaped
to make that hard — §3.3 is a data registry precisely so adding a row is a
data change. A26's root-store review is the natural place to notice the
rotation.

**A note against a symmetric mistake.** "Support both, it's only +1 package"
would also have been defensible had any real TSA served P-256. None does, and
`tasks/A.md` A-OD8's own phrasing ("*beyond* the normative P-384+RSA") makes
P-256 the addition that needs justification, not the omission.

---

## 5. The captured evidence

Recorded under `testdata/anchors/A25-bootstrap/` with the `D60-` prefix, so
nothing collides with the OTS `*.timestamp` files or the `freetsa-D59-*`
pair. Provenance, UTC timestamps, endpoint list and the derivation of every
tamper fixture: `testdata/anchors/A25-bootstrap/D60-CAPTURE.log`.

Nine request/response pairs (`D60-tsa-<name>-req.tsq` /
`D60-tsa-<name>-resp.tsr`), all `PKIStatus: granted`, all nonce-echoed, plus
five derived tamper fixtures. **No TSA refused anything** — not `certReq`,
not the nonce, not HTTP vs HTTPS, and no rate limit was reached at one
request per endpoint spaced ≥ 3 s.

### 5.1 Dissection

| property | value |
| --- | --- |
| stamped digest | `083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df` (the committed golden vector) |
| request | 69–70 B, v1, SHA-256 messageImprint, 64-bit nonce, `certReq = TRUE` |
| nonce echo | **9 / 9 exact** |
| `genTime` encoding | **9 / 9 `YYYYMMDDHHMMSSZ`, exactly 15 octets, second precision, no fractional part, `Z`-terminated** |
| `TSTInfo.accuracy` | present in 4 / 9 (SwissSign 4 B, Apple/GlobalSign/Certum 3 B) — OPTIONAL, must be tolerated |
| `TSTInfo.ordering` | present only on FreeTSA (`TRUE`) |
| `SignerIdentifier` | **9 / 9 `issuerAndSerialNumber`** (SignerInfo version 1); no `subjectKeyIdentifier` seen |
| signed-attribute count | 4 or 5 (max **5**) |
| ESSCertID versions | v1 only: FreeTSA, Sectigo, Apple, Entrust · v2 only: DFN, SwissSign, GlobalSign · **both**: DigiCert, Certum |
| chain embedded | yes, 2–4 certificates; **max 4** (GlobalSign) |
| signer-cert EKU | **9 / 9 present and `critical`** with `id-kp-timeStamping` |

### 5.2 Sizes, against the frozen caps

| quantity | max measured | which | frozen cap | margin |
| --- | --- | --- | --- | --- |
| `TimeStampResp` bytes | **7 660** | GlobalSign | `MAX_TSA_TOKEN_BYTES` = 1 048 576 | **136.9 ×** |
| CMS token bytes | 7 651 | GlobalSign | — | — |
| single certificate bytes | **2 105** | SwissSign signer | `MAX_CERT_BYTES` = 65 536 | **31.1 ×** |
| certificates per token | **4** | GlobalSign | `MAX_INTERMEDIATE_COUNT` = 16 | 4.0 × |
| DER depth, `TimeStampResp` | **19** | Sectigo/SwissSign/GlobalSign/Certum/Entrust | — | see §6 b1 |
| DER depth, `TSTInfo` re-parse | 7 | FreeTSA | — | — |
| DER depth, certificate re-parse | 6 | all | — | — |
| DER depth, extension re-parse | 7 | FreeTSA root | — | — |
| signed attributes | **5** | DigiCert/DFN/SwissSign/Certum | — | see §6 b4 |

The depth-19 path is the ESSCertIDv2 `issuerSerial` → `GeneralNames` →
`[4] directoryName` → `RDNSequence` → `RDN` → `AttributeTypeAndValue` chain
inside `signedAttrs`, present in the five TSAs that populate `issuerSerial`.

### 5.3 End-to-end verification with the ruled crate set

```
FreeTSA   SignedData version=V3   digestAlgs=["2.16.840.1.101.3.4.2.3"]
  signerInfo digestAlgorithm      = 2.16.840.1.101.3.4.2.3   (SHA-512)
  signerInfo signatureAlgorithm   = 1.2.840.10045.4.3.4      (ecdsa-with-SHA512)
  signedAttrs count               = 4   (contentType, signingTime,
                                         signingCertificate, messageDigest)
  eContent (TSTInfo) bytes        = 379
  message-digest attr == SHA-512(eContent): true
  signedAttrs DER re-encode: 187 bytes, first byte 0x31
  ECDSA-P384/SHA-512 signature VERIFIES (verify_prehash over 64-B hash)

DigiCert  signerInfo digestAlgorithm    = 2.16.840.1.101.3.4.2.1  (SHA-256)
  signerInfo signatureAlgorithm         = 1.2.840.113549.1.1.1    (rsaEncryption)
  signatureAlgorithm parameters         = NULL
  signedAttrs count                     = 5   (+ signingCertificateV2)
  embedded cert count                   = 3
  RSA modulus bits                      = 4096
  RSA-PKCS1v15/SHA-256 signature VERIFIES

FreeTSA leaf sigAlg = 1.2.840.113549.1.1.13   root sigAlg = 1.2.840.113549.1.1.13
  root RSA modulus bits = 4096
  leaf<-root RSA-PKCS1v15/SHA-512 cert-link signature VERIFIES
```

Both normative tokens verify, and the FreeTSA path needs **both** algorithm
families in one token: ECDSA-P384/SHA-512 for the signature and
RSA-PKCS1v15/SHA-512 for the certificate link.

### 5.4 The clock

This host's clock ran **129 s slow** at capture time, measured against three
unrelated hosts' HTTP `Date` headers within one second of each other
(freetsa.org +129 s, crates.io +128 s, blockstream.info +129 s), and
consistent with the observed gap between the local POST time (19:20:19Z) and
FreeTSA's `genTime` (19:22:27Z).

The consequence is a rule, not a footnote: **no anchor-stage or capture-path
check may treat a token's `genTime` as invalid because it exceeds a local
clock reading.** An implementer writing the obvious `gen_time <= fetch_date`
sanity check would reject every token in `D60-*`. `antseal-core` cannot make
this mistake by construction — it reads no clock, and `verify_at` is a
parameter (A9, A18) — but `antseal-anchor`'s A10 capture client *can*, since
it is the one that stamps `fetch_date`. → **A32**.

---

## 6. The four open (b)-class limits

Each obeys F1–F4 (`docs/format/anchor-artifact-limits.md` §1): evaluated only
in the anchor stage, never reachable from `SealProof::decode`; an over-limit
artifact fails **that anchor alone** as `invalid`; raise-only thereafter.

### b1 — max DER nesting depth: **63, consumed from `der`, not minted**

`der 0.8.1` enforces `MAX_DEPTH = 64` in `Reader::split_nested`
(`der-0.8.1/src/reader/position.rs:20,76-79`) — 63 nested constructions
accepted, 64 rejected with `ErrorKind::NestingDepth`, per parse invocation,
not configurable. Bisected:

```
N=62  recursive-Decode OK
N=63  recursive-Decode OK
N=64  recursive-Decode error NestingDepth
```

Measured maximum over nine live TSAs: **19**. Margin **3.3 ×**.

**No antseal constant is minted.** A tighter limit would require antseal to
measure depth, which requires the recursive walker §2.4 proved is a
stack-overflow-to-`abort` hazard. Taking `der`'s guard costs nothing and
keeps `antseal-core` walker-free. `ErrorKind::NestingDepth` maps to
`anchor-der-nesting-depth` (§7.2), which is the "distinct cap error" A5's
Accept row requires.

F4's raise-only rule still binds, and it now binds *upstream*: the assertion
test in §7.4 fails if a `der` bump moves the constant in **either**
direction, so a lowering is refused at the bump review rather than shipped.

### b2 — max certificate count in a validated chain: **`MAX_CHAIN_CERTS = 8`**

Measured maximum path material: 4 certificates (GlobalSign). Deepest real
validated path: 3 links (DigiCert leaf → G4 TS CA → pinned Trusted Root G4),
4 if closed through the cross-certificate to Assured ID Root. Margin
**2.0 ×** over the deepest bag observed.

**Why not 18** (`MAX_INTERMEDIATE_COUNT + signer + root`): because the path
can never *exceed* 18, so an 18-limit is a check that cannot fail — the
defect this project keeps finding. At 8 the limit is reachable: a hostile
bundle carrying 16 intermediates that chain into a 9-long path hits it, and
that is the DoS shape (path building is quadratic in candidates) the limit
exists for.

### b3 — max per-certificate size in a validated chain: **`MAX_CHAIN_CERT_BYTES = 16_384`**

This is genuinely open, and A27 §4 was right that it is: the certificates
A9 validates come out of the **TSA token**, whose only bound is
`MAX_TSA_TOKEN_BYTES` = 1 MiB — *not* out of the bundle's
`intermediates` field, where `MAX_CERT_BYTES` fires in stage 1. Nothing
today stops a hostile token carrying a 900 KiB "certificate".

Measured maximum: **2 105 B** (SwissSign's signer certificate). Margin
**7.8 ×**.

It carries the **A28-shaped derived constraint**
`MAX_CHAIN_CERT_BYTES <= MAX_CERT_BYTES` (16 384 ≤ 65 536), pinned by a
`const` assertion, for exactly A28's reason: a certificate accepted out of a
token must afterwards be embeddable in a `.sealproof` as an intermediate, or
the seal anchors and then cannot be revealed.

This is **not** a duplicate of `MAX_CERT_BYTES` in the sense A5's Accept row
forbids: different value, different name, different surface (token-internal
vs bundle field), and the relationship between them is asserted rather than
assumed. A pinned root, being compiled in and reviewed at A7/A26, is checked
by the same assertion at build time.

### b4 — max signed-attribute count: **`MAX_SIGNED_ATTRS = 16`**

Measured maximum: **5** (DigiCert, DFN, SwissSign, Certum). Margin **3.2 ×**.
RFC 5652's attribute set for a timestamp token is small and closed; 16 is
generous and reachable (a hostile token with 17 attributes hits it).

**Residual, named for A8, not limited here:** `SigningCertificate.certs` is a
`SEQUENCE OF ESSCertID` and Sectigo/Entrust populate three entries. Since only
the first is checked (§3.4), the rest are bounded by the enclosing attribute's
own DER length and need no separate cap; if A8 ever iterates them, it needs
one.

### F4 registry rows — verbatim, for `docs/format/anchor-artifact-limits.md` §5

```
| limit | owner | initial value | date set | measured against (A25 fixture path) | margin | lowered |
| `MAX_DER_NESTING_DEPTH` (consumed from `der 0.8.1` `Reader::MAX_DEPTH`; not minted) | A5 | 63 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr` (measured depth 19) | 3.3x | never |
| `MAX_CHAIN_CERTS` | A5 | 8 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr` (4 certificates) | 2.0x | never |
| `MAX_CHAIN_CERT_BYTES` (derived constraint: `<= MAX_CERT_BYTES`) | A5 | 16384 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-swisssign-resp.tsr` (signer certificate 2105 B) | 7.8x | never |
| `MAX_SIGNED_ATTRS` | A5 | 16 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr` (5 signed attributes) | 3.2x | never |
```

---

## 7. The implementer's contract

### 7.1 Constants — `crates/antseal-core/src/anchor/caps.rs` (new file)

```rust
/// Longest certificate path A9 will build, signer through pinned root.
/// D60 §6 b2. Measured against D60-tsa-globalsign-resp.tsr (4 certificates).
pub const MAX_CHAIN_CERTS: usize = 8;

/// Largest single certificate accepted out of a TSA token. D60 §6 b3.
/// Measured against D60-tsa-swisssign-resp.tsr (signer certificate 2105 B).
pub const MAX_CHAIN_CERT_BYTES: u32 = 16_384;

/// Largest `signedAttrs` set accepted. D60 §6 b4.
/// Measured against D60-tsa-digicert-resp.tsr (5 attributes).
pub const MAX_SIGNED_ATTRS: usize = 16;

/// A28-shaped embeddability constraint: a certificate accepted out of a token
/// must still fit the bundle field it will be embedded in.
const _: () = assert!(MAX_CHAIN_CERT_BYTES as u64 <= crate::codec::caps::MAX_CERT_BYTES);
```

`MAX_DER_NESTING_DEPTH` is **not** declared — §6 b1.

### 7.2 The `der::ErrorKind` → antseal code mapping (A5 implements)

New error-code prefix **`anchor-`**, owner **A** (→ Q72 registers it in
`docs/testing/error-code-contract.md` §2).

`anchor-der-not-strict` means *"the input's encoding does not conform to
DER"*. That definition is deliberately wider than "is BER": `ErrorKind::Length`
carries both a non-minimal length (strictness) and a wrong-length-for-type
(e.g. a 2-octet BOOLEAN), and `der` gives no way to separate them. Both are
non-conforming encodings; both get this code. The alternative — a
hand-written minimal-length prescan — is §2.4's stack-overflow hazard, and
the tamper row this code serves (A21 row 7) binds to fixtures, not to a claim
of perfect classification.

| `der::ErrorKind` | antseal code |
| --- | --- |
| `IndefiniteLength`, `Noncanonical{..}`, `Length{..}`, `Overlength`, `SetOrdering`, `SetDuplicate` | `anchor-der-not-strict` |
| `NestingDepth` | `anchor-der-nesting-depth` |
| `Incomplete{..}`, `TrailingData{..}`, `TagUnknown{..}`, `TagUnexpected{..}`, `TagNumberInvalid`, `TagModeUnknown`, `Value{..}`, `OidMalformed`, `OidUnknown{..}`, `DateTime`, `Overflow`, `Failed`, `Reader`, `EncodingRules`, `FileNotFound`, `PermissionDenied` | `anchor-der-malformed` |

`SetOrdering`/`SetDuplicate` are a **named non-row**: semantically strictness,
but §2.2 proves they are unreachable from the decode path at this pin
(`SetOfVec` canonicalises instead). They are mapped correctly so a future
`der` that starts rejecting produces the right code, and **no tamper row
binds them** — the row that would exist is the one §2.3 rejects.

`FileNotFound`/`PermissionDenied` are `std`-only and unreachable in
`antseal-core`; they are mapped rather than left to a catch-all so the match
stays exhaustive and a new `der` variant is a compile error, not a silent
default.

### 7.3 The eight codes minted here

| code | owner | fires when |
| --- | --- | --- |
| `anchor-der-not-strict` | A5 | the artifact's encoding does not conform to DER (§7.2) |
| `anchor-der-malformed` | A5 | the artifact is not well-formed at all (§7.2) |
| `anchor-der-nesting-depth` | A5 | `der`'s depth guard fires (> 63 in one parse) |
| `anchor-chain-cert-count` | A5 | a built path would exceed `MAX_CHAIN_CERTS` |
| `anchor-chain-cert-size` | A5 | a certificate parsed out of a token exceeds `MAX_CHAIN_CERT_BYTES` |
| `anchor-signed-attr-count` | A5 | `signedAttrs` exceeds `MAX_SIGNED_ATTRS` |
| `anchor-digest-alg-unsupported` | A8 | a digest OID outside §3.3's table appears in any position §3.3 lists |
| `anchor-signature-alg-unsupported` | A8 | a signature OID outside §3.3's table appears, or bare `rsaEncryption` appears in a **certificate**'s `signatureAlgorithm` |

All eight are pairwise distinct, none borrows another family's prefix, each
has a named owner. Every one of them renders the affected anchor `invalid`
per F3 and nothing else (F2).

### 7.4 Tests that must exist, and what makes each fail

| test | location | fails if |
| --- | --- | --- |
| `der_pin_rejects_indefinite_length` | `crates/antseal-core/tests/der_pin_eval.rs` | `der` stops rejecting `30 80 …`, or a future `cms` bump makes `from_der` BER-tolerant. Feeds `D60-ber-indefinite-freetsa.tsr` **and** asserts `from_ber` accepts it — without that second leg the test cannot distinguish "rejected for being BER" from "rejected for being garbage" |
| `der_pin_rejects_nonminimal_length` | same | `D60-ber-nonminimal-len-freetsa.tsr` and `-digicert.tsr` stop producing `anchor-der-not-strict` |
| `der_pin_accepts_required_integer_leading_zero` | same | a strictness change rejects `02 11 00 D5 8D …` — DigiCert's real serial number. **This is the anti-over-strictness test**; without it a future "reject leading zeros" hardening passes review and breaks DigiCert |
| `der_pin_rejects_redundant_integer_leading_zero` | same | `02 02 00 05` starts being accepted |
| `der_nesting_depth_limit_is_63` | same | a `der` bump moves `MAX_DEPTH` in **either** direction. Builds 63 and 64 nested SEQUENCEs and asserts `Ok` / `NestingDepth`. This is the F4 raise-only guard for b1 |
| `der_pin_rejects_non_der_generalized_time` | same | fractional-second, seconds-omitted, offset-bearing or `Z`-less `GeneralizedTime` starts being accepted |
| `der_pin_setof_ordering_is_canonicalised_not_rejected` | same | `der` starts *rejecting* unsorted SET OF. That would be a **welcome** change and must be a deliberate review event, because §2.3's certificates-SET finding says 6 of 9 real TSAs would then fail. Asserts today's behaviour so the day it changes is visible |
| `real_tsa_tokens_parse` | `crates/antseal-core/tests/anchor_real_tokens.rs` | any of the nine `D60-tsa-*-resp.tsr` stops parsing. Nine cases, not two — the seven non-default TSAs are the parser's diversity corpus |
| `real_tsa_tokens_signature_algorithms` | same | the §3.3 registry loses a row a real TSA needs. Asserts, per fixture, the exact `(digestAlgorithm, signatureAlgorithm)` pair — including DigiCert's bare `rsaEncryption` and FreeTSA's `ecdsa-with-SHA512` |
| `freetsa_verifies_ecdsa_p384_sha512` | same | the ECDSA path regresses, or `p384` changes prehash truncation |
| `digicert_verifies_rsa_pkcs1v15_sha256` | same | the RSA path regresses, or `sha2/oid` is dropped (compile failure) |
| `esscertid_v1_binds_signer_cert_by_sha1` | same | the SHA-1 binding regresses. Runs against **both** `D60-tsa-freetsa-resp.tsr` and the committed `freetsa-D59-resp.tsr` (independent captures, same signer certificate, same `certHash` `481fd53c…544766`), plus a one-byte-flipped `certHash` mutant that must be rejected — without the mutant leg an implementation that never reads the attribute passes |
| `esscertid_v1_only_first_entry_is_checked` | same | **two legs, because one is vacuous.** (a) `D60-tsa-sectigo-resp.tsr` verifies, which fails an "all entries must match" rule (its entries 2 and 3 are the CA and root and do not match the signer). (b) A mutant of it whose **first** entry is swapped for the CA's own SHA-1 — a legitimate hash of a certificate genuinely in the bag — is **rejected**, which fails an "any entry matches" rule. Leg (a) alone passes under both rules and would witness nothing |
| `esscertid_v2_absent_hash_alg_defaults_sha256` | same | **two legs.** (a) `D60-tsa-dfn-resp.tsr` (v2 only, `hashAlgorithm` absent — verified: `SEQUENCE(38) > SEQUENCE(36) > SEQUENCE(34) > OCTET STRING(32)`, no AlgorithmIdentifier) verifies. (b) A mutant with one flipped byte in the 32-byte hash is rejected. Leg (a) alone passes an implementation that ignores the attribute entirely |
| `sha1_rejected_as_cms_digest_algorithm` | same | SHA-1 becomes acceptable as a signature digest. Uses `D60-tsa-apple-resp.tsr`, a **real** token whose `SignerInfo.digestAlgorithm` is SHA-1, and asserts `anchor-digest-alg-unsupported` |
| `signer_cert_is_not_assumed_first_in_bag` | same | a leaf-first assumption creeps in. Uses `D60-tsa-dfn-resp.tsr` (signer at index 1) and `D60-tsa-swisssign-resp.tsr` (index 2) |
| `signer_cert_without_basic_constraints_is_accepted` | same | a "BasicConstraints required on the signer" rule is introduced. Uses `D60-tsa-swisssign-resp.tsr` |
| `eku_criticality_required_on_signer_only` | same | criticality is demanded of CA certificates. Uses `D60-tsa-digicert-resp.tsr`, whose intermediate has a non-critical EKU |
| `chain_cert_size_cap_is_reachable_and_bounded_by_bundle_cap` | `crates/antseal-core/tests/anchor_caps.rs` | a synthetic token carrying a 20 KiB certificate stops producing `anchor-chain-cert-size`, or `MAX_CHAIN_CERT_BYTES > MAX_CERT_BYTES` (const assertion) |
| `chain_cert_count_cap_is_reachable` | same | a synthetic 9-long path stops producing `anchor-chain-cert-count`. **Reachability is the assertion** — a limit of 18 would make this test unwritable |
| `signed_attr_count_cap_is_reachable` | same | a synthetic 17-attribute token stops producing `anchor-signed-attr-count` |
| `f1_over_limit_token_leaves_bundle_decodable` | same | F1/F2/F3 regress: bundle still decodes, manifest verdict unchanged, only that anchor `invalid` |
| `anchor_core_has_no_recursive_der_walker` | A30's lane | a recursive DER traversal appears in `antseal-core` source (§2.4) |

### 7.5 The `deny.toml` entry — verbatim

Append inside the existing `[advisories].ignore` array in
`/home/deb/Documents/code0/deny.toml`:

```toml
    # ── D60 (2026-08-02): the one advisory the RFC 3161 pin set carries ──
    { id = "RUSTSEC-2023-0071", reason = "Marvin attack (CVE-2023-49092): a timing side channel in `rsa`'s non-constant-time modular exponentiation that leaks information about the PRIVATE key. antseal-core holds no RSA private key and performs no RSA private-key operation, ever: the only `rsa` API it calls is `pkcs1v15::VerifyingKey::verify`, over a TSA's PUBLIC key read out of a certificate (D60 section 3.3). There is no secret in the computation, so there is nothing for the side channel to leak. The advisory's range is `introduced: 0.0.0-0` with no fixed version, so no `rsa` release escapes it and this is not waiting on an upgrade; upstream tracks the constant-time migration at RustCrypto/RSA#626. Re-assess if antseal ever signs or decrypts with RSA (it has no reason to: authorship signatures are Ed25519 + ML-DSA-65, MVP-SPEC.md line 97). Review by 2027-02-01." },
```

**No entry is added for `GHSA-9c48-w39g-hm26`** — `0.10.0-rc.18` is outside
its `fixed: 0.9.10` range, so `cargo-deny` does not report it and an ignore
would be dead config.

### 7.6 Where the new checks fire in the frozen order

Nothing here touches verify stage 1. Per F1, every check in this decision
lives in the **anchor stage (R12)**, downstream of `SealProof::decode` and of
every D10 cap. Within the anchor stage, for one TSA artifact, in order:

1. `TimeStampResp` strict-DER parse — §7.2 codes.
2. `PKIStatusInfo.status` is `granted` / `grantedWithMods`.
3. `ContentInfo` → `SignedData`; `signedAttrs` count ≤ `MAX_SIGNED_ATTRS`.
4. Each certificate out of the bag: size ≤ `MAX_CHAIN_CERT_BYTES`.
5. Algorithm registry (§3.3) — before any signature verification, so an
   unsupported algorithm is a distinct code and not a verification failure.
6. Signer certificate located by `sid`; ESSCertID / ESSCertIDv2 binding (§3.4).
7. `content-type` / `message-digest` / eContent digest; `TSTInfo` parse;
   `messageImprint` == `anchor_digest`; nonce when supplied.
8. Signature over the DER `SET OF` re-encoding of `signedAttrs`.
9. Critical EKU `id-kp-timeStamping` on the signer.
10. A9: path build ≤ `MAX_CHAIN_CERTS`, per-link verification, name chaining,
    BasicConstraints/KeyUsage, validity at `genTime`.

A failure at any step renders **that anchor** `invalid` (F3) and nothing else
(F2).

---

## 8. Residual risks

1. **Two pre-release pins** (`cms =0.3.0-pre.2`, `rsa =0.10.0-rc.18`). Both
   are frozen by `Cargo.lock`, so a stabilisation or an rc bump is a
   deliberate event, and both have stable-line alternatives that this
   decision disqualifies on measurement rather than taste. The yank risk —
   `cargo deny`'s `yanked` check is on — is P23's.
2. **`der/ber` is on** and `Decode::from_ber` is reachable from antseal
   source. Proven not to weaken `from_der`; banned at lane level by A30.
3. **SET OF ordering is not enforced** (§2.2/§2.3), so TSA token bytes are
   malleable. Harmless because nothing binds token bytes, but A22's golden
   vectors must key on the *verdict*, not on token bytes.
4. **RSASSA-PSS is unsupported.** No TSA reachable today serves it; adding it
   is one registry row plus `rsa`'s `pss` path.
5. **SHA-1 is in the WASM verifier's graph.** Confined by §3.4's reasoning and
   A30's lane rule; its only caller is the ESSCertID binding.
6. **`MAX_CHAIN_CERTS = 8` could be tight** for a future qualified-TSA chain.
   F4 makes raising it free; the reachability argument in §6 b2 is why it is
   not simply 18.

---

## 9. Corrections to hand back

These are defects in existing prose that this decision found. The
orchestrator amends them at source; they are not edits made here.

1. **`tasks/A.md` A8 `Do`** — *"Signature algorithms: RSA PKCS#1 v1.5
   (SHA-256/384/512) and ECDSA P-384."* Under-specified in three ways that
   would each fail an Accept row: the ECDSA **digest** is unpinned and the
   real FreeTSA token is `ecdsa-with-SHA512`, not the SHA-384 the pairing
   suggests; bare `rsaEncryption` in `SignerInfo.signatureAlgorithm` is not
   mentioned and five of nine real TSAs use it, DigiCert included; and SHA-1
   is not named as rejected although a real TSA (Apple) serves it. Replace
   with a reference to D60 §3.3.
2. **`tasks/A.md` A8 `Do`** — *"the TSA cert's EKU extension must be present,
   critical, and contain `id-kp-timeStamping`"*. True of the **signer**
   certificate only. DigiCert's intermediate carries a non-critical EKU, so a
   rule applied to CA certificates rejects DigiCert. Add "signer certificate".
3. **`tasks/A.md` A9 `Do`** — *"per-link signature verification (RSA + ECDSA
   P-384) …"*. The FreeTSA chain's links are `sha512WithRSAEncryption`, and
   GlobalSign's/DigiCert's include `sha384WithRSAEncryption`; A9 needs RSA
   with all three SHA-2 digests even for the "ECDSA" TSA. Also add: a pinned
   root's own self-signature is never verified (§3.2.8).
4. **`tasks/A.md` A9 `Do`** — *"BasicConstraints and KeyUsage checks"*.
   SwissSign's signer certificate has no BasicConstraints extension at all;
   the requirement is `cA = TRUE` on every **CA** in the path, and absence on
   the signer is legal (RFC 5280 §4.2.1.9).
5. **`tasks/A.md` A-OD8** — the nominee list `der`, `cms`, `x509-cert`,
   `rsa`, `p384` is **incomplete**: `sha1` and `const-oid` are required, and
   `sha2` needs a feature change. It also does not say that both `cms` and
   `rsa` are disqualified at their stable lines.
6. **`tasks/A.md` A25 `Do`** — the bootstrap note says *"one TSA response per
   default endpoint"*. Nine were captured, and the seven non-default ones are
   what produced findings 1–9 of §3.2. Worth widening so a re-run does not
   narrow the corpus.
7. **`docs/format/anchor-artifact-limits.md` §4** — the row *"A5 | max
   per-certificate size | RFC 5280 sets no ceiling; real DigiCert/FreeTSA
   certs set the scale"* is right that it is open, but the *reason* is
   sharper than stated and worth recording: the certificates A9 validates come
   out of the **token** (bounded only by `MAX_TSA_TOKEN_BYTES`), not out of
   the bundle's `intermediates` field, so `MAX_CERT_BYTES` does not already
   bound them. Without that sentence a reader concludes the limit is a
   duplicate and drops it.
8. **`docs/testing/error-code-contract.md` §2** — the prefix table has no
   `anchor-` row, so A has no registered namespace. → Q72.
9. `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.
