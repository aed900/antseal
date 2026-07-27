# D7 — Deterministic-CBOR crate: `minicbor = "=2.3.0"`

- **Status: RESOLVED** (P10/F1 joint decision; pin landed in the same change
  set, decision recorded first)
- **Date: 2026-07-27**

## Context

Every hashed, signed, stored, or paid-for byte of the antseal formats flows
through the deterministic-CBOR codec (MVP-SPEC.md line 73): RFC 8949 §4.2.1
Core Deterministic Encoding on emit, and a decoder that MUST hard-reject
every non-canonical input class — duplicate map keys, non-shortest int
encodings, non-shortest length encodings, indefinite-length items,
out-of-order keys, unknown/extra keys in fixed schemas, floats/out-of-schema
simples, trailing bytes. The crate must build for `wasm32-unknown-unknown`
with no I/O and no non-determinism, expose header/probe APIs sufficient for
the strict layer (F3), and be compatible with F11's allocation caps. The
registry (F4) uses only unsigned-integer map keys, so bytewise key order ==
ascending numeric order.

Candidates evaluated: `minicbor` (spec candidate, line 73), `ciborium`,
`cbor4ii`. `serde_cbor` was excluded up front: **RUSTSEC-2021-0127**
(unmaintained since 2021-08) plus RUSTSEC-2019-0025 (OSV, 18:16Z).

## Method

Evidence, not memory: throwaway prototype crates (outside the repo), one per
candidate at an exact pinned version, running real test snippets for each
profile requirement, plus reading the pinned versions' actual source in the
cargo registry. All runtime outputs below were produced 2026-07-27 on
toolchain 1.92.0 (edition 2024 workspace); each candidate was also built for
`wasm32-unknown-unknown` in isolation. The repo copy of the minicbor
evidence lives on as `crates/antseal-core/tests/cbor_pin_eval.rs` so the
verdict stays live in CI.

## Candidates matrix vs the line-73 profile

Versions: minicbor **2.3.0** (2026-07-23), ciborium **0.2.2** (2024-01-24),
cbor4ii **1.2.2** (2025-11-30) — crates.io API, 18:10Z. "F3-wrapper" means
the crate exposes probe surfaces on which our strict layer implements the
rejection; "no hook" means the crate normalizes silently with no public API
to detect the offense.

| Requirement | minicbor 2.3.0 | ciborium 0.2.2 | cbor4ii 1.2.2 |
| --- | --- | --- | --- |
| Shortest-form int heads (encode), tested at 0/23/24/255/256/65535/65536/2^32−1/2^32/u64::MAX | **PASS** — byte-exact; source is literally the §4.2.1 range match (`encode/encoder.rs::u64`) | PASS — byte-exact | PASS — byte-exact |
| Shortest-form length heads + definite lengths (encode) | **PASS** — bstr 23/24 boundary heads `0x57`/`0x58 0x18`; `map(n)`/`array(n)` always definite; indefinite exists only as separate `begin_*` calls F2 never exposes | PASS (Value layer) | PASS — `types::Map`/`types::Bytes` definite; `unbounded` variants separate |
| Caller-controlled map-key order | **PASS** — `Encoder` emits keys verbatim in call order (proven both sorted and deliberately unsorted) | PASS — `Value::Map` is an order-preserving `Vec` of pairs | PASS — `types::Map(&[(K,V)])` verbatim |
| Reject non-shortest **int** encodings | **F3-wrapper on native probes**: `input()` + `position()` give the raw head byte (`0x18` for `18 05`) and the consumed width (2 bytes for value 5) | **NO HOOK** — `from_reader(18 05)` = 5, silently; no public probe/offset API on the `ciborium` crate | no public head/width API; only recoverable by writing our own `Read` impl and re-deriving widths — the probe layer would be ours from raw bytes |
| Reject non-shortest **length** encodings | **F3-wrapper on native probes**: `59 00 01 AA` → head byte `0x59`, consumed 4 vs canonical 2 | **NO HOOK** — silently normalized (proven) | same caller-rebuilt situation |
| Reject indefinite-length items | **F3-wrapper on native classification**: `datatype()` returns distinct `BytesIndef`/`StringIndef`/`ArrayIndef`/`MapIndef` *before* consumption; `map()`/`array()` return `None` (second hook) | **NO HOOK** — indefinite array/map decode to values indistinguishable from definite (proven) | PARTIAL — `types::Array/Map::len()` → `None` for arrays/maps, but indefinite byte/text strings are auto-joined by the typed decoders (`dec.rs::decode_bytes`, segment loop); `if_major(0xbf) == if_major(0xa1)` — no indefiniteness classification |
| Reject duplicate keys | **F3-wrapper**: sequential key reads (`map()` + per-entry decode) feed strict-ascent enforcement | Value layer retains both entries (post-hoc detectable), serde-derive path resolves them invisibly; no streaming surface | possible over caller-built reader |
| Reject out-of-order keys | **F3-wrapper**: same sequential reads, strict ascent (distinct variant from duplicate) | same Value-layer-only situation | possible over caller-built reader |
| Reject unknown/extra keys in fixed schemas | **schema-layer (F5/F8) over the same sequential key reads** — explicit per-key dispatch sees every key | Value layer sees all keys; the serde-derive path needs `deny_unknown_fields` and still cannot see the other offenses | possible over caller-built reader |
| Reject floats / out-of-schema simples | **F3-wrapper on native classification**: distinct `Type::F16/F32/F64/Bool/Null/Undefined/Simple`; float *decoding* is not even compiled in without the opt-in `half` feature | floats are first-class and mandatory: `1.5f64` auto-shrinks to f16 (`f9 3e 00`); `half` is a required dep | float Encode impls present; no decode-side classification |
| Invalid UTF-8 in tstr (F3 taxonomy) | **NATIVE** — `str()` returns a UTF-8 error and refuses indefinite text (source + test) | errors via serde `String` decode | checked path errors (`RequireUtf8`, source-read); `UncheckedStr` escape hatch exists |
| Reject trailing bytes | **F3-wrapper**: `position() < input().len()` after top-level item | **NO HOOK** — `from_reader([01 02 03])` = 1, trailing `02 03` silently ignored (proven) | detectable only because the position-tracking `Read` is ours |
| `wasm32-unknown-unknown` build, no I/O | **PASS** — `no_std` by default, zero deps with `alloc` | PASS (builds) | PASS — `no_std`, zero deps with `use_alloc` |
| F11 allocation-cap compatibility | **PASS** — zero-copy `&[u8]` decode; bstr claiming u64::MAX length on 9-byte input → `Err(EndOfInput)` with no allocation possible by construction (proven) | `Value` tree allocates per input; no zero-copy surface | typed decode pre-reserves `min(len, 256)` (source-read); strict layer would bypass |
| Malformed input → `Err`, never panic | **PASS** — bad heads, truncations, empty input all return typed errors (proven) | n/a to verdict | n/a to verdict |
| Normal-dep footprint | **zero** transitive deps | `ciborium-io` + `ciborium-ll` + `half` + `zerocopy` + `serde`(+derive) + 3 proc-macro crates | zero transitive deps |
| Maintenance (crates.io, 18:10Z) | active: 2.3.0 (2026-07-23), 2.2.3 (2026-07-20), 2.2.2 (2026-05-17), steady cadence | **dormant since 2024-01-24** | active: 1.2.2 (2025-11-30), several 2025 releases |
| RUSTSEC/OSV (18:16Z) | none | none | none |
| License | **BlueOak-1.0.0** (permissive, uncommon — consequence below) | Apache-2.0 | MIT |
| MSRV / edition vs toolchain 1.92.0 | edition 2024, no declared `rust-version`; compiles clean on 1.92.0 (proven) | declared 1.58 | compiles clean on 1.92.0 (proven) |

## Per-candidate verdicts

- **minicbor 2.3.0 — WINNER.** Only candidate whose *public* decoder surface
  (`Decoder::input()/position()/datatype()/probe()`, `map()/array()` →
  `Option<u64>`) natively carries every signal F3's strict layer needs;
  encoder is shortest-form by construction (source-verified); zero deps;
  `no_std`; active weekly-to-monthly maintenance; integer-keyed maps are its
  signature design.
- **ciborium 0.2.2 — REJECTED.** Four of the mandatory rejection classes
  (non-shortest ints, non-shortest lengths, indefinite items, trailing
  bytes) are *unimplementable*: the serde surface normalizes silently and
  exposes no probe/offset API. The low-level `Header` type (in the separate
  `ciborium-ll` crate) erases encoded widths (`Header::Positive(u64)`) and
  bakes floats in. Dormant 2.5 years; mandatory `half` float dep in a
  no-float profile.
- **cbor4ii 1.2.2 — REJECTED (runner-up).** Encoder is fully conformant and
  dep-free, but the decode side offers no head classification (`peek_one` is
  `pub(crate)`; public helpers are raw-byte `if_major/high/low`), silently
  normalizes non-shortest forms, and auto-joins indefinite byte/text-string
  segments. A strict layer would have to re-implement header parsing from
  raw bytes over a caller-built `Read` — that is the in-house-codec
  contingency wearing a dependency, with none of minicbor's probe surface.
- **serde_cbor 0.11.2 — EXCLUDED** (RUSTSEC-2021-0127 unmaintained;
  RUSTSEC-2019-0025).

## Decision

1. **Pin `minicbor = "=2.3.0"`** in `[workspace.dependencies]`, features
   `["alloc"]` only (no `std`, no `derive`, no `half` — minicbor 2.3.0 has
   no default features; verified in its manifest). `antseal-core` consumes
   it via `minicbor.workspace = true` as its only CBOR crate (F1 accept:
   no second CBOR crate ever enters `antseal-core`'s dependency tree; the
   independent implementation below is dev-tool-only).
2. **Version choice**: 2.3.0 is 4 days old at decision time; delta from the
   well-aged 2.2.2 (2026-05-17) is additive only — u128/i128 support
   (2.3.0) and `no_std` widening of IP/SocketAddr impls + derive bump
   (2.2.3) (upstream CHANGELOG.md, 18:22Z). Nothing touches the u8–u64
   head paths, length heads, or decoder probes we rely on, and all evidence
   tests ran against 2.3.0 itself, so we pin the evaluated version rather
   than an unevaluated older one. Bumps follow dependency-policy §4.
3. **Strictness architecture (F sign-off)**: minicbor's own decoder is
   deliberately lenient (Postel — `18 05` decodes to 5). **Every line-73
   rejection rule is implementable on this crate**, split as the F tasks
   already anticipate: the seven canonicality classes owned by F3 —
   duplicate keys, non-shortest ints, non-shortest lengths, indefinite
   items, out-of-order keys, floats/out-of-schema simples, trailing bytes —
   are F3 wrapper logic over native probe surfaces (raw head bytes via
   `input()`/`position()`, consumed-width deltas via `position()`,
   pre-consumption classification via `datatype()` with distinct
   indefinite/float/simple variants, `map()`/`array()`
   `None`-for-indefinite, sequential key reads for strict-ascent with
   duplicate and disorder as two distinct variants); the eighth line-73
   class, unknown/extra keys in fixed schemas, is a schema-layer check
   (F5/F8) over the same sequential reads; and F3's invalid-UTF-8-in-tstr
   class is the one rejection the crate performs natively (`str()` also
   refuses indefinite text outright). Every class was demonstrated
   detectable in the evidence tests; none requires forking or patching the
   crate.
4. **Derive macros are NOT used for wire formats** (F1 Notes, recorded):
   `minicbor-derive` expresses integer keys (`#[n(i)]`) but derived
   `Decode` is lenient by design (skips unknown fields, ignores order,
   last-wins duplicates) and derived `Encode` cannot express the
   embedded-`body`-bstr envelope (signatures over exact received bytes,
   verifiers never re-encode). **F5–F9 use manual `Encode`/`Decode`-style
   impls layered on F2/F3.** The `derive` feature stays off;
   `minicbor-derive` stays out of the graph.

## In-house-codec contingency (trigger)

F1 names the fallback: a small canonical CBOR reader/writer inside
`antseal_core::codec`. It activates if, and only if, one of:

- a **deliberate** pin bump (policy §4) finds the probe surface
  (`input`/`position`/`datatype`/`map`/`array` semantics) or the
  shortest-form encoder guarantees changed such that
  `crates/antseal-core/tests/cbor_pin_eval.rs` cannot be kept green
  unmodified, and no compatible minicbor version exists;
- F3's tamper matrix cannot produce a distinct error for some line-73
  rejection class on the pinned crate (discovered during F3, before the M0
  Definitions freeze); or
- a RUSTSEC advisory lands against the pinned version whose fix requires an
  incompatible version (assessed per policy §4).

The strict layer's public API (F2/F3) must not leak minicbor types, so the
swap stays behind `antseal_core::codec` either way.

## D12 nomination — independent cross-check implementation

**Python `cbor2`, exact pin `==6.1.3`** (PyPI, released 2026-07-04, MIT,
requires Python ≥3.10; metadata 18:18Z) — dev-tool-only, consumed by the
F14/Q11 golden-vector cross-check; it never enters any Rust dependency
tree. Justification:

- **Independent lineage**: agronholm/cbor2, C-accelerated Python with a
  pure-Python fallback — different language, author, and codebase from
  minicbor; a shared implementation bug is implausible rather than merely
  unlikely (a second *Rust* crate would share ecosystem idioms and the
  temptation to compare against the same reference code).
- **Proven byte-compatible** (18:27Z, cbor2 6.1.3 wheel): reproduces
  minicbor's exact bytes for all integer boundaries (0…u64::MAX), the
  24-byte bstr length head, and the sorted uint-key map
  `{1:0,2:0,10:0,24:0}` → `a4010002000a00181800`; structural decode of
  minicbor output matches.
- **Ordering caveat, recorded for F14**: `cbor2`'s `canonical=True` uses
  length-first key ordering (RFC 7049 §3.9), not RFC 8949 bytewise. Over
  the registry's unsigned-int-only keys the two orders coincide (shorter
  shortest-form uint encodings sort first in both; F2 asserts this
  equivalence per its accept criteria), and F14's checker additionally
  validates canonicality (shortest forms, sorted keys, definite lengths)
  with its own explicit logic over our bytes rather than trusting either
  library's notion of "canonical".

D12 itself (the cross-check *vehicle and wiring*) is closed by F14/Q11;
this record supplies its named, pinned implementation.

## Consequences

- **P13/Q29 (deny.toml)**: BlueOak-1.0.0 needs an explicit license
  allowlist entry (pre-flagged in D6's housekeeping note).
- **F2/F3**: implement the canonical encode layer and strict decode layer
  on this pin; `cbor_pin_eval.rs` is the pin-evaluation evidence, *not* the
  codec — it must stay green and unmodified across any future bump, or the
  contingency question is opened.
- **F14**: install `cbor2==6.1.3` exact-pinned wherever the checker runs
  (dependency-policy §5 dev-tool rule).
- **dependency-policy.md**: exact-pin table row updated from "candidate"
  to the landed pin; `cbor2` added to the §5 dev-tool list.
- **Format identifier strings** (P10 note): F consumes the crate name
  decision before the M0 Definitions freeze — no format string embeds the
  crate name; the profile is defined by RFC 8949 §4.2.1 + line 73, so a
  future codec swap is invisible on the wire.

## Evidence log (2026-07-27)

- crates.io API: minicbor/ciborium/cbor4ii/serde_cbor/minicbor-derive
  version + license + date metadata (18:10Z).
- OSV API: advisory queries for all candidates plus `half` (18:16Z).
- Upstream CHANGELOG.md (twittner/minicbor, 18:22Z): 2.2.2→2.3.0 delta.
- Pinned-source reads (cargo registry): minicbor
  `encode/encoder.rs::u64` (shortest-form match), `decode/decoder.rs`
  (`input`/`position`/`datatype`/`type_of`, lenient int decode); cbor4ii
  `core/dec.rs` (`peek_one` pub(crate), `decode_bytes` segment auto-join,
  `min(len, 256)` reserve); ciborium-ll `hdr.rs` (`Header::Positive(u64)`
  width erasure).
- Prototype runs (18:13Z–18:25Z): 11 minicbor, 8 ciborium, 6 cbor4ii
  evidence tests, all passing with the behaviors tabulated above; three
  isolated `wasm32-unknown-unknown` builds OK; cbor2 6.1.3 byte-compare
  script output as quoted.
