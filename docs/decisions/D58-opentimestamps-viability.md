# D58 — `opentimestamps` 0.2.0 viability on stable + wasm32

- **Status: RESOLVED — the crate is NOT adopted, in any form: not pinned,
  not wrapped, not vendored. `antseal-core` gets an in-house `.ots` codec
  over the already-pinned `sha2 =0.11.0` and **zero** new dependencies.
  The register's framing is overturned twice. First on its premise: the
  crate *does* compile, cleanly, on `=1.92.0` and on
  `wasm32-unknown-unknown` (`cargo check` and full `cargo build` codegen,
  both green), so the one question P18 and A11's Notes told the implementer
  to ask is the one question that does not decide anything. Second on its
  contingency: "vendoring/forking the codec" is not a cheaper fallback than
  writing it, because the crate is **edition 2015** and every line that
  would need to change is a line. What decides it is measured behaviour —
  an **80-byte** `.ots` drives an uncatchable `SIGABRT` out of
  `vec![0; attacker_varint]`, a **102-byte** `.ots` drives a second one out
  of an unbounded hexlify chain, an **87-byte** `.ots` panics in debug and
  *parses to a different answer* in release, and a **90-byte** `.ots` makes
  this crate and the reference implementation report **different attestation
  sets from identical bytes**. None of it is wrappable: `from_reader` fuses
  parse, op execution and recursion into one call, so every limit A11 is
  required to enforce can only be enforced by a pre-scanner that is itself
  the parser. Seven limits are set here with their F4 rows.**
- **Date: 2026-08-02** (M2 planning round; register `TODO.md:570`)
- **Owning task: A11**, with **P18** retired and **A13/A14/A12** consuming
  the format findings in §7
- **Blocks: A11, P18; consumed by A12, A13, A14, A18, A23, A28**

## Context

The register entry is one line (`TODO.md:570`):

> **D58** `opentimestamps` 0.2.0 viability on stable + wasm32; vendor/fork
> fallback (A11/P18 — "A-OD6")

`tasks/A.md`'s A11 Notes expand it:

> `opentimestamps` 0.2.0 is from 2023 and dormant — verify at execution
> time that it compiles on current stable and wasm32; vendoring/forking the
> codec is the contingency (A-OD6).

and `tasks/P.md`'s P18 `Do` makes the same test the gate:

> verify at execution that 0.2.0 compiles for wasm32-unknown-unknown
> without I/O/rand baggage; if it fails, escalate to A/F for an in-house
> `.ots` codec decision.

MVP-SPEC.md line 108 records the crate's *scope* correctly — "a codec only;
the calendar HTTP client … is committed in-house M2 work … reusing the crate
solely as the wire-format layer" — and that sentence survives unchanged as a
statement about the calendar client. What does not survive is the assumption
underneath it: that the wire-format layer is a thing we can reuse.

**Both the register's question and the register's contingency are wrong.**
The question is wrong because compilation passes and proves nothing about
the property A11 needs. The contingency is wrong because "vendor/fork" and
"write it" are the same amount of work here, and only one of them leaves
us owning the result. Everything below is a command that was run.

Environment for every measurement in this document: `rustc 1.92.0
(ded5c06cf 2025-12-08)`, `cargo 1.92.0`, targets `x86_64-unknown-linux-gnu`
and `wasm32-unknown-unknown` installed, probe crate under the session
scratchpad (never in the workspace), 2026-08-02.

## 1. The compile question, answered — and why it decides nothing

A throwaway `edition = "2024"` crate with `opentimestamps = "=0.2.0"` as its
only dependency:

| command | result |
| --- | --- |
| `cargo check --locked` | **PASS**, `Finished dev profile … in 10.87s` |
| `cargo check --locked --target wasm32-unknown-unknown` | **PASS**, `… in 8.08s` |
| `cargo build --locked --lib --target wasm32-unknown-unknown` | **PASS**, `… in 8.13s`, `libd58probe.rlib` 4 022 B |
| `cargo build --locked --release` | **PASS**, `… in 19.81s` |
| `grep -rn unsafe src/` | **no matches** |
| `license` field | `MIT OR Apache-2.0` |

The full wasm32 run is `build`, not only `check`, so this is real codegen for
the target and not a type-check. `env_logger`, `is-terminal`, `libc`,
`regex` and `termcolor` all compiled for `wasm32-unknown-unknown` without a
cfg escape hatch, which is the specific outcome P18 expected to fail.

So the recorded answer to P18's Accept row is: **wasm32 compile check
performed, PASSED.** It is recorded here rather than as a pin, because the
crate is not adopted for reasons that a compiler cannot see.

## 2. The dependency closure

`cargo tree` on the probe crate:

```
d58probe v0.1.0
└── opentimestamps v0.2.0
    ├── bitcoin_hashes v0.12.0
    │   └── bitcoin-private v0.1.0
    ├── env_logger v0.10.2
    │   ├── humantime v2.4.0
    │   ├── is-terminal v0.4.17
    │   │   └── libc v0.2.189
    │   ├── log v0.4.33
    │   ├── regex v1.13.1
    │   │   ├── aho-corasick v1.1.4
    │   │   │   └── memchr v2.8.3
    │   │   ├── memchr v2.8.3
    │   │   ├── regex-automata v0.4.16
    │   │   │   ├── aho-corasick v1.1.4 (*)
    │   │   │   ├── memchr v2.8.3
    │   │   │   └── regex-syntax v0.8.11
    │   │   └── regex-syntax v0.8.11
    │   └── termcolor v1.4.1
    └── log v0.4.33
```

**Fourteen packages, of which thirteen are new to `antseal-core`.** Measured
against the current graph (`cargo tree -p antseal-core -e normal --prefix
none --locked`, de-duplicated): **56** packages today, **80** with
`--all-features`. Only `memchr v2.8.3` is already present, and at the same
version, so the delta is **+13 on both** — *derived*: 56 + 13 = **69**
default, 80 + 13 = **93** heavy. (Derived rather than measured because
landing the edge to measure it is an implementation act, not a planning one;
the arithmetic is exact because the intersection was checked name by name.)

Four observations, in descending order of how much they matter.

**(a) `env_logger` is a non-optional dependency of a codec.** It is declared
in the crate's `Cargo.toml` with no `optional = true` and no feature gate:

```toml
[dependencies.env_logger]
version = "0.10"
```

It exists only for the crate's `ots-info` binary, but Cargo does not care —
every library consumer gets it. That drags an environment-variable reader, a
stderr writer, `is-terminal`, `libc` and a regex engine into the crate that
MVP-SPEC.md lines 47–53 require to be I/O-free and that ships as the
verifier page's WASM. It is not merely inelegant: it is the exact property
the `core-dep-graph` lane exists to defend.

**(b) The `core-dep-graph` lane would NOT have caught it.** `scripts/ci-lanes.sh`,
`lane_dep_graph`:

```sh
local forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) '
```

`env_logger`, `libc`, `is-terminal`, `regex` and `termcolor` are on none of
those lines. A lane whose stated job is "antseal-core's NORMAL dependency
graph must be I/O-free" would have gone green on a graph containing a
logger that reads `RUST_LOG` and writes to a terminal. **That is a hole in a
live guard, independent of this decision** — it is written up as **Q74** in
§12.

**(c) `bitcoin_hashes 0.12.0` is a second SHA-256.** It is not a `cargo
tree` duplicate — it does not depend on RustCrypto at all; it carries its
own `sha1`, `sha256` and `ripemd160` implementations, and `Op::execute`
calls them (`op.rs:24`, `op.rs:100-107`). So it does not trip
`multiple-versions`, and it is worse than a version duplicate: it is a
second independent implementation of the one primitive MVP-SPEC.md line 100
makes the whole product's binding rest on ("standard-model SHA-256
collision-resistance … the permanent sealer-equivocation bound"), compiled
into the same verifier, reachable from adversary-controlled bytes.
`bitcoin_hashes` 0.12 is also pre-1.0 and three minor generations behind.

**(d) The advisory sweep is clean, and says so plainly.** Both halves of
the D19-mandated sweep were run over all fourteen packages:

- **osv.dev**, `POST https://api.osv.dev/v1/query` per package, retrieved
  **2026-08-02T19:30:23Z**: every one of the fourteen returned `{}`.
- **RUSTSEC via `cargo-deny 0.19.8`** (the pinned tool version) with the
  project's own config, `cargo deny check --config …/deny.toml advisories
  bans`: **`advisories ok, bans ok`**. The four `advisory-not-detected`
  warnings are pre-existing `[advisories].ignore` rows for the ant-core
  graph, absent from this probe graph by construction.
- Licence `MIT OR Apache-2.0` — permissive, and inside the allowlist Q29
  will write (`deny.toml`'s licences check is stubbed until then, so no
  check would have fired either way).

**No advisory, no licence problem, no `unsafe`, no yank.** This is stated
because it removes the easy reason to reject and forces the decision onto
measured behaviour, which is where it belongs — and where it is decisive.

## 3. What the API actually does, and the four ways it crashes

Read from source at
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/opentimestamps-0.2.0/src/`,
not from docs.rs prose. The crate's library is **7 files, 1 040 lines**
(`wc -l`): `ser.rs` 304, `timestamp.rs` 200, `op.rs` 142, `attestation.rs`
128, `lib.rs` 132 (90 of them embedded test constants), `error.rs` 86,
`hex.rs` 48 — plus a 57-line `ots-info` binary.

The good news first, because it is real: `DetachedTimestampFile::from_reader`
**does** execute the op DAG. `Timestamp::deserialize_step_recurse`
(`timestamp.rs:60-116`) calls `op.execute(&input_digest)` at line 105 and
stores the result in `Step::output`, so a parsed tree carries the derived
value at every node, including at each attestation. It is not a parse tree.
And on honest input it round-trips: all eight real fixtures below
re-serialised **byte-identically**.

Everything else is a defect.

### 3.1 Uncatchable abort from an 80-byte file (unbounded allocation)

`attestation.rs:63-95`:

```rust
let tag = deser.read_fixed_bytes(TAG_SIZE)?;
let len = deser.read_uint()?;
if tag == BITCOIN_TAG { … } else if tag == PENDING_TAG { … } else {
    Ok(Attestation::Unknown { tag, data: deser.read_fixed_bytes(len)? })
}
```

and `ser.rs:205-209`:

```rust
pub fn read_fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
    let mut ret = vec![0; n];          // allocate first, read second
    self.reader.read_exact(&mut ret)?;
```

`len` is an attacker-chosen varint with **no cap**, and the `Vec` is
allocated before a byte is read. Reproduced with an 80-byte `.ots`
carrying an 8-byte unknown tag and the length varint
`ff ff ff ff ff 0f`:

```
input is 80 bytes
memory allocation of 549755813887 bytes failed
Aborted     exit=134
```

**Exit 134 is `SIGABRT`, not a panic.** It is `handle_alloc_error`, which
does not unwind; `catch_unwind` cannot intercept it, and in WASM it is a
module trap. Identical in debug and release. This is precisely the path
A11's `Do` requires to be safe: *"Unknown ops/attestation types surface as
typed unverifiable results, never crashes."* The crate crashes, on the
input that names the requirement.

For scale: the reference implementation caps this at `MAX_PAYLOAD_SIZE =
8192` (§4).

### 3.2 Uncatchable abort from a 102-byte file (unbounded op output)

`op.rs:30` caps the *operand* of append/prepend at `MAX_OP_LENGTH = 4096`.
Nothing caps the **running value**. `Op::Hexlify` (`op.rs:108-110`) doubles
it, with no operand at all — so `0xf3` repeated is a doubling chain from a
32-byte digest:

| hexlify ops | file size | outcome under a 2 GiB address-space cap |
| --- | --- | --- |
| 20 | 98 B | parses (32 MiB allocated) |
| **24** | **102 B** | **`Aborted`, exit 134** — `memory allocation of 536870912 bytes failed` |
| 36 | 114 B | `Aborted`, exit 134 — asks for 32·2³⁶ = 2 TiB |

`32 · 2²⁴ = 536 870 912`, exactly the failed allocation, so the mechanism is
confirmed and not inferred. On a machine without the `ulimit` the ceiling is
RAM; on wasm32 it is `memory.grow` failing, which is a trap.

### 3.3 A build-profile-dependent verdict from an 87-byte file

`ser.rs:186-202`:

```rust
pub fn read_uint(&mut self) -> Result<usize, Error> {
    let mut ret = 0; let mut shift = 0;
    loop {
        let byte = self.read_byte()?;
        ret |= ((byte & 0x7f) as usize) << shift;   // ser.rs:193
        if byte & 0x80 == 0 { break; }
        shift += 7;                                  // unbounded
    }
```

`shift` has no bound. Thirteen continuation bytes take it past 63. Same
87-byte input, two profiles:

```
--debug--
thread 'main' panicked at …/opentimestamps-0.2.0/src/ser.rs:193:20:
attempt to shift left with overflow                      exit=101

--release--
  round-trip: DIFFERS
   in : …00deadbeefdeadbeef80808080808080808080808000
   out: …00deadbeefdeadbeef00
```

In release the shift is masked, the length silently becomes `0`, the file
**parses successfully** as an unknown attestation with an empty payload, and
re-serialises to different bytes. So the same `.sealproof` yields *the
verifier crashed* from a debug or test build and *valid artifact, one
unknown attestation* from the shipped release build.

`crates/antseal-core/src/codec/caps.rs` states the standard this violates in
its own words — "a per-verifier cap knob would let the CLI and the WASM page
disagree on whether a bundle is valid, which is precisely the divergence
line 73 exists to prevent". A build profile is a worse knob than a
configuration flag, because nobody thinks of it as one.

### 3.4 The serializer panics on hand-built trees — which A13 must build

Every field of `Timestamp`, `Step` and `StepData` is `pub`; there is no
constructor and no validation. A13 must build these by hand, because
merging calendars is the one thing the crate does not do. Two one-line
mistakes, both reproduced:

```
about to serialize an Op step with next=[]
panicked at …/src/timestamp.rs:139:66: index out of bounds: the len is 0 but the index is 0

about to serialize a Fork step with next=[]
panicked at …/src/timestamp.rs:131:29: attempt to subtract with overflow
```

`timestamp.rs:131` is `for i in 0..step.next.len() - 1` on a `usize`.
`fmt_recurse` (`timestamp.rs:185`) has the same `next[0]`, so `Display`
panics too. Deserialisation cannot produce these shapes; A13's merge code
can, and a panic in `antseal seal` is a failed seal after payment.

### 3.5 What is *not* wrong

Stated so the ruling is not read as a hatchet job:

- No `unsafe` anywhere.
- Recursion **is** bounded — `RECURSION_LIMIT = 256` (`timestamp.rs:25`),
  confirmed empirically: a 255-op chain parses, a 256-op chain returns
  `Error::StackOverflow`. That is a real defence and better than most
  2023-era parsers.
- Pending-URI length is capped (`MAX_URI_LEN = 1000`) and its charset is
  validated.
- Round-trip fidelity on honest input is exact.

Two riders on the recursion bound, because it is not as safe as it looks.
First, it is native stack recursion, and the frame cost was measured by
parsing a 255-op chain on threads of decreasing stack size:

| profile | 255-op chain parses at | fails at |
| --- | --- | --- |
| release | 163 840 B | 147 456 B |
| debug | 1 048 576 B | 786 432 B |

`wasm-ld`'s documented default `-z stack-size` is **1 048 576**. *That
default is the one number in this document not produced by a command here* —
no `wasm-ld` is on this machine's PATH and `rust-lld -flavor wasm --help`
does not print it, so it is cited from documentation and the implementer
should re-confirm it against whatever `wasm-pack` actually links with.
Taking it as 1 MiB: a release WASM build clears the measured requirement by
~6.4×; a **debug** WASM build sits exactly on the line, and a wasm stack
overflow is a trap, not an `Error::StackOverflow`. Second — and
this is the part that would outlive the crate — under F4 a limit is
**raise-only forever**. Pinning the crate would make **255 the permanent
ceiling on `.ots` op depth**, chosen in 2023 by someone bounding their own
stack, not by anyone reasoning about Bitcoin merkle depth.

## 4. The parser differential: two implementations, identical bytes, different attestations

This is the finding that would matter even if the crashes were all fixed.

`opentimestamps` 0.2.0 reads the attestation payload length and then
**ignores it** for every tag it recognises (`attestation.rs:63-95`, quoted in
§3.1): it reads `len`, then parses the Bitcoin height or the pending URI
from the *outer* stream, and never checks that `len` bytes were consumed.

The reference implementation does the opposite. `python-opentimestamps`,
`opentimestamps/core/notary.py`, `TimeAttestation.deserialize` (retrieved
**2026-08-02T19:31Z**):

```python
tag = ctx.read_bytes(cls.TAG_SIZE)
serialized_attestation = ctx.read_varbytes(cls.MAX_PAYLOAD_SIZE)
payload_ctx = opentimestamps.core.serialize.BytesDeserializationContext(serialized_attestation)
# ... attestation type dispatch ...
payload_ctx.assert_eof()
```

with `MAX_PAYLOAD_SIZE = 8192`. Three differences: a **sub-context** limited
to the declared payload, a **cap**, and an **`assert_eof`**. The Rust crate
has none of the three.

Consequence, demonstrated on a 90-byte `.ots` in which a Bitcoin attestation
declares a 9-byte payload and writes 1:

| parser | verdict |
| --- | --- |
| `opentimestamps` 0.2.0 | parses cleanly, **2 attestations**: `bitcoin(height=1)` **and** `pending(uri="ab")` |
| length-respecting parser (python semantics) | **1 attestation**: `bitcoin`, 9-byte payload — then runs off the end of the input into garbage ops |

Same bytes. Different attestation sets. The sealer authors the `.ots`, it is
embedded in a `.sealproof`, and the counterparty may verify with the CLI, the
WASM page, or the OTS project's own tooling. A sealer who can show one
attestation to one verifier and a different one to another has a
capability antseal exists to deny. It is not hypothetical: it is 90 bytes.

A weaker instance of the same bug is visible even without an exploit — feed
the crate a Bitcoin attestation declaring `len = 1` around a 3-byte height
varint and it reports `height = 16384` and re-serialises with `len = 3`, so
its own round-trip is not byte-preserving on inputs a conformant parser
rejects outright.

## 5. Why a hardening wrapper cannot work

This is the structural argument, and it is what rules out the middle option
("pin it with a documented in-house hardening wrapper").

A11 must enforce five limits over `.ots` internals. Every one of them
describes a property of the *whole* artifact — op count, depth, branch
width, attestation count, operand length. The crate's entire API surface for
reading is:

```rust
pub fn from_reader<R: Read>(reader: R) -> Result<DetachedTimestampFile, Error>
```

One call. It parses, executes every op, allocates every intermediate value,
and recurses to full depth *before it returns anything*. There is no
callback, no visitor, no budget parameter, no streaming mode, no
parse-without-execute. By the time a wrapper can inspect the result:

- the 512 GiB allocation has already been attempted (§3.1) — and it aborted,
  so the wrapper never runs at all;
- the hexlify chain has already doubled twenty-four times (§3.2);
- the shift has already overflowed or been masked (§3.3);
- the length-differential attestation set is already the only one on offer
  (§4).

A wrapper could pre-scan the bytes before handing them over. To count ops it
must decode varints and op tags; to find attestations it must know where
each op's operand ends; to measure depth and width it must track `0xff` and
`0x00`. **That pre-scanner is the parser.** Having written it, the crate
supplies nothing that remains needed: SHA-256 comes from the pinned
`sha2 =0.11.0`, and the DAG walk is the pre-scanner's own.

So the honest set of options is two, not four: *ship a parser we wrote*, or
*ship two parsers, one of which we wrote and one of which aborts on 80
bytes*.

## 6. Why "vendor a subset" is a fiction here

The register's contingency assumes vendoring is cheaper than writing.
Measured against the source, it is not.

- The crate is **edition 2015**: its `Cargo.toml` has no `edition` key, and
  the source uses `extern crate bitcoin_hashes;`, `#[macro_use] extern crate
  log;` and crate-relative imports (`use error::Error;`, `use op::Op;`).
  None of that compiles inside an edition-2024 crate. Every module header
  and every intra-crate path changes.
- The I/O model is `std::io::Read`/`Write` throughout
  (`ser.rs:17-18`, `op.rs:22`, `attestation.rs:19`, `timestamp.rs:16`).
  `antseal-core` parses a `&[u8]` that is already in memory and already
  size-capped by `MAX_OTS_BYTES`; a `Read` cursor buys nothing and costs the
  `Error::Io` arm, which becomes an unreachable variant we would have to
  keep or delete.
- `Op::execute` calls `bitcoin_hashes`. Every call site changes to `sha2`,
  and the `sha1`/`ripemd160` arms have no home at all (§9.4).
- The four crash sites (§3.1–§3.4) and the length-differential (§4) are each
  a rewrite of the function containing them, and those five functions are
  most of the parsing logic.
- What is left is `MAGIC`, the tag constants, and the shape of the fork
  encoding — roughly 20 lines of constants, all of which are public
  protocol facts documented in §7, not authored expression.

Vendoring MIT-or-Apache-2.0 source also carries a real obligation
(`LICENSE` retention plus attribution in the derived files) and creates a
permanent "who tracks upstream" question for a repository whose last release
was 2023. Paying that for 20 lines of constants is a bad trade, and the
constants are not copyrightable protocol facts in the first place.

## 7. The `.ots` file format, established from the captured bytes

A13 has to write this file and A11 has to parse it, and the captures in
`testdata/anchors/A25-bootstrap/` are **calendar op-streams, not `.ots`
files**. This section closes that gap. Every claim was verified by
constructing the file and round-tripping it.

### 7.1 The container

```
<magic: 31 B> <version: varuint> <digest-type: 1 B> <digest: 32 B> <timestamp>
```

with `magic` = `00 "OpenTimestamps" 00 00 "Proof" 00 bf 89 e2 e8 84 e8 92 94`
(`ser.rs:25`), `version` = `1` (`ser.rs:28`), digest-type tag `0x08` =
SHA-256 (`ser.rs:99`). **Header total: 65 bytes.**

Field-labelled dump of the merged 3-calendar file built from the A25
captures for digest A:

```
   0  00                                     0x00 — magic byte 0
   1  4f70656e54696d657374616d7073           "OpenTimestamps"
  15  0000                                   0x00 0x00
  17  50726f6f66                             "Proof"
  22  00                                     0x00
  23  bf89e2e884e89294                       magic tail (magic total = 31 B)
  31  01                                     major version, varuint = 1
  32  08                                     digest type tag 0x08 = SHA256
  33  083f87df…abd69df                       start digest (32 B) = anchor_digest
  65  ff                                     0xff — FORK: another branch follows
  66  f008                                   0xf0 append, operand length 8
  68  62b08fafc9eaf1c8                         operand
  76  08                                     0x08 sha256
  77  f010                                   0xf0 append, operand length 16
  79  d61312af69c8178592521e533e7343aa         operand
  95  08                                     0x08 sha256
  96  f020                                   0xf0 append, operand length 32
  98  33d5cb7d…691c746c                        operand
 130  08                                     0x08 sha256
 131  f120                                   0xf1 prepend, operand length 32
 133  bd4cdda4…81bfc07d                        operand
 165  08                                     0x08 sha256
 166  f020                                   0xf0 append, operand length 32
 168  b7d136ba…cf3706d9                        operand
 200  08                                     0x08 sha256
 201  f104                                   0xf1 prepend, operand length 4
 203  6a6f9804                                 operand
 207  f008                                   0xf0 append, operand length 8
 209  ed69d89a4dab025f                         operand
 217  00                                     0x00 ATTESTATION
 218  83dfe30d2ef90c8e                       PENDING attestation tag
 226  2e                                     payload length varuint = 46
 227  2d                                       varbytes length = 45
 228  68747470733a2f2f616c696365…              uri = "https://alice.btc.calendar.opentimestamps.org"
      … branches 2 and 3 follow the same shape; file ends at byte 664.
```

Bytes 66–272 are `A-alice.timestamp` verbatim. The container is header +
`0xff` separators + the calendar responses unmodified.

### 7.2 The timestamp body

- `0x00` — attestation, terminates this path. Followed by an 8-byte type
  tag, a varuint payload length, and that many payload bytes.
  Pending tag `83 df e3 0d 2e f9 0c 8e`, payload = varbytes URI.
  Bitcoin tag `05 88 96 0d 73 d7 19 01`, payload = varuint block height.
- `0xff` — fork; **a `0xff` precedes every branch except the last**, so `N`
  branches cost `N-1` separator bytes. `ff A ff B C` is three branches.
- anything else — an op tag: `0x02` sha1, `0x03` ripemd160, `0x08` sha256,
  `0x67` keccak256, `0xf0` append, `0xf1` prepend, `0xf2` reverse,
  `0xf3` hexlify. Only `0xf0`/`0xf1` carry an operand (varuint length, then
  bytes). Ops execute in stream order on the running value.
- Varuints are little-endian base-128 with the high bit as the continuation
  flag.
- The file must end exactly at the end of the DAG; the crate reports
  `TrailingBytes` on one extra byte, and so must we.

### 7.3 Merging N calendars — the recipe A13 executes

```
header(anchor_digest) ‖ 0xff ‖ resp₁ ‖ 0xff ‖ resp₂ ‖ … ‖ 0xff ‖ resp_{N-1} ‖ resp_N
```

Verified: built for both committed golden-vector digests, parsed, and
re-serialised **byte-identically**, with all three pending attestations
recovered and each carrying its own derived commitment.

| merged file | size | ops | depth | forks | width | attestations |
| --- | --- | --- | --- | --- | --- | --- |
| digest A (`083f87df…69df`), 3 calendars | **664 B** | 34 (14 append, 14 sha256, 6 prepend) | 13 | 1 | 3 | 3 |
| digest B (`3448b9f2…5e9c`), 3 calendars | **629 B** | 32 (13 append, 13 sha256, 6 prepend) | 13 | 1 | 3 | 3 |

`664 = 65 (header) + 207 + 170 + 220 (responses) + 2 (separators)`.
Cross-checked with an independently written length-respecting scanner, which
consumed exactly 664/664 and 629/629 and agreed on every count.

**The merged pending `.ots` is 664 B against `MAX_OTS_BYTES = 1 048 576` —
1 579× headroom.** That is A28's input.

**The fixture this table measures does not exist on disk yet.** A11 must
commit the merged file as
`testdata/anchors/A25-bootstrap/merged-A.ots` (and `merged-B.ots`), built by
the recipe above from the already-committed captures — it is deterministic
from files in the tree, so it is reproducible rather than a new capture, and
§9.5's F4 rows and §11's tests both name that path. Without it three of the
§11 tests have nothing to read.

Two riders for A13:

- **Branch order is A13's to fix, not the format's.** The reference
  implementation sorts branches by their serialized op bytes; nothing in the
  container requires it and nothing in the crate would have done it. A13
  must impose a deterministic order (sort by the calendar's op-stream bytes)
  or two seals of the same digest against the same calendars produce
  different files.
- **Do not round-trip a received file to store it.** §4 shows the crate
  normalises attestation lengths; any encoder that re-emits a parsed file
  can change bytes. Store the bytes as assembled.

### 7.4 The upgrade endpoint, measured

Each pending attestation's polling commitment is the value the ops derive at
that attestation — which is exactly what A11's executor produces, so A14
depends on A11's executor and on no crate. All six captures yielded a 44-byte
commitment, e.g. for A/bob:

```
6a6f9805da7f14a96bcb07a45dc11eabc6ec73a21edc256fc1e4a109dc32556f003873210b8c9c8c453329b8
```

`GET https://<calendar>/timestamp/<hex-commitment>`, all three calendars,
retrieved **2026-08-02T19:34:10Z**:

```
http=404 bytes=42 ctype=text/plain
"Pending confirmation in Bitcoin blockchain"
```

That could have been a generic 404, so it was **falsified rather than
assumed**. The same endpoint, retrieved **2026-08-02T19:54:40Z**, with the
real commitment and with two corruptions of it:

| commitment | HTTP | bytes | body |
| --- | --- | --- | --- |
| real (derived by executing the ops) | 404 | **42** | `Pending confirmation in Bitcoin blockchain` |
| real with the last byte changed | 404 | **9** | `Not found` |
| 44 bytes of `deadbeef…` | 404 | **9** | `Not found` |

Two conclusions, and the second is the more valuable.

**(a) The op executor is validated end-to-end against a live third party.**
The calendar recognises the value we derived and does not recognise a
one-byte perturbation of it. That is independent confirmation that
`append`/`prepend`/`sha256` execution and the fork walk are right —
stronger than any self-consistent round-trip test, because the other party
computed the same value from its own records.

**(b) A14's discriminator is three-way, not two-way**, and no task says so:

| response | meaning | A14 action |
| --- | --- | --- |
| `200` + body | upgraded | merge the returned ops/attestations |
| `404` + `Pending confirmation in Bitcoin blockchain` | known, not yet upgraded | re-poll later; **not** an error |
| `404` + `Not found` | the calendar does not know this commitment | **hard error** — the submission was lost or the commitment was derived wrongly; re-polling forever will not fix it |

A client that maps 404 to failure reports every honest pending anchor as
broken; a client that maps 404 to "not ready" retries a lost submission
until the user gives up. Both are wrong, and the two cases are
distinguishable only by the body.

Also re-verified at **2026-08-02T19:34:10Z**:
`finney.btc.calendar.opentimestamps.org` still does not resolve
(`getent hosts` empty). The A25 capture's DNS failure was not transient;
D54 should treat finney as absent, not flaky.

### 7.5 A real upgraded `.ots`

The two-day A25 cycle has not run, so no upgraded fixture exists in the tree
yet. One real upgraded mainnet proof was available and is used below with its
provenance stated exactly: it is the `LARGE_TEST` constant in
`opentimestamps-0.2.0/src/lib.rs:54-113`, a genuine proof over Bitcoin blocks
**449397** and **449399** (≈ January 2017). It is *not* an A25 fixture, and
§9 records that A25 must re-measure against the real one and append.

| | value |
| --- | --- |
| size | 1 768 B |
| ops | **100** — 21 append, 21 prepend, 58 sha256 |
| max depth | **69** |
| fork nodes / max width | 3 / **2** |
| attestations | **4** — 2 pending + 2 bitcoin |
| max append/prepend operand | **174 B** (the coinbase-transaction prefix) |
| max running value | **210 B** |
| max attestation payload | **46 B** (pending URI); bitcoin payload 3 B |

**Op kinds observed across every real file, pending and upgraded:
`append`, `prepend`, `sha256`, and nothing else.** No sha1, no ripemd160, no
keccak256, no reverse, no hexlify. This is what makes §9.4 possible.

## 8. The ruling

**Write the `.ots` codec in-house in `antseal-core`. Add no dependency.**

- `opentimestamps = "=0.2.0"` is **not pinned**. Nothing is added to
  `[workspace.dependencies]` and nothing to any member manifest.
- **P18 is retired**, not amended: its deliverable was the pin. Its Accept
  rows are discharged here — the wasm32 check was performed (§1, PASS) and
  the crates.io state was checked (`GET https://crates.io/api/v1/crates/opentimestamps`,
  retrieved **2026-08-02T19:54Z**: `max_version 0.2.0`, published
  **2023-04-12T18:30:14Z**, `yanked: false`; the only other release is
  0.1.2 from 2017 — so "dormant" is confirmed at three years and one
  release). The escalation clause its `Do` provides for
  ("escalate to A/F for an in-house `.ots` codec decision") is what this
  document is, reached by a different route than the clause anticipated.
- **A11's `Do` changes** from "wrap the `opentimestamps` 0.2.0 crate … behind
  a hardened API" to "implement the `.ots` codec". Every other clause of A11
  — op execution, the digest-commitment check, per-attestation extraction,
  typed unverifiable results, the (b) limits, `MAX_OTS_BYTES` by name —
  stands unchanged and is now implementable rather than aspirational.
- **A-OD6's "vendor/fork" contingency is closed as not-taken**, on §6.
- Dependency cost of the ruling: **zero new packages.** `sha2 =0.11.0` is
  already in `antseal-core`'s graph. Against the alternative's +13, the
  in-house codec is also the cheaper option by the project's own metric.

## 9. The seven limits, with their derivations

All obey F1–F4 (`docs/format/anchor-artifact-limits.md`): evaluated **only**
in the anchor stage, never reachable from `SealProof::decode`; an over-limit
`.ots` fails **that anchor alone** as `invalid`; raise-only afterwards.

`MAX_OTS_BYTES = 1_048_576` is **consumed by name** from
`crates/antseal-core/src/codec/caps.rs` and is not redefined, restated or
shadowed here. It fires in verify stage 1 as `bundle-ots-too-large`; the
anchor stage re-checks nothing about total size.

### 9.1 The values

```rust
pub const MAX_OTS_OPS: u32 = 4_096;
pub const MAX_OTS_DEPTH: u32 = 1_024;
pub const MAX_OTS_BRANCH_WIDTH: u32 = 64;
pub const MAX_OTS_ATTESTATIONS: u32 = 256;
pub const MAX_OTS_OPERAND_BYTES: u32 = 16_384;
pub const MAX_OTS_VALUE_BYTES: u32 = 32_768;
pub const MAX_OTS_ATTESTATION_PAYLOAD_BYTES: u32 = 8_192;
```

### 9.2 Derivations

**`MAX_OTS_OPS = 4_096`** — total op steps across all branches. Structural
ceiling for an honest artifact: a Bitcoin merkle path costs 3 ops per level
(operand, sha256, sha256); block transaction count is consensus-bounded by
the 1 MB base size over the 60-byte minimum transaction, ≈ 16 666 txs, so
depth ≤ 14 → ≤ 42 ops, plus 2 for the coinbase split = **44**. A calendar
aggregating even 2²⁰ requests in one round costs 20 levels × 3 = **60**. So
an honest branch is ≤ ~110 ops, and a `.ots` merging 8 calendars is ≤ ~880.
4 096 is 4.6× that and **40.96×** the largest real file measured (100).

**`MAX_OTS_DEPTH = 1_024`** — longest root-to-attestation path. Same
structural argument gives ~110–134 for the deepest imaginable honest branch;
**14.84×** the measured 69. The implementation is required to be iterative
(§10.3), so depth costs a `Vec` entry, not a stack frame — which is why it
can be generous, and why the crate's stack-bound 255 (§3.5) is not
inherited.

**`MAX_OTS_BRANCH_WIDTH = 64`** — children of one fork node. A13 emits one
branch per calendar; each upgrade adds one more under that calendar. So
honest width ≈ 2 × calendars. 64 admits 32 fully upgraded calendars against
a ≥2-calendar policy (spec line 108), and is **21.33×** the measured 3.

**`MAX_OTS_ATTESTATIONS = 256`** — attestation nodes in the file. Honest
ceiling is 2 per calendar. **64×** the measured 4 (upgraded), **85.33×** the
measured 3 (A25 merged). Numerically the same as its bundle-side sibling
`MAX_OTS_ANCHOR_COUNT = 256`, deliberately.
**This limit is load-bearing, not decorative**: measured, a **1 048 566-byte**
`.ots` — *under* `MAX_OTS_BYTES` — carries **74 893** attestations at 14.00
bytes each, and `opentimestamps` 0.2.0 parses all of them. The byte cap does
not bound the count usefully; only this does.

**`MAX_OTS_OPERAND_BYTES = 16_384`** — one append/prepend operand.
Measured 32 B (A25) and 174 B (upgraded, the coinbase-transaction prefix).
The honest maximum is a fat coinbase transaction split around its OP_RETURN
commitment; pools paying hundreds of outputs directly from the coinbase
reach several KB, so the reference's 4 096 (and the crate's `MAX_OP_LENGTH`)
would be **too tight**, not too loose. 16 384 is **94.16×** the measured
174 B and 1.6 % of `MAX_OTS_BYTES`, so no single operand can dominate a file.

**`MAX_OTS_VALUE_BYTES = 32_768`** — the running value at any step, checked
**before** allocating the new value. Admits a full 16 384-byte prepend and a
full 16 384-byte append around a 32-byte hash, which is the honest worst
case. **156.04×** the measured 210 B. This is the limit that closes §3.2:
hexlify from 32 B reaches the cap after 10 doublings and stops, instead of
asking for 2 TiB.

**`MAX_OTS_ATTESTATION_PAYLOAD_BYTES = 8_192`** — declared payload of one
attestation, checked **before** allocating. Not guessed: it is
`python-opentimestamps`' own `MAX_PAYLOAD_SIZE = 8192` (§4), so a payload we
accept is one the reference accepts and vice versa. **178.09×** the measured
46 B. This is the limit that closes §3.1.

### 9.3 Every limit is reachable inside `MAX_OTS_BYTES`

A limit that the byte cap shadows is a rejection test that cannot fail —
the defect class this project keeps finding. But a witness must clear a
second bar as well, and the obvious shapes do not: **it must not trip an
*earlier* check in §10.3's order**, or the test asserts one code and
receives another, and the implementer "fixes" it by reordering the checks.
Two of these had to be redesigned for exactly that reason and are marked.

**Depth is defined as edges from the root step, root at 0**, so a chain of
`N` ops terminated by an attestation has maximum depth `N`. That definition
is what makes the witnesses below computable, and it must be the one the
implementation uses.

| limit | witness | why it does not trip an earlier check | file size |
| --- | --- | --- | --- |
| `MAX_OTS_OPS` | **5 branches of 820 `0x08` ops each** = 4 100 ops (*not* 4 097 in one chain) | one chain of 4 097 has depth 4 097 and trips `ots-too-deep` **first**; split, each branch is depth 821 < 1 024, width 5 < 64, 5 attestations < 256 | ≈ 4 234 B |
| `MAX_OTS_DEPTH` | 1 025 × `0x08` + attestation | 1 025 ops < 4 096, so the op count does not fire | ≈ 1 103 B |
| `MAX_OTS_BRANCH_WIDTH` | 65 sibling branches, each a 13-B pending attestation | 65 attestations < 256; 0 ops; depth 1 | ≈ 975 B |
| `MAX_OTS_ATTESTATIONS` | **64 root branches, each forking into 5** = 320 attestations (*not* 257 siblings) | 257 siblings is width 257 and trips `ots-branch-too-wide` **first**; nested, every fork is exactly at the width cap (64 and 5), never over | ≈ 4 544 B |
| `MAX_OTS_OPERAND_BYTES` | one 16 385-byte append operand | operand length is checked before value length, so it fires rather than `ots-value-too-long` | ≈ 16 455 B |
| `MAX_OTS_VALUE_BYTES` | two 16 384-byte appends (32 → 16 416 → 32 800) | each operand is exactly *at* 16 384 and passes; the value cap fires on the **second** append | ≈ 32 900 B |
| `MAX_OTS_ATTESTATION_PAYLOAD_BYTES` | one 8 193-byte unknown-tag payload | 1 attestation; the payload cap is checked before the bytes are read | ≈ 8 275 B |

Every witness is under 33 KB — 3.1 % of `MAX_OTS_BYTES` at worst — so no
limit is shadowed by the byte cap.

### 9.4 Ops we do not implement, and why that is not a limit

Per **F3**, unknown ≠ over-limit. §7.5 measured that every real `.ots`,
pending and upgraded, uses only `append`, `prepend` and `sha256`. So
`antseal-core` implements exactly those three and needs no hash primitive
beyond the pinned `sha2 =0.11.0` — no SHA-1, no RIPEMD-160, no Keccak-256
enter the core to execute a foreign format's dead opcodes.

The registered-but-unimplemented ops `0x02` sha1, `0x03` ripemd160, `0x67`
keccak256, `0xf2` reverse, `0xf3` hexlify are all **one wire byte with no
operand**, so the parser skips them structurally: the subtree below such an
op has an *indeterminate* value, and every attestation in that subtree is
reported **unverifiable**. Sibling subtrees are unaffected. This is A11's
"typed unverifiable results, never crashes", implemented.

Promoting one of these later — implementing sha1, say — only turns
`unverifiable` into a real verdict. It never rejects an artifact a past
release accepted, so it is compatible with MVP-SPEC.md line 123 and with F4.

### 9.5 The F4 registry rows (verbatim, for `docs/format/anchor-artifact-limits.md` §5)

| limit | owner | initial value | date set | measured against (A25 fixture path) | margin | lowered |
| --- | --- | --- | --- | --- | --- | --- |
| `MAX_OTS_OPS` | A11 | 4_096 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/` (100 ops; bootstrap measurement taken on the rust-opentimestamps `LARGE_TEST` mainnet proof, blocks 449397/449399, pending A25's two-day cycle) | 40.96x | never |
| `MAX_OTS_DEPTH` | A11 | 1_024 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/` (depth 69; bootstrap measurement as above) | 14.84x | never |
| `MAX_OTS_BRANCH_WIDTH` | A11 | 64 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (width 3) | 21.33x | never |
| `MAX_OTS_ATTESTATIONS` | A11 | 256 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (3) and `.../upgraded/` (4, the binding one; bootstrap measurement as above) | 64.00x | never |
| `MAX_OTS_OPERAND_BYTES` | A11 | 16_384 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/` (174 B coinbase-prefix operand; bootstrap measurement as above) | 94.16x | never |
| `MAX_OTS_VALUE_BYTES` | A11 | 32_768 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/` (210 B running value; bootstrap measurement as above) | 156.04x | never |
| `MAX_OTS_ATTESTATION_PAYLOAD_BYTES` | A11 | 8_192 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (46 B pending payload); value taken from python-opentimestamps `MAX_PAYLOAD_SIZE` | 178.09x | never |

**A25 must re-measure the four `upgraded/` rows against the real upgraded
fixture when the two-day cycle completes and append the measurement.** The
values do not change — F4 forbids lowering and none of them needs raising —
but the provenance cell must stop citing a third-party crate's test
constant.

## 10. Exact instructions for the implementer

### 10.1 File layout

New module tree in `antseal-core` (there is no `anchor` module today; this
creates it):

```
crates/antseal-core/src/anchor/mod.rs          — pub mod ots;
crates/antseal-core/src/anchor/ots/mod.rs      — public API + OtsArtifact/OtsAttestation
crates/antseal-core/src/anchor/ots/limits.rs   — the seven constants of §9.1
crates/antseal-core/src/anchor/ots/parse.rs    — the iterative parser
crates/antseal-core/src/anchor/ots/exec.rs     — append / prepend / sha256
crates/antseal-core/src/anchor/ots/error.rs    — OtsError
crates/antseal-core/src/anchor/ots/encode.rs   — the writer (task A34)
```

`crates/antseal-core/src/lib.rs` gains `pub mod anchor;` **immediately before
`pub mod bundle;`**, keeping the list alphabetical.

> **Amendment, 2026-08-02 (orchestrator, reported by the A2 lane).** This
> paragraph originally read *"between the existing `pub mod bundle;` (line 19)
> and `pub mod canon;` (line 20), keeping the list alphabetical"*, which is
> **self-contradictory**: `anchor` sorts *before* `bundle`, so the stated
> position and the stated reason cannot both be satisfied. A2 landed the
> module at the alphabetically correct position, which is what this text now
> says. Recorded rather than silently fixed, per the round's rule that a
> correction left in a task report is one the next reader never sees.

### 10.2 Public API

```rust
pub fn parse_ots(bytes: &[u8], anchor_digest: &[u8; 32]) -> Result<OtsArtifact, OtsError>;

pub struct OtsArtifact {
    pub attestations: Vec<OtsAttestation>,
}

pub enum OtsAttestation {
    /// Calendar attestation. `commitment` is the ops-derived value at this
    /// node — the string A14 puts in the upgrade URL. `None` when the path
    /// to this node crosses a registered-but-unimplemented op (§9.4), so
    /// the value is indeterminate and this attestation is unverifiable.
    Pending { uri: String, commitment: Option<Vec<u8>> },
    /// `merkle_root` is the ops-derived value at this node, `None` under the
    /// same condition. A12 byte-compares it with the embedded 80-byte
    /// header's merkle-root field; a length other than 32 fails that compare
    /// naturally, so the parser does not need to assert one.
    Bitcoin { height: u64, merkle_root: Option<Vec<u8>> },
    /// An attestation type we do not know: skipped structurally (its payload
    /// is length-prefixed), carried as evidence, never verified. The payload
    /// bytes are deliberately **not** retained — only its length.
    UnknownType { tag: [u8; 8], payload_len: u32 },
}
```

`anchor_digest` is a **required parameter**, not an optional check — the
signature makes "parse without checking the digest" unspellable. Every
attestation node is reported even when its value is indeterminate, so a
`.ots` that mixes a verifiable branch with one under an unimplemented op
still yields the verifiable half; that is what makes §9.4's "sibling
subtrees are unaffected" true in the type rather than in prose.
Measured: `commitment` is 44 bytes for all six A25 captures.

### 10.3 Frozen check order

Fixes tamper-row precedence, in the manner of D10 §5. Steps 1–6 are O(1).

| order | check | code on failure |
| --- | --- | --- |
| 0 | *(stage 1, F's, already done)* `input.len() > MAX_OTS_BYTES` | `bundle-ots-too-large` |
| 1 | 31-byte magic | `ots-bad-magic` |
| 2 | version varuint `== 1` | `ots-unsupported-version` |
| 3 | digest-type tag `== 0x08` | `ots-unsupported-digest-type` |
| 4 | 32 digest bytes present | `ots-truncated` |
| 5 | **`start_digest == anchor_digest`** | `ots-ops-do-not-commit-anchor-digest` |
| 6 | walk the DAG, limits below | per limit |
| 7 | input fully consumed | `ots-trailing-bytes` |

Step 5 is A11's named "ops do not commit `anchor_digest`" error, and placing
it at step 5 is deliberate: every attestation in the file descends from
`start_digest`, so the equality on that one header field *is* the
commitment check — and putting it ahead of the walk means a wrong-digest
`.ots` costs one 32-byte comparison and can never be used as a work
amplifier.

Inside the walk, per step:

| order | check | code |
| --- | --- | --- |
| a | varuint ≤ 9 bytes and value fits `u64` | `ots-varint-too-long` |
| b | depth of the child being entered ≤ `MAX_OTS_DEPTH` | `ots-too-deep` |
| c | running op total ≤ `MAX_OTS_OPS` | `ots-too-many-ops` |
| d | operand length ≤ `MAX_OTS_OPERAND_BYTES`, **before reading** | `ots-operand-too-long` |
| e | resulting value length ≤ `MAX_OTS_VALUE_BYTES`, **before allocating** | `ots-value-too-long` |
| f | fork children ≤ `MAX_OTS_BRANCH_WIDTH` | `ots-branch-too-wide` |
| g | running attestation total ≤ `MAX_OTS_ATTESTATIONS` | `ots-too-many-attestations` |
| h | attestation payload length ≤ `MAX_OTS_ATTESTATION_PAYLOAD_BYTES`, **before allocating** | `ots-attestation-payload-too-long` |
| i | attestation payload fully consumed by its own parse | `ots-attestation-payload-not-consumed` |
| j | any read past the end of input | `ots-truncated` |

Rules that are not limits and must be implemented as written:

1. **The parser is iterative.** An explicit `Vec` work-stack, no recursive
   descent. This is what makes native and wasm32 behave identically at depth
   and what makes `MAX_OTS_DEPTH` a policy rather than a stack measurement
   (§3.5). A `#![deny]`-level review item, and a test at depth
   `MAX_OTS_DEPTH` on a 256 KiB thread stack witnesses it.
2. **Attestation payloads are sub-sliced.** Read exactly `payload_len` bytes,
   parse the height or the URI *within that slice*, and require the slice to
   be exhausted (check `i`). This is the fix for §4 and it is the reason
   `ots-attestation-payload-not-consumed` exists.
3. **Varuints are bounded, not minimal.** At most 9 continuation-free bytes
   (63 bits, so the shift can never reach 64). Minimal encoding is *not*
   required — `.ots` is a foreign format we do not control, and rejecting a
   non-minimal varuint a future calendar emits would be a rejection the
   reference does not make.
4. **Never allocate from a length header before checking it.** The clamp
   discipline of `codec/caps.rs` applies unchanged.
5. **`parse_ots` takes no total-size cap of its own, and must not grow one.**
   `MAX_OTS_BYTES` fires in stage 1 over the bundle field (F's,
   `bundle-ots-too-large`) and A28 bounds A13's merged file; adding a third
   would be the duplicate A11's Accept has a grep-level review item against.
   Safety does not depend on it: the walk's own limits terminate early
   regardless of input length — an arbitrarily long run of `0x08` dies at
   `MAX_OTS_OPS`, of `0xff` at `MAX_OTS_BRANCH_WIDTH`, of `0x00`-attestations
   at `MAX_OTS_ATTESTATIONS` — so work is bounded by the limits, not by the
   caller's diligence.

### 10.4 Error codes

> **Amended 2026-08-02 by [D91](D91-anchor-error-code-namespace.md).** This
> section originally opened *"New domain prefix **`ots-`**, owner **A**,
> appended to `docs/testing/error-code-contract.md` §2's table. It borrows no
> other family's prefix; A5 will want a sibling `tsa-` on the same grounds."*
> **`ots-` is not registered and never will be. The A domain has one prefix,
> `anchor-`.** The sibling this section predicted was decided the same day and
> went the other way: **D60 §7.2** — A5's own decision — opens *"New
> error-code prefix **`anchor-`**, owner **A**"* and mints eight codes under
> it, as do D53 §7, D56 §7 and D59 §5. The sixteen codes listed below are
> therefore read as `anchor-ots-*` throughout: fifteen take the prefix
> mechanically (D91 §7.1's map), and the seventh,
> `ots-ops-do-not-commit-anchor-digest`, is **not minted at all** — the
> digest-commitment check is D56 §7's `anchor-ots-digest-mismatch`, which
> §10.3 step 5 raises and to which D53 §8 already binds M2 tamper row 1.
> Every other clause of §10.4 stands, and so does the whole of §§9–11: the
> seven limits, their derivations and F4 rows, the frozen check order, the
> iterative-parser requirement and the named tests are untouched by the
> renaming. One further correction §10.2 needs, from D91 §6.4: `OtsArtifact`
> has no `stamped_digest` field, and this is correct — the comparison belongs
> in the parser for §10.3's work-amplifier reason — so **D56 rule O2 names an
> outcome rather than adding a second check**, and D58 §11's
> `ots_stamping_a_different_digest_is_rejected` and D56 §9's
> `a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` are one test.

New domain prefix **`ots-`**, owner **A**, appended to
`docs/testing/error-code-contract.md` §2's table. It borrows no other
family's prefix; A5 will want a sibling `tsa-` on the same grounds.

```
ots-bad-magic
ots-unsupported-version
ots-unsupported-digest-type
ots-truncated
ots-trailing-bytes
ots-varint-too-long
ots-ops-do-not-commit-anchor-digest
ots-too-many-ops
ots-too-deep
ots-branch-too-wide
ots-too-many-attestations
ots-operand-too-long
ots-value-too-long
ots-attestation-payload-too-long
ots-attestation-payload-not-consumed
ots-unknown-op
```

Sixteen codes, pairwise distinct, each with a tamper row or a rejection test
in §11. They join `testdata/error-codes/v1/CODES.txt` by the additions-only
path (§4a of the contract).

`ots-unknown-op` covers an op tag that is in **neither** the implemented set
`{0x08, 0xf0, 0xf1}` **nor** the registered-but-unimplemented set
`{0x02, 0x03, 0x67, 0xf2, 0xf3}`. It is a parse error, not an unverifiable
result — see the correction in §12.2, which explains why A11's `Do` cannot be
followed literally here.

### 10.5 Mapping onto the frozen seven states

**No eighth state is minted and no spelling changes.** A18 maps A11's
`OtsArtifact` onto the frozen `AnchorState`
(`crates/antseal-core/src/verify/report.rs:257`) as:

| A11 result | `AnchorState` |
| --- | --- |
| ≥1 `Bitcoin` with `Some(merkle_root)` matching the embedded header (A12) | `attested` |
| ≥1 `Pending` with `Some(commitment)`, no verified `Bitcoin` | `pending` |
| parses, but **no** attestation has a determinate value — every one is `UnknownType`, or carries `None` | `internally-consistent-only` |
| any `OtsError` — including every limit code | `invalid` |

The third row is the one that would otherwise tempt someone to mint a state.
It does not need one: MVP-SPEC.md line 133 defines
`internally-consistent-only` as "cryptographically well-formed but not
independently anchored", which is exactly an `.ots` whose attestations are
all of types we cannot check.

## 11. Tests that must exist, and what makes each fail

Named tests, in `crates/antseal-core/src/anchor/ots/` unit modules unless a
path is given. For each, the mutation that turns it red.

| test | fails when |
| --- | --- |
| `merged_pending_ots_parses_and_yields_three_pending_attestations` | the A25 merged fixture stops parsing, or the fork/`0xff` handling drops or duplicates a branch (count ≠ 3) |
| `pending_commitment_matches_recorded_value` | op execution changes: the derived 44-byte commitment for A/bob stops equalling the recorded hex, so A14 would poll the wrong URL |
| `upgraded_ots_yields_bitcoin_height_and_merkle_root` | the Bitcoin attestation payload parse regresses, or the derived root at that node changes |
| `ots_stamping_a_different_digest_is_rejected` | step 5 is removed or moved after the walk — flip one bit of the fixture's start digest; must be `ots-ops-do-not-commit-anchor-digest` and **not** any other code (A21 row 1) |
| `unknown_attestation_with_huge_declared_length_is_rejected_not_aborted` | the payload cap is removed — this is the §3.1 80-byte input; must return `ots-attestation-payload-too-long`. **Red today against `opentimestamps` 0.2.0: the process aborts and the test binary dies** |
| `hexlify_chain_cannot_grow_the_running_value` | the value cap is removed — §3.2's 102-byte input; must return `ots-value-too-long` |
| `thirteen_byte_varint_is_rejected` | the varuint bound is removed; §3.3's input must return `ots-varint-too-long`. A masked-shift regression that "succeeds" fails this |
| `ots_module_contains_no_runtime_shift` | a shift by a non-constant amount reappears anywhere under `anchor/ots/`. **This is the test that carries the cross-profile claim, and it exists because the unit test above cannot** — see the note below |
| `attestation_payload_length_is_authoritative` | the sub-slice or the `assert_eof` is removed — §4's 90-byte input; must be `ots-attestation-payload-not-consumed`, and must **not** report two attestations |
| `over_limit_ots_fails_only_its_own_anchor` (`crates/antseal-core/tests/`) | **F1/F2 demonstrated, not asserted**: a bundle whose sole `.ots` breaks any limit must still decode, still verify its manifest, still render its TSA anchors, and mark only that anchor `invalid`. Fails if a limit leaks into `SealProof::decode` |
| `every_ots_limit_has_a_reachable_witness_under_max_ots_bytes` | a limit is raised past the point where its `cap + 1` witness exceeds `MAX_OTS_BYTES`, which would make its rejection test unfallible. Asserts each §9.3 witness is `< MAX_OTS_BYTES` **and** returns **its own** code — the second half is the one that matters, because two of the seven natural witnesses trip a different limit first (§9.3) and would otherwise silently test the wrong thing |
| `check_order_is_the_frozen_one` | any two checks in §10.3 are swapped. Constructs an artifact violating **two** limits at once (e.g. a 4 097-op single chain, which is over both `MAX_OTS_OPS` and `MAX_OTS_DEPTH`) and pins which code wins. Without this, §9.3's witnesses are correct only by accident |
| `ots_limits_match_the_f4_registry` | a constant in `limits.rs` and its row in `docs/format/anchor-artifact-limits.md` §5 drift apart (same shape as the existing `format_registry_freeze.rs` cross-check) |
| `no_ots_constant_duplicates_max_ots_bytes` | a byte cap over the whole artifact is re-minted in `limits.rs`; A11's grep-level review item made mechanical |
| `unimplemented_ops_yield_indeterminate_values_not_errors` | sha1/ripemd160/keccak256/reverse/hexlify stop being skipped structurally. A two-branch fixture — one branch clean, one behind a `0xf2` — must yield **both** attestations, the first with `Some(commitment)` and the second with `None`. Fails if the whole parse errors (over-strict) *or* if the second reports a value (which would be a fabricated commitment) |
| `unknown_attestation_type_is_carried_not_dropped` | an unknown 8-byte tag stops producing an `UnknownType` entry. It must appear with its tag and payload length, its payload bytes must **not** be retained, and sibling attestations must be unaffected |
| `parser_is_iterative_at_max_depth` | recursion is reintroduced: parse a `MAX_OTS_DEPTH` chain on a 256 KiB stack thread. **A recursive implementation aborts here** — that is exactly the measurement of §3.5 |
| `round_trip_of_the_merged_fixture_is_byte_identical` (A34) | the encoder stops reproducing the assembled bytes, or branch ordering becomes non-deterministic |
| wasm32 parity (`scripts/wasm-bitmatch.sh`) | native and wasm32 disagree on any fixture or any rejection code |

Two of these are deliberately written to be red *today*: the abort tests
would kill the test process against `opentimestamps` 0.2.0, and
`parser_is_iterative_at_max_depth` would abort against any recursive-descent
implementation. That is the point — they witness the ruling rather than
restating it.

**Why the cross-profile claim needs a second, structural test.** `.github/workflows/ci.yml:148`
is `cargo test --workspace --locked` and there is **no release test lane
anywhere in CI or in `scripts/local-gate.sh`**. So a test asserting "the same
answer in debug and release" would only ever *run* in debug and could never
fail on the release half — precisely the un-failable test this project keeps
finding. The cross-profile property is instead guaranteed by construction
(a bounded varuint reader has no shift that can overflow) and witnessed by a
grep-level assertion that the module contains no shift by a runtime value,
which is the only construct whose behaviour differs between profiles.

This is worth stating beyond its own test row, because it is the general
lesson of §3.3: **a release-only behaviour difference is structurally
invisible to this project's CI.** The `opentimestamps` shift bug is not an
exotic case — it is the shape of bug that a debug-only suite is guaranteed to
miss, and it argues for keeping adversarial parsing inside code we own and
audit rather than behind a dependency's API.

## 12. Errors found in the register, the tasks and the docs

### 12.1 `tasks/A.md` A11 Notes — the stated test is not the deciding test

> "verify at execution time that it compiles on current stable and wasm32;
> vendoring/forking the codec is the contingency"

Both halves are wrong as guidance. It compiles on both (§1), and vendoring
is not a cheaper contingency than writing (§6). An implementer following
this Note literally would have pinned the crate on a green compile.
**Correction:** replace with — *"0.2.0 compiles on 1.92.0 and wasm32 (D58
§1); it is rejected on measured behaviour, not portability. `.ots` codec is
in-house — D58."*

### 12.2 `tasks/A.md` A11 `Do` — "unknown ops … surface as typed unverifiable results" is not implementable as one rule

The sentence treats unknown ops and unknown attestation types alike. They
are not alike, and the difference is structural: an **attestation** payload
is length-prefixed, so an unknown type can be skipped and surfaced as
unverifiable; an **op** tag carries no length, so an unregistered op tag
cannot be skipped at all — the parser cannot find where it ends and
therefore cannot reach anything after it. **Correction:** split the clause —
unknown *attestation types* and registered-but-unimplemented *ops* surface
as typed unverifiable results (§9.4); an *unregistered op tag* is
`ots-unknown-op` and renders that anchor `invalid`, because an artifact we
cannot finish reading is not known to be well-formed, which is F3's own
reasoning for why over-limit is not `internally-consistent-only`.

### 12.3 `docs/format/anchor-artifact-limits.md` §4 — the A11 row list is incomplete

§4 presents its table as exhaustive: *"the genuinely open, genuinely M2,
genuinely non-frozen numbers are these eight"*, with four for A11 (op count,
operand length, branch depth/width, attestation count). Two more are
required, and their absence is not cosmetic — each corresponds to a measured
uncatchable abort:

- **max running value length** — §3.2, the 102-byte hexlify abort. An
  *operand* cap does not bound the running value, because `hexlify` and
  `reverse` take no operand.
- **max attestation payload length** — §3.1, the 80-byte abort.

**Correction:** add both rows to §4's table under owner A11, and soften
"these eight" to "these ten"; or, better, drop the exhaustiveness claim,
since it is what made the omission invisible.

### 12.4 `MVP-SPEC.md` — the crate is named in **two** places, not one

**Line 108** ends: *"reusing the crate solely as the wire-format layer."*
The sentence's first half is right and stays — the crate is a codec only, and
the calendar client is committed in-house M2 work. The last clause is now
false. **Correction:** *"…is committed in-house M2 work (~1–2 weeks). The
crate is **not** reused as the wire-format layer either — see
`docs/decisions/D58`; the `.ots` codec is in-house, over the already-pinned
`sha2`, at zero added dependency cost."*

**Line 155**, the M2 milestone line, repeats it in a parenthesis that is easy
to miss: *"OTS calendar client (in-house; `opentimestamps` crate as
codec)"*. **Correction:** *"(in-house, codec included — D58)"*. Correcting
line 108 alone would leave the milestone line contradicting it, and the
milestone line is what a reader checks when scoping M2.

The effort estimate is unaffected either way: the client was always the work.
For scale, the crate's whole library is **1 040 lines across 7 files**
(1 097 with its `ots-info` binary), and a large fraction of that is `Display`
impls, the embedded test constants, and the `std::io` scaffolding §6 says we
would delete. The in-house parser + executor + encoder is estimated at 300–400
lines; that figure is an estimate and is the only unmeasured number in this
document.

### 12.5 `scripts/ci-lanes.sh` `lane_dep_graph` — the forbidden list has a hole

Reported in §2(b) and written up as **Q74**. The lane's stated claim is
"antseal-core's NORMAL dependency graph must be I/O-free and RNG-free", but
its regex is a list of nine async/network/RNG names. `env_logger`, `libc`,
`is-terminal`, `termcolor` and `regex` pass it. The hole is independent of
this decision and would be exercised by the next crate anyone nominates.

> **Corrected 2026-08-02 (Q74, at implementation).** This heading — *"the
> forbidden list has a hole"* — states the defect in a way that **invites the
> wrong fix**, and the D90 planner measured that the wrong fix does not work:
> extending the name list still admits `env_logger`, `libc`, `is-terminal`,
> `regex` and `termcolor`. **I/O-freedom is not decidable from a dependency
> graph**, so the list can never be completed. Q74 therefore narrowed the
> *claim* rather than widening the *check*: the lane now asserts that
> `antseal-core`'s normal graph is **exactly a 57-name reviewed set** (set
> equality, both directions), keeps the nine names as the separately-titled
> *decided prohibitions*, and carries a scope note stating outright that a
> green verdict is a "nothing entered unreviewed" proof and **not** an
> I/O-freedom proof, and may not be cited as one. Proven to bite by planting
> `env_logger` on `antseal-core`: new check **RED** naming 13 unreviewed
> arrivals, pre-Q74 check **GREEN** on the identical graph.

### 12.6 `tasks/A.md` A14 — the "not ready" discriminator is three-way, and the task implies two

A14's `Do` requires distinguishing "not ready yet" from hard calendar errors
and does not say how. Measured (§7.4), the upgrade endpoint returns **404 for
both** conditions and separates them **only by response body**: 42 bytes of
`Pending confirmation in Bitcoin blockchain` for a commitment it knows and has
not yet upgraded, 9 bytes of `Not found` for one it does not know.
**Correction/addition:** record all three outcomes on A14 (200 = upgraded;
404 + `Pending…` = re-poll; 404 + `Not found` = hard error, the submission
is lost or the commitment is wrong). A status-code-only client cannot
implement A14's own requirement.

### 12.7 D54's calendar set — finney is absent, not flaky

`finney.btc.calendar.opentimestamps.org` failed DNS at the A25 capture
(19:16:21Z) and again on independent re-check at **19:34:10Z** (§7.4). Two
failures 18 minutes apart is weak evidence of permanence but it is the
evidence there is; D54 should treat it as absent and pick its default set
from alice / bob / catallaxy, all three of which answered HTTP 200 on submit
and a well-formed 404 on upgrade.

## 13. Residual risks

1. **No real upgraded `.ots` fixture exists yet.** Four of the seven F4 rows
   are measured against a third-party crate's 2017 mainnet test constant
   (§7.5), with provenance stated in the registry cell. A25's two-day cycle
   must re-measure and append. The risk is bounded by direction: F4 forbids
   lowering, and every margin is ≥ 14×, so a surprise in the real fixture
   would have to be an order of magnitude off to matter.
2. **Coinbase-transaction size is the softest input to `MAX_OTS_OPERAND_BYTES`.**
   16 384 rests on a reasoned ceiling for a fat coinbase, not on a measured
   one — the only measurement is 174 B. It is the row most likely to need a
   raise, and raising is free.
3. **`ots-unknown-op` renders `invalid` for an op the OTS project might
   register later.** Reversible in the safe direction (§9.4), but it should
   be a watch item: if OTS registers a new op, A11's set changes and the
   change is a promotion.
4. **The in-house codec is new code on an adversarial path.** Mitigated by
   A23's fuzz target, by the §11 tamper tests, and by A35's cross-
   implementation differential — the last of which exists specifically
   because §4 is the class of bug that unit tests do not find.

## 14. Revisit triggers

- A maintained pure-Rust `.ots` codec appears with bounded parsing, a
  `&[u8]` API, no logger, and reference-conformant attestation payload
  handling. (`opentimestamps` 0.2.0 gaining a new release is *not* by itself
  a trigger; the four defect classes are.)
- The OTS project registers a new op tag or a new attestation type.
- A25's real upgraded fixture exceeds any margin in §9.5 by more than 10×,
  i.e. any measured quantity lands within 1.5× of its cap.
- Bitcoin's consensus block-size rule changes, which is the input to
  `MAX_OTS_OPS`' and `MAX_OTS_DEPTH`' structural derivations.

## Index row (orchestrator applies at merge)

| [D58](D58-opentimestamps-viability.md) | `opentimestamps` 0.2.0 viability — **not adopted in any form; the `.ots` codec is in-house in `antseal-core` over the already-pinned `sha2`, at +0 packages against the crate's +13.** Both halves of the register's framing overturned: it **does** compile on `=1.92.0` and wasm32 (`cargo build` codegen green), so the stated test decides nothing; and "vendor/fork" is not a cheaper contingency because the crate is **edition 2015** and every line needing change is a line. Decided on measured behaviour instead — an **80-byte** `.ots` drives an uncatchable `SIGABRT` from `vec![0; attacker_varint]`, a **102-byte** one from an unbounded hexlify chain, an **87-byte** one panics in debug and *parses to a different answer* in release, and a **90-byte** one makes this crate and `python-opentimestamps` report **different attestation sets from identical bytes** (the crate ignores the declared attestation payload length; the reference sub-slices, caps at 8192 and asserts EOF). Unwrappable: `from_reader` fuses parse + op execution + recursion in one call, so any pre-filter enforcing A11's limits *is* the parser. Also: `env_logger` is a non-optional dep of a codec, and `core-dep-graph`'s forbidden list would not have caught it (→ Q74). Establishes the `.ots` container byte-by-byte from the A25 captures (65-B header, `0xff` before every branch but the last; 3-calendar merge = 664 B, round-trip byte-identical), and — by falsifying it against corrupted commitments — that the upgrade endpoint's discriminator is **three-way, not two**: `404 + "Pending confirmation in Bitcoin blockchain"` (re-poll) vs `404 + "Not found"` (hard error), separated by body alone, which also validates the op executor against a live calendar (→ A14). **Seven limits set with F4 rows** (ops 4 096, depth 1 024, width 64, attestations 256, operand 16 384 B, running value 32 768 B, attestation payload 8 192 B), two of them absent from A27 §4's "exhaustive" list and each closing a measured abort; measured, a 1 048 566-B `.ots` carries **74 893** attestations under `MAX_OTS_BYTES`. **P18 retired** | RESOLVED | 2026-08-02 |
