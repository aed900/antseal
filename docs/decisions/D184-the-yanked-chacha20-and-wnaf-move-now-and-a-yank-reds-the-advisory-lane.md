# D184 — The yanked `chacha20 0.10.1` and `wnaf 0.14.0` move **now**, in both lockfiles, as one dependency-policy §4 event with **no manifest change**; `deny.toml` gains **`yanked = "deny"` in the same act**, so the next upstream yank reds the advisory lane; **no redeploy is owed**; and `P23`'s rc watch is **recorded, not moved**

- **Status: RESOLVED. `Q275`'s "leave both alone" lean fell on its premise; H1 kept its
  direction and lost one premise, that the policy treats a yank as a red flag; H2 was a
  false dichotomy.**
  - **The lean falls on its premise.** `Q275` Do (d) left the pair alone because *"a
    chacha20/wnaf move is a §4 crypto event inside antseal-core's frozen-vector graph"*.
    For a crate that is not `ant-core`, §4 asks three things — a changelog review, a
    RUSTSEC check and a golden-vector re-run (`docs/dependency-policy.md:250-256`) — and
    all three are measured in §1 or run inside the wave-close gate, which any `Cargo.lock`
    change already forces to the heavy tier and the devnet E2E (`CONTRIBUTING.md:349-353`).
    The frozen vectors are the detector that makes the move safe, not a reason against it.
    The lean was a sound **scope** ruling for `Q275` — §4 keeps a bump to *"only the bump
    and its direct fallout"* (`docs/dependency-policy.md:247-248`), and the pair was not
    rustls' fallout — but it leaves the pair with no owner once `Q275` ticks: `Q275` is the
    only row that names either crate (§1.8).
  - **H1 — *lock-only*, *cheap*, *the policy's own red flag*.** *Lock-only* holds: root lock
    7+/6−, fuzz lock 5+/4−, package counts 772 and 127 unchanged, feature sets unchanged,
    and the only new edge, `wnaf → primefield`, points at a package already locked.
    *Cheap* holds, but the E2E tier and a by-hand reproducibility comparison must be paid.
    **The red flag falls**: no rule makes a yank red. D19 (`:36-37`) and `deny.toml:38` say
    yanks *"surface"*, and cargo-deny 0.19.8's default `yanked = "warn"` prints a warning and
    does not fail the check — measured on this repository: `advisories ok`, exit 0, two
    `warning[yanked]` (§1.5).
  - **H2 — a false dichotomy.** `wnaf 0.14.0` is a real correctness bug — its `le_repr`
    reversed every scalar's bytes, which is wrong for little-endian scalar fields
    (`elliptic-curves#1913`: `bignp256`'s scalars were read with the wrong value) — it **is**
    on antseal's P-384 TSA verify path, and it is **value-identical for P-384**, whose scalar
    is big-endian: all three at once. Upstream's yank note calls it *"a breaking bounds
    change"*.
  - **chacha20's yank reason is confirmed, and is narrower than "SSE2 UB".** The SSE4.1
    intrinsic sits at two sites. antseal's XChaCha core reaches neither in the default and
    wasm32 graphs, but the shipped `ant-backend` CLI reaches the second through
    saorsa-transport's default-on UPnP fallback (§1.3). The effect is a SIGILL on an x86 CPU
    with SSE2 but neither AVX2 nor SSE4.1 — never a verdict defect.
  - **`P23` — record, do not move; its yank premise falls.** The move trigger stays the final
    releases. `rsa 0.10.0-rc.19` cannot resolve against the `der =0.8.1` pin, `cms
    0.3.0-rc.0` changes a verdict-path parse, and both `P23`'s *"the first symptom would be a
    red advisory lane"* and D60 §8.1's *"`cargo deny`'s `yanked` check is on"* were false
    under `warn`. Neither rc's re-verification had been recorded anywhere.
- **Date: 2026-10-16**
- Owner rows: **`Q278`** (minted with this record: the yanked pair, the move and the `yanked`
  key — §2 R1–R3, R6); **`Q275`** (a dated pointer: its Do (d) residue is discharged by
  `Q278`); **`P23`** (a dated note and no move — §2 R5).
- Related: **D19** (the advisory lane; *"defaults kept (vulnerability / unmaintained / unsound
  / yanked all surface)"*; takes a dated addendum), **D60** §8.1 (*"`cargo deny`'s `yanked`
  check is on"*; takes a dated addendum), **D18** (the shipped module is `antseal-wasm`'s
  package output, whose graph carries both crates; `wasm-bitmatch`, the native↔wasm32
  comparison §2 R1 relies on), **`Q275`**, **`P23`**, **`R86`**/**`Q238`** (the two-environment
  reproducibility comparison §3 G6 runs by hand on the moved graph).

## 0. What was measured against

`HEAD` `fbcee1e` (== `origin/main`). Planning lane P5 (wave 37) worked read-only on the
repository and ran every experiment in a `git clone --local`, restored to a clean status each
time, against advisory DB `edb58f59` (2026-10-14T22:18+02:00) — the head `Q275` landed
against — and `cargo-deny 0.19.8`. It read crates.io's API and the RustCrypto and rustsec
trackers on 2026-10-16, and the sha256 of each of the ten `.crate` files it downloaded equals
crates.io's `checksum`.
Before this record was written the records lane re-ran, without touching the tree: the
yanked flags in cargo's sparse-index cache; `cargo deny --locked check --disable-fetch
advisories` at `HEAD`; the same against a copy of `deny.toml` carrying `yanked = "deny"`,
passed with `--config`, on the `HEAD` lock and on a moved lock; both `--precise` moves in a
throwaway local clone; `cargo tree -i` and `-e features` on the `HEAD` graph; the upstream
sources at the locked versions; this host's CPU flags; and the string counts of the page
module built at `fbcee1e`. Every result agreed with P5. This host's clock runs about three
minutes slow (instrument ledger, 2026-10-15); every time quoted below is crates.io's or
GitHub's.

## 1. What was measured

### 1.1 The yanks (crates.io, 2026-10-16)

| crate | version | yanked | when, by whom | successor |
| --- | --- | --- | --- | --- |
| `chacha20` | 0.10.0, 0.10.1 | yes | 2026-08-27T18:33Z, newpavlov | 0.10.2, published 2026-08-27T17:51Z |
| `wnaf` | 0.14.0 | yes | 2026-09-03T19:10:31Z, tarcieri | 0.14.1, published 19 s later |
| `chacha20` | 0.9.1 (also in the root lock, under another parent) | no | — | — |

Neither yank carries a message. Checksums: `chacha20 0.10.1` `d524456b…0a81` → `0.10.2`
`65c35e4b…1b06`; `wnaf 0.14.0` `ab12e709…daf1` → `0.14.1` `795ca18b…f6fa`. Both new versions
declare `rust-version 1.85`, inside the 1.92.0 pin. RUSTSEC (`edb58f59`): `chacha20` has only
RUSTSEC-2019-0029 (`patched >= 0.2.3`); `wnaf`, `p384`, `primeorder`, `primefield` and
`chacha20poly1305` have no directory. A clean-machine `cargo build --locked` still downloads a
yanked version: a yank deletes nothing (`Q275` Notes).

### 1.2 What changed upstream

- **`chacha20` 0.10.1 → 0.10.2** changes `src/backends/sse2.rs` and nothing else that
  compiles (`Cargo.toml` changes only `version`). 0.10.1 calls the SSE4.1 intrinsic
  `_mm_extract_epi32` at `chacha20-0.10.1/src/backends/sse2.rs:54`, inside `if
  size_of::<V::Counter>() == 8` (64-bit counters only), and at `:133`, inside `rng_inner`
  (`:113-134`, `cfg(feature = "rng")`), unconditionally. 0.10.2's `sse2.rs` has no use left:
  `Backend::new` loads the state and `save_ctr` stores the whole counter row. For the `Ietf`
  variant the counter advances by `_mm_add_epi32(…, set_epi32(0,0,0,n))` (P5:
  `chacha20-0.10.2/src/backends/sse2.rs:94,111`), so the nonce lanes are never written and the
  whole-row store equals the old `state[12]` write. CHANGELOG: *"Use of SSE4.1 intrinsic in
  SSE2 backend of RNG and legacy (64-bit counter) variants ([#580])"*; `stream-ciphers#583`:
  *"The yanked versions contain UB in SSE2 backend, see #580."* The Miri report (`#579`)
  traces `rng_inner::<chacha20::R12, chacha20::variants::Legacy>` from
  `rand-0.10.2/src/rngs/thread.rs:56`.
- **`wnaf` 0.14.0 → 0.14.1** changes `le_repr` from *always reverse `to_repr()`*
  (`wnaf-0.14.0/src/lib.rs:197-202`, under `// TODO(tarcieri): determine endianness`) to
  `fe.to_le_repr()` (`wnaf-0.14.1/src/lib.rs:197-199`), which reverses only when the field is
  big-endian (`primefield-0.14.0/src/traits.rs:30-37`); it moves the bound `WnafSize:
  PrimeField` to `PrimeFieldExt` (`src/traits.rs:26`) and adds a `primefield` dependency.
  Compile compatibility is predicted from source, not compiled:
  `primeorder-0.14.0/src/lib.rs:54` already bounds `Scalar: PrimeFieldExt + WnafSize`, and
  `p384`, `primeorder`, `primefield` 0.14.0 and `chacha20poly1305` 0.11.0 are each the newest
  published.

### 1.3 Where each reaches antseal

- **`chacha20` 0.10.1** has two parents (`cargo tree -i chacha20@0.10.1 -e normal --workspace
  --all-features --target all`): `chacha20poly1305 0.11.0` (antseal-core and antseal-cli —
  every unit and manifest ciphertext) and `rand 0.10.2 ← igd-next 0.17.1 ← saorsa-transport
  0.35.1 ← saorsa-core 0.26.2 ← ant-node / ant-protocol ← ant-core 0.5.0 ← antseal-net`.
  `antseal-core`'s graph compiles the features `cipher, xchacha, zeroize`; the all-features
  graph adds `rng`.
  - antseal's XChaCha core is `XChaChaCore<R>(ChaChaCore<R, Ietf>)` with `type Counter = u32`
    (`chacha20-0.10.1/src/xchacha.rs:42,82`), so `:54` is dead code for it, and `rng_inner` is
    not compiled at all in the default and wasm32 graphs.
  - **`:133` is reachable in the `ant-backend` build.** saorsa-transport's `upnp` feature is
    on by default (`saorsa-transport-0.35.1/Cargo.toml`: `default` includes `"upnp"`, and
    `upnp = ["dep:igd-next"]`). When the preferred external port is refused it falls back to
    `add_any_port` (`src/upnp.rs:499-545`). igd-next's `add_any_port` calls
    `common::random_port()` (`igd-next-0.17.1/src/gateway.rs:99,143`,
    `src/aio/gateway.rs:99,154`), which is `rand::rng().random_range(32_768_u16..65_535_u16)`
    (`src/common/mod.rs:9-10`); `rand::rng()`'s core is `chacha20::ChaChaCore<R12, Legacy>`
    (`rand-0.10.2/src/rngs/thread.rs:41`), which runs `rng_inner` on the SSE2 backend. That is
    `#579`'s trace exactly.
  - Runtime dispatch (`chacha20-0.10.1/src/lib.rs:274-285`) takes AVX2, else SSE2, else the
    `soft` backend; targets that are neither x86 nor NEON — wasm32 among them — always take
    `soft`.
- **`wnaf` 0.14.0** sits under `primeorder 0.14.0 ← p384 0.14.0 ← antseal-core`, and so under
  `antseal-wasm` and `wasm-bitmatch` too. `precomputed-tables` is off (`Cargo.toml:358`
  declares `p384` with `ecdsa` and `pkcs8` only; resolved features `arithmetic, digest, ecdsa,
  ecdsa-core, pkcs8, sha2, sha384`), so `p384` uses `primeorder::mul_backend::VariableOnly`
  (`p384-0.14.0/src/arithmetic.rs:46-47`): `ecdsa-0.17.0/src/hazmat.rs:150` calls
  `mul_by_generator_and_mul_add_vartime`, which is `lincomb_vartime`
  (`primeorder-0.14.0/src/mul_backend.rs:31-40`) over `WnafBase`/`WnafScalar`
  (`primeorder-0.14.0/src/projective.rs:525-529`). antseal reaches it from
  `verify_ecdsa_p384` in `crates/antseal-core/src/anchor/tsa.rs:717-731` and
  `crates/antseal-core/src/anchor/chain.rs:1054-1061` — every ECDSA P-384 TSA signature and
  chain link. **P-384's scalar declares `byte_order: primefield::ByteOrder::BigEndian`**
  (`p384-0.14.0/src/arithmetic/scalar.rs:48`), so 0.14.0's unconditional reversal and 0.14.1's
  conditional one produce the same bytes.

### 1.4 The lock delta (P5 in a clone; reproduced by the records lane)

`cargo update -p chacha20@0.10.1 --precise 0.10.2` prints `Updating chacha20 v0.10.1 ->
v0.10.2`, numstat `4 4`: the version and checksum lines, and `"chacha20 0.10.1"` →
`"chacha20 0.10.2"` in the dependency lists of `chacha20poly1305 0.11.0` and `rand 0.10.2`.
`cargo update -p wnaf@0.14.0 --precise 0.14.1` gives numstat `3 2`: version, checksum and `+
"primefield",`. Together `7 6`, in either order, to one lock (sha256 `76e2f7fd5b83…`, from
`HEAD`'s `c98f4c051ac8…`, which is `Q275`'s recorded post-move lock); `[[package]]` 772 → 772.
The `@version` spec is required, because the root lock also carries `chacha20 0.9.1`. Under
`fuzz/` (toolchain `nightly-2026-01-26`, installed) the same two commands give numstat `5 4`,
127 → 127; the pair sits at `fuzz/Cargo.lock:151-154` and `:1171-1174`. `cargo metadata
--locked` exits 0 for both moved locks, and `cargo fetch --locked` for the root; neither lock is
rewritten. The all-features resolve diff (766 nodes) is the two packages and their parents'
edges and nothing else; feature sets are unchanged on both sides, and no `tempfile` edge flips.
The rebuild set is 19 packages under all-features and 11 under default, with no `aws-lc-sys`.
On the moved lock `cargo tree --locked --offline -i chacha20@0.10.1 --workspace
--all-features` answers ``error: package ID specification `chacha20@0.10.1` did not match any
packages`` (exit 101).

### 1.5 What the advisory lane can see

| lock | `deny.toml` | verdict | exit | yanked lines |
| --- | --- | --- | --- | --- |
| `HEAD` | as committed (`yanked` defaults to `warn`) | `advisories ok, bans ok, licenses ok, sources ok` | 0 | 2 × `warning[yanked]`, one for `chacha20` and one for `wnaf` |
| moved | as committed | the same line | 0 | 0 |
| `HEAD` | plus `yanked = "deny"` | `advisories FAILED` | 1 | 2 × `error[yanked]`, the same two crates |
| moved | plus `yanked = "deny"` | `advisories ok` | 0 | 0 |
| `HEAD` | plus `yanked = "deny"` and `{ crate = "chacha20@0.10.1", reason = "… Review by …" }` | `advisories FAILED` | 1 | 1 × `error[yanked]`, `wnaf` only |

Rows 1–2 are P5's, all four checks (`warning[duplicate]` 74 → 74). Rows 3–5 are the records
lane's, `advisories` only, with the key added to a copy of `deny.toml` passed by `--config`.
Every count is of ANSI-stripped output. Row 5 is the per-crate ignore §2 R3 names as the escape
hatch: cargo-deny 0.19.8 honours it per `name@version` (its `docs/src/checks/advisories/cfg.md`
at 0.19.8, line 69). The same page's line 53 states the defect in one sentence: *"`warn`
(default) - Prints a warning … but does not fail the check"*, and the source sets that default at
`cargo-deny-0.19.8/src/advisories/cfg.rs:110` (D183 §1.3). The hosted record agrees: `ci`
run `38788439680`'s `audit-deny` job (wave 36's push) ended `advisories ok, bans ok, licenses ok,
sources ok` beside two `warning[yanked]` (`Q275` Notes). `audit-deny` and `advisory-cron.yml:81`
run `cargo deny --locked check advisories bans sources licenses` at the root only
(`scripts/ci-lanes.sh:2036`), so **`fuzz/Cargo.lock` is scanned by nothing**.

### 1.6 This host, and the shipped module

This host is an Intel Pentium G4400 — `sse2 ssse3 sse4_1 sse4_2`, no `avx`, no `avx2` — so
chacha20's dispatch selects **SSE2** here: the gate's native AEAD golden vectors execute the
**changed** code (`Backend::new` and `save_ctr` on the `Ietf` path), and `wasm-bitmatch`
compares its output byte for byte with wasm32's `soft` backend. The page module built at
`fbcee1e` (stamped `fbcee1e`, decoded from `ANTSEAL_MODULE_B64`) carries `chacha20-0.10.1` once
and `wnaf-0.14.0` twice — on one line, so `grep -c` reads 1 — and `chacha20-0.10.2`,
`wnaf-0.14.1` and the control `chacha20-0.19.7` zero times. `git diff 9c846cb fbcee1e` over every
compile input (`Cargo.lock`, `Cargo.toml`, `fuzz/Cargo.lock`, `crates/antseal-core`,
`crates/antseal-wasm`, `rust-toolchain.toml`, `.cargo`) is empty, so the live module, deployed
from `9c846cb`, carries the same pair. That is an inference: the served bytes were not read.

### 1.7 `P23`'s rc watch

- The pinned `rsa 0.10.0-rc.18` and `cms 0.3.0-pre.2` are not yanked, and nor are the newer
  `rsa 0.10.0-rc.19` (2026-10-06) and `cms 0.3.0-rc.0` (2026-10-13).
- `rsa` rc.19 is a `pkcs1` rc.5 migration plus a regression test, with no private-key code
  change. RUSTSEC-2023-0071 still has `patched = []` (*"Still affected as of 2026-09-12 … rsa
  0.10.0-rc.18"*), so the ignore stands. Against the pin, `rsa =0.10.0-rc.19` exits 101 —
  *failed to select a version for `der` … required by package `pkcs1 v0.8.0-rc.5` … previously
  selected package `der v0.8.1`*. With `der =0.8.2` it resolves: `der` 0.8.1 → 0.8.2, `pkcs1`
  rc.4 → rc.5, `rsa` rc.18 → rc.19, `spki` 0.8.0 → 0.8.1, numstat `22 22`, 772 packages.
- `cms` rc.0 moves the lock `3 3` (`tempfile`'s `getrandom` edge) and changes
  `CertificateChoices::Other`'s `[3]` from `tag_mode = "EXPLICIT"` to `"IMPLICIT"`
  (`cms-0.3.0-rc.0/src/cert.rs:32`; `pre.2` reads EXPLICIT at the same line) — a parse on the
  verdict path. Its new `default = ["pem"]` stays off under antseal's `default-features =
  false`.
- A grep of `HEAD` for any record of an rc.19 or rc.0 re-verification finds only the two
  policy-row phrases.

### 1.8 Ownership

`git grep -n -w wnaf HEAD -- . ':!Cargo.lock'` finds D60's pin record (`:256`, `:301`),
`fuzz/Cargo.lock`, the `core-dep-graph` allowlist (`scripts/ci-lanes.sh:406`) and `Q275` — no
`deny.toml` entry, and no row but `Q275`.

## 2. RULING

### §2 R1 — Both move this wave, as one dependency-policy §4 event, with no manifest change

`cargo update -p chacha20@0.10.1 --precise 0.10.2` and `cargo update -p wnaf@0.14.0 --precise
0.14.1`: `Cargo.lock` 7+/6− (772 → 772 packages), `fuzz/Cargo.lock` 5+/4− (127 → 127). No
`Cargo.toml` changes: `chacha20poly1305 =0.11.0` and `p384 =0.14.0` stay, and `Cargo.toml:431`'s
*"versions are frozen by Cargo.lock"* stays true. What decides it:

- `chacha20` 0.10.1's yank reason — an SSE4.1 intrinsic in the SSE2 backend's `rng_inner` — is
  reachable in the shipped `ant-backend` CLI through saorsa-transport's UPnP fallback, igd-next
  and `rand::rng()`; on an x86 CPU with neither AVX2 nor SSE4.1 it is a SIGILL.
- `wnaf` 0.14.0's `le_repr` bug is on the P-384 TSA verify path and value-identical for
  big-endian P-384, so the move should change no verdict — which §3 G5's `tsa-freetsa-p384`
  vector checks.
- This host has no AVX2: the gate's native AEAD vectors run the changed SSE2 code, and
  `wasm-bitmatch` compares it with wasm32's `soft` backend.
- The delta is exactly 13 + 9 lock lines, and leaving the pair relies on a yank detector that
  cannot fire (§1.5).

§4's checklist for a crate that is not `ant-core` is answered by §1.2 (changelog), §1.1 and §1.5
(RUSTSEC) and §3 G5–G6 (every committed vector byte-exact).

### §2 R2 — `fuzz/Cargo.lock` moves in the same act

It carries the same pair (`:151-154`, `:1171-1174`), and nothing scans it for advisories (§1.5).
A move that leaves it behind keeps the yanked versions in the tree with no instrument watching
them.

### §2 R3 — `yanked = "deny"`, in the same act as the lock moves, never before

`deny.toml`'s `[advisories]` gains `yanked = "deny"`, with a comment citing `Q278`, in the same
act as R1–R2. **Never before**: on the `HEAD` lock that key alone reds `audit-deny` (§1.5 row 3).
It costs nothing on the moved lock (§1.5 row 4) and makes `P23`'s yank watch an instrument. From
that act, an upstream yank of any locked version anywhere in the all-features scan
(`deny.toml:29`) — a pinned rc included — reds the required `audit-deny` context (per pull
request and on push to `main`) and the weekly `advisory-cron`, until a reviewed move (§4) or a review-dated per-crate ignore,
`{ crate = "name@version", reason = "<justification>. Review by YYYY-MM-DD." }`, under D19's
ignore discipline. This changes D19's *"defaults kept"* for `yanked` alone; D19 takes a dated
addendum.

### §2 R4 — No redeploy is owed

The live module, deployed from `9c846cb`, carries `chacha20 0.10.1` and `wnaf 0.14.0` (§1.6).
Neither yank reason reaches wasm32: chacha20 takes the `soft` backend there, and P-384's scalar is
big-endian. Every commit moves the module digest anyway (`docs/ci-verification.md:2767-2779`,
D135 §1.5's `ANTSEAL_SOURCE_COMMIT` stamp). The next consented Pages dispatch carries the new
pair, and §3 G7 is what a rebuild shows.

### §2 R5 — `P23`: a dated note, no move

*"Re-verify at each rc"* (`docs/dependency-policy.md`, the `cms` row) is three checks: (i) the
yanked status of each pinned rc; (ii) the RUSTSEC/GHSA status of the new rc; (iii) the lock delta
the next reviewed bump would carry. They are recorded for rc.19 and rc.0 per §1.7, with (ii)
for RUSTSEC only (the GHSA half is in §4): the pinned rc.18 and pre.2 are not yanked; rc.19
cannot resolve against `der =0.8.1`; cms rc.0 changes a verdict-path parse (`[3]` EXPLICIT →
IMPLICIT); RUSTSEC-2023-0071 is still unpatched. The trigger stays the final releases, or an
advisory or a yank on a pinned rc — the yank half an instrument from R3. Two dated
corrections: `P23`'s Problem (*"`cargo deny`'s `yanked` check is on by default, so the first
symptom would be a red advisory lane"*, `tasks/P.md:309`) and D60 §8.1 (*"`cargo deny`'s
`yanked` check is on"*) were false under `warn` and are true after R3.

### §2 R6 — A new row owns the move; `Q275` gets a pointer

**`Q278`** owns R1–R3. `Q275`'s Do (d) residue is discharged by `Q278`, recorded as a dated
pointer on `Q275`. If the move reaches `main` before the `advisory-cron` run of Mon 2026-10-19
06:17 UTC, that run shows no yanked warning rather than two; either way `Q275` needs only its
verdict line.

### §2 Execution — the orchestrator's act, at the close

Executed by the orchestrator at the close of wave 37, **after L-TOOL's `deny.toml` edits (D183)
land**, before the final commit: R1's two commands at the root and under `fuzz/`, R3's key, and
the evidence G1–G7 (§3), written into `Q278` in the act that ticks it.

## 3. Fault plants

Green baselines first; every verdict is judged by its message on ANSI-stripped output; `touch`
after every restore.

**Green predictions, owed at execution:**

- **G1** — `git diff --numstat` reads `7 6` for `Cargo.lock` and `5 4` for `fuzz/Cargo.lock`;
  `[[package]]` 772 and 127; nothing under `testdata/` or `docs/format/` changes. *Pre-measured
  in a clone (§1.4).*
- **G2** — `cargo tree --locked --offline -i chacha20@0.10.1 --workspace --all-features` answers
  *did not match any packages*. Cargo exits 101 with that answer; the message is the verdict.
  *Pre-measured (§1.4).*
- **G3** — `cargo metadata --locked` and `cargo fetch --locked` exit 0 at the root and under
  `fuzz/`, and neither lock is rewritten.
- **G4** — `./scripts/ci-lanes.sh audit-deny` exits 0 and ends `advisories ok, bans ok, licenses
  ok, sources ok`, with zero `warning[yanked]` and zero `error[yanked]`. It is read on the tree
  that carries D183's `deny.toml` edits, so a red for any other reason is judged by its message
  and owned by its own record. *The yanked half pre-measured (§1.5 row 4).*
- **G5** — the gate with `ANTSEAL_GATE_BASE=origin/main ANTSEAL_GATE_HEAVY=1
  ANTSEAL_GATE_E2E=1`: `test` PASS, with the AEAD golden vectors byte-exact and
  `tsa-freetsa-p384` still `proven`; `wasm32-tests` and `wasm-bitmatch` PASS, **not `n/a`** (both
  trigger lists name `Cargo.lock`: `scripts/wasm-tests.sh:121-125`,
  `scripts/wasm-bitmatch.sh:157`); `verifier-page` PASS; the heavy tier's log shows `Compiling
  chacha20 v0.10.2` and `Compiling wnaf v0.14.1`; `e2e-devnet` PASS; this host's CPU flags quoted
  beside the verdicts.
- **G6** — by hand, because the gate does not run them: `./scripts/ci-lanes.sh golden-vectors`
  and `./scripts/ci-lanes.sh tamper-matrix`, their counters quoted, and
  `scripts/reproducible-build.sh --compare` green (about 150 s).
- **G7** — the rebuilt page's module, counted by occurrence: `chacha20-0.10.2` ≥ 1,
  `chacha20-0.10.1` = 0, `wnaf-0.14.1` ≥ 1, `wnaf-0.14.0` = 0, and the control `chacha20-0.19.7`
  = 0.

**Plants:**

- **P1** — copy the pre-move `Cargo.lock` back. Under R3: 2 × `error[yanked]` naming `chacha20`
  and `wnaf`, `advisories FAILED`, exit 1 (pre-measured, §1.5 row 3). Under `warn` only a count
  would move, which is why R3 exists. Restore by re-running R1's commands, compare with `cmp`
  against the moved lock, `touch`.
- **P2** — run G7's counts against a module built before the move: they must read the old
  strings (`chacha20-0.10.1` 1, `wnaf-0.14.0` 2; §1.6 shows exactly this on the `fbcee1e` page),
  proving G7 can fail and that a stale page cannot pass it.
- **P3** — `scripts/wasm-bitmatch.sh --self-test` first: the comparison must go red on its
  injected divergence before its green on the moved graph counts.

**Checks that cannot fail for this change** (P5's list; the last item added by the records lane
from R2's premise):

- `vector-freeze` and `format-freeze`: no frozen file moves.
- `core-dep-graph`'s allowlist (`scripts/ci-lanes.sh:400-406`, `:436-438`): it lists names, and
  only versions move.
- `audit-deny`'s verdict word under `warn` (§1.5) — R3 is what gives the lane a red.
- Hosted AEAD vectors on AVX2 runners: they select the AVX2 backend and never run the changed
  SSE2 code. This host is the SSE2 witness.
- `e2e-devnet` for the RNG path: `add_any_port` needs a LAN UPnP gateway that refuses the
  preferred port, and a loopback devnet has none.
- A planted pre-move `fuzz/Cargo.lock`: nothing scans it (§1.5), so no lane can go red. Its
  witnesses are G1's numstat and G3's exit codes.

## 4. What this record does NOT decide

- **The hosted runners' CPU.** If they have AVX2, the hosted `test` lane never runs chacha20's
  SSE2 path; the SSE2 witness is this host's.
- **Whether the client ever reaches `add_any_port`.** The reachability is a code path, not an
  observation.
- **That the moved graph compiles, and the post-move module digest.** G5 and G7 establish them
  at execution; P5 built nothing.
- **The bytes antseal.org serves.** §1.6's *"the live module carries the pair"* is inferred.
- **Whether any of the nine real TSA tokens uses `[3]` `CertificateChoices`** — the question a
  future `cms` bump review must answer (`P23`).
- **Upstream's reason for calling a value fix "a breaking bounds change".**
- **A GHSA/osv sweep of `rsa` rc.19 and `cms` rc.0.** §1.7 checked RUSTSEC only; D19's amendment
  makes the GHSA/osv sweep part of `Q10`'s weekly operation.
- **Whether the act takes a commit of its own.** P5 proposed one; the ruling fixes the order —
  after D183's `deny.toml` edits land, before the final commit — and R3's same-act rule. §4's
  *"its own PR"* presumes a PR flow this repository does not use; `Q275`'s four-crate move rode
  wave 36's `c36949f`.
- **How D183 §2 R3's review-date checker reads a `crate = "name@version"` ignore.** That is
  D183's lane's to define; this record requires only that such an entry carries a review date.
- **Scanning `fuzz/Cargo.lock` for advisories.** Not ruled: R2 keeps it in lockstep by hand, and
  the dependency policy says so.

## 5. Edit list — per write scope, with the lane named

### The orchestrator — §2 R1–R3, at the close (after L-TOOL's `deny.toml` edits land, before the final commit)

- `Cargo.lock`: R1's two commands — the §1.4 lines only.
- `fuzz/Cargo.lock`: the same two commands under `fuzz/` (R2).
- `deny.toml`: the `yanked = "deny"` key under `[advisories]` with a comment citing `Q278` and
  D184 (R3), and the `[advisories]` header comment (*"Defaults deliberately kept: …"*,
  `deny.toml:38` at `HEAD`) no longer saying the `yanked` default is kept. `deny.toml` is a
  `task-citations` scan root, so `Q278` is registered in
  `tasks/Q.md` and `TODO.md` in the same commit.
- §3's G1–G7 and P1–P3, captured into `Q278` in the act that ticks it.

### DOCS lane — `docs/dependency-policy.md`

- Dated brackets on §1's AEAD-stack row (`chacha20` 0.10.1 → 0.10.2 under `chacha20poly1305
  =0.11.0`: lock-only, with the yank reason and its `ant-backend`-only reach) and its `p384` row
  (`wnaf` 0.14.0 → 0.14.1 under `p384 =0.14.0`: lock-only, value-identical for P-384) — R1; and
  on the `cms` and `rsa` rows, §2 R5's re-verification at rc.0 and rc.19 and the unchanged
  trigger.
- One sentence in the fuzz bullet of *Enforcement & cross-references* (`:404-409`):
  `fuzz/Cargo.lock` moves in lockstep with `Cargo.lock` for every crate the two share, because no
  lane scans it for advisories (R2).

### Registrar — the orchestrator: `TODO.md`, `tasks/Q.md`, `tasks/P.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, dated addenda

- Mint **`Q278`** (row and entry) per R6.
- `Q275`: the dated pointer (R6), in its Notes and on its register row.
- `P23`: the dated note (R5) — the re-verification and the correction of its Problem's yank
  sentence — in `tasks/P.md` and on its register row.
- Dated addenda on **D19** (`yanked` leaves the defaults) and **D60** §8.1.
- `docs/instrument-ledger.md`: one entry attributed to D184 — cargo-deny's default `yanked =
  "warn"` cannot fail the check, so two crates yanked since 2026-08-27 and 2026-09-03 could
  never turn the advisory lane red (its colour in those weeks was decided by other findings),
  and D60 §8.1's *"check is on"* and `P23`'s *"first symptom would be a red advisory lane"*
  were false under it.
- This record's index row and register row.

### Not touched

`Cargo.toml` and every other manifest; `testdata/`; `docs/format/`.

## 6. As built — wave 37, the orchestrator's act (recorded in place before this record was first committed)

Executed after the S41 run, so that the closing gate's own log shows the moved crates compiling (§3
G5). Every verdict below was read from an exit file, on output with ANSI codes stripped.

- **The premise, re-measured at landing.** On the sparse index, `chacha20` 0.10.0 and 0.10.1 are
  yanked and 0.10.2 is not; `wnaf` 0.14.0 is yanked and 0.14.1 is not.
- **G1.** `cargo update -p chacha20@0.10.1 --precise 0.10.2` and `cargo update -p wnaf@0.14.0
  --precise 0.14.1`, at the root and under `fuzz/`, all `rc=0`. `git diff --numstat` reads `7 6
  Cargo.lock` and `5 4 fuzz/Cargo.lock`, with 772 and 127 `[[package]]`. Nothing under `testdata/`
  or `docs/format/` moved. (`wnaf` 0.14.1 adds a dependency edge on `primefield`, already in the
  lock.)
- **G2.** `cargo tree --locked --offline -i chacha20@0.10.1 --workspace --all-features` and the
  same for `wnaf@0.14.0` both answer *"package ID specification … did not match any packages"*
  (exit 101). `chacha20 v0.10.2` sits under `chacha20poly1305 v0.11.0`.
- **G3.** `cargo metadata --locked` and `cargo fetch --locked` exit 0 at the root and under
  `fuzz/`, and neither lock was rewritten (sha256 re-checked).
- **§2 R3's "it costs nothing on the moved lock" was already false at execution.** With `yanked =
  "deny"` set, `./scripts/ci-lanes.sh audit-deny` on the moved lock exited 1. The cause was
  `error[yanked]: detected yanked crate (try `cargo update -p zip`)` for `zip 2.4.2`, yanked at
  2026-10-16T03:35:15Z, about two hours after planning measured exactly two yanked crates.
  - crates.io now marks every `zip` 2.x release and every 9.x release but 9.0.3 yanked, with no
    yank message. The RUSTSEC database carried no advisory against it.
  - `ant-core =0.5.0` and `ant-node 0.15.0` both require `zip = "2"`, so no lock-only move exists.
  - Upstream calls it only in `ant-core`'s node-binary installer and `ant-node`'s self-upgrade;
    antseal calls neither. It is absent from `antseal-core`'s graph and the wasm32 graph.

  The instrument did what §2 R3 built it to do. The ruled disposition was taken: a review-dated
  per-crate ignore (`{ crate = "zip@2.4.2", … Review by 2026-11-16 … }`), owned by **`Q280`**,
  minted in the same act. In cargo-deny 0.19.8 a crate-form entry lands in `ignore_yanked`
  (`src/advisories/cfg.rs:165-200`), so it silences the yank only.
- **G4.** With that entry, `audit-deny` exits 0 and ends `advisories ok, bans ok, licenses ok,
  sources ok`, with 0 `warning[yanked]` and 0 `error[yanked]`. `scripts/check-deny-reviews.py`
  is green: 8 entries, the next due 2026-11-16.
- **P1.** The pre-move `Cargo.lock` copied back gave `error[yanked]` for `chacha20` and for `wnaf`,
  `advisories FAILED`, exit 1. The moved lock was restored (`cmp` equal, touched).
- **The `zip` entry, planted.** Dropping it reds `error[yanked]` for `zip` with `advisories FAILED`,
  exit 1. `deny.toml` was restored (`cmp` equal, touched).
- **P2, before any rebuild.** The page module built at `fbcee1e` (`b9f84e3d…`) reads
  `chacha20-0.10.1` ×1, `wnaf-0.14.0` ×2, `chacha20-0.10.2` ×0, `wnaf-0.14.1` ×0 and the control
  `chacha20-0.19.7` ×0, as §1.6 predicted. So G7's count can fail.
- **`deny.toml`'s header** no longer calls a yank merely a warning. The new key carries its comment,
  citing `Q278`.
- **G5–G7 and P3** are the closing gate's and the post-commit rebuild's. They are recorded on `Q278`
  by the commit that carries the gate.

## Closing — this record is not consent

It moves two lockfiles and one `deny.toml` key inside the wave's own commits. It pushes nothing,
dispatches nothing and redeploys nothing. The push that carries it to `main` — and with it the
first hosted `audit-deny` under `yanked = "deny"` — needs the maintainer's express consent naming
the action, the destination and the account, like every push. §2 R4 owes no Pages dispatch.

## Addendum — 2026-10-16 (wave 37 close): G5–G7 and P3, measured

§6 left G5–G7 and P3 to the closing gate and the rebuild after the commit. They are recorded on `Q278`, which ticked on them:

- **G5:** the gate at `477e0a6` with the heavy tier and the devnet E2E forced exited 0. All 46 lanes passed, `wasm32-tests` and `wasm-bitmatch` among them (neither `n/a`), and `e2e-devnet: PASS commit=477e0a6 nodes=14 suites_run=4 failed=[] pending=[] secs=963 anvil=1.5.1-stable`.
  - The gate keeps no output for a passing lane, so G5's *"the heavy tier's log shows `Compiling chacha20 v0.10.2`"* has no log to read. Cargo's dep-info files written inside the gate window stand in: 8 `chacha20-0.10.2` units and 6 `wnaf-0.14.1` units, and none of the old versions.
  - The host is a Pentium G4400 (SSE4.1, no AVX2).
- **G6:** 92 golden-vector tests matched, including both AEAD vectors and the anchor-vector regeneration whose first vector is `tsa-freetsa-p384`, `proven`. The tamper matrix passed 38 tests. The two-environment comparison was reproducible: `dd00e186…f2f6` (1 879 147 B), in 114 s.
- **G7:** the rebuilt module counts `chacha20-0.10.2` ×1, `chacha20-0.10.1` ×0, `wnaf-0.14.1` ×2, `wnaf-0.14.0` ×0, and the control `chacha20-0.19.7` ×0.
- **P3:** the gate's `bitmatch-inject` lane (`wasm-bitmatch.sh --self-test`) passed before `wasm-bitmatch --check`.

Nothing else in this record changes.

## Addendum — 2026-10-17: the advisories behind the `zip` yank, and a hosted yank check that reads a stale index

The first hosted run after the consented push of `fbcee1e..5050f5b` (`ci` run `38984904528` at `5050f5b`) reddened `audit-deny` on three advisories against `zip 2.4.2`: RUSTSEC-2026-0367, -0368 and -0369. Each is patched only at `>= 9.0.0`, and all three were added to the database after §6's act. §6's crate-form ignore silences the yank only, as its own comment says, so each advisory needs its own id. Three review-dated id ignores landed locally. `Q280` owns them, and a plant proves each one load-bearing. Nothing in the graph calls the affected extraction APIs. The measurements are on `Q280`.

The same run printed `warning[yanked-not-detected]` for the `zip@2.4.2` entry. cargo-deny takes yank state from cargo's local index cache, and both hosted venues restore an older one. §2 R3's *"an upstream yank of any locked version … reds the required `audit-deny` context (per pull request and on push to `main`) and the weekly `advisory-cron`"* therefore holds only where that cache is fresh. This is ledgered under rule 8 (`docs/instrument-ledger.md`, 2026-10-17). The fix changes two workflows and goes to the next planning round.

Nothing else in this record changes.
