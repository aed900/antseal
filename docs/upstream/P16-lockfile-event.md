# P16 — the M1 lockfile event: 128 → 736 packages (ant-core's graph + the devnet subtree)

- **Date: 2026-08-01** (M1 wave 1, lane γ — P16 execution)
- **Kind: deliberate dependency-review record under P7 §4** (docs/dependency-policy.md).
  This is THE M1 lockfile event pre-recorded by the P16 feasibility memo
  (docs/research/P16-devnet-feasibility.md §5) and by tasks/P.md P16's accept
  ("executed as ONE deliberate joint P7 §4 review"): one review, one
  changelog/RUSTSEC sweep, covering **both** the ant-core base graph and the
  ant-node devnet subtree — S6's later adapter edge in `antseal-net` re-uses
  this locked graph and this record rather than re-running the event.
- **Trigger:** the new never-published workspace member `crates/devnet-launcher`
  declares `ant-core = { workspace = true, features = ["devnet"] }` +
  `ant-node = { workspace = true }` as **optional deps behind its non-default
  `devnet` feature**. Cargo.lock records the union of all member features, so
  the full graph enters the lock while default `--workspace` lanes compile
  none of it (§5).

## 1. The numbers

| State | `[[package]]` entries |
| --- | --- |
| before (commit 96f1367, P15) | **128** |
| fresh resolve (adding the launcher's edges) | 725 |
| after the tested-set precise-pins (§2) | **736** (+608 vs before) |

The memo's static probe predicted 652/688 for a bare scratch manifest; on top
of our own 128-package workspace (81 overlapping names) the union lands at
736. None of the heavy stack (tokio, reqwest, alloy, saorsa-core, heed,
self_encryption, evmlib) existed in the lock before this event.

**`ant-node = "=0.15.0"` exact pin** (workspace manifest + policy §1 row,
landed with this event): ant-core 0.5.0's own requirement is caret `0.15.0`,
deterministic on 2026-08-01 only because no other 0.15.x exists and 0.16.0
(2026-07-29) is outside the caret — the day upstream ships 0.15.1, an
unpinned fresh resolve would silently move the entire node stack. The pin is
network-consensus-affecting by the project's own definition and was
recommended by the memo **before** the lock landed.

## 2. The tested-set decision (the saorsa-core drift, decided)

ant-core 0.5.0's **packaged Cargo.lock** (inside the sha256-verified crate
archive, P9 §3) is the graph upstream built and tested the release against.
A fresh caret resolve today is not that graph. The memo left one decision
open: accept the drift or `cargo update --precise` back. **Decision:
precise-pin the first-party protocol family back to upstream's tested set;
accept fresh patch-drift in the third-party substrate.** Executed:

| Crate | fresh resolve | upstream tested | action |
| --- | --- | --- | --- |
| `ant-protocol` | 2.3.1 | 2.3.0 | `cargo update -p ant-protocol --precise 2.3.0` |
| `saorsa-core` | 0.26.4 | 0.26.2 | `--precise 0.26.2` |
| `saorsa-transport` | 0.35.3 | 0.35.1 | `--precise 0.35.1` (rippled in by saorsa-core's downgrade) |

**Why this is not merely tidy — the drift is coupled:** `ant-protocol 2.3.1`
*requires* `saorsa-core ^0.26.4` (the precise-pin attempt failed until
ant-protocol went first, proving it). Upstream's patch release drags the
whole saorsa line past the set ant-core 0.5.0/ant-node 0.15.0 shipped
against; accepting "just a patch bump" of ant-protocol would have forced an
untested transport pairing. The unwind order — **ant-protocol → saorsa-core
→ saorsa-transport** — is load-bearing; the next ant-core bump review reuses
it. Ripples accepted from saorsa-core 0.26.2's own requirements: `nix`
0.31.3→0.29.0, `unicode-width` 0.2.2→0.2.0, and +14 package entries
(older-generation duplicates re-enter, e.g. extra `windows-*`).

**Verified end state — first-party family at exactly the tested versions:**
`ant-core 0.5.0`, `ant-node 0.15.0`, `ant-protocol 2.3.0`, `ant-merkle
1.5.1`, `saorsa-core 0.26.2`, `saorsa-transport 0.35.1`, `saorsa-pqc 0.4.2 +
0.5.1` (upstream's own dual set), `self_encryption 0.36.0` (transitive only —
D35 prohibition, recorded per policy §4), `evmlib 0.9.0`, `blake3 1.8.5`
(= the P15 workspace pin, so S4's future direct edge changes nothing in the
lock), `heed 0.22.1`.

**Accepted drift, with reasons:**

- *Third-party QUIC/TLS substrate*: `quinn 0.11.11` / `quinn-proto 0.11.16` /
  `quinn-udp 0.5.15` / `rustls 0.23.43` (tested: 0.11.9/0.11.15/0.5.14/
  0.23.40). Mature, conservatively-patched infrastructure whose patch
  releases carry the security fixes we want; the caret ranges of the — now
  tested-set-matched — first-party layer span both; the advisory lane, not
  version archaeology, is the control here.
- *Utility tier*: 165 further name-level drifts (futures 0.3.33, libc,
  syn…), several FORCED by our own exact pins winning unification (`serde
  1.0.229`, `serde_json 1.0.151`, `thiserror 2.0.19`, `zeroize 1.9.0` — all
  inside upstream's caret ranges, so ONE copy serves both worlds).
- *Names only in our lock* (21): the four antseal crates + wasm-bitmatch +
  devnet-launcher, our pinned stack upstream lacks (`minicbor`, `ml-dsa`,
  `unicode-normalization`, `rand_pcg` via proptest), and ML-DSA/PQC
  transitives (`module-lattice`, `shake`, `sponge-cursor`, `cmov`, …).

## 3. The duplicate-major wave (bans: ok, 60 warnings — expected, recorded)

`cargo deny check bans` emits **60 `duplicate` warnings**, warn-level by
P13's recorded choice (deny.toml `[bans] multiple-versions = "warn"`; D19).
This IS the wave the memo pre-recorded — do **not** "fix" it ad hoc:

- `reqwest` 0.12 (ant-core) + 0.13 (ant-node);
- the RustCrypto generation split — our pinned 0.11/0.13 generation
  (`sha2`, `hkdf`, `hmac`, `chacha20poly1305`, `aead`, `cipher`, `digest`,
  `block-buffer`, …) beside upstream's 0.10/0.12 generation;
- `ed25519`/`ed25519-dalek`/`signature`/`curve25519-dalek` 2.x-vs-3/5
  (our D13 pins beside upstream's);
- `rand`/`rand_core`/`getrandom` triples; `windows-*` quads; `syn` 1+2+3.

Q10 (permanent operation) owns revisiting the warn level now that the M1
graph is real.

## 4. Advisory sweep (cargo-deny 0.19.8, RUSTSEC DB of 2026-08-01)

`cargo deny --locked check advisories bans sources` on the 736-package lock:
**four findings, all `unmaintained`-class, zero vulnerability-class. No
blocker.** Disposition per D19's ignore discipline (justification + review
date in `deny.toml`; re-assess or expire by the review date):

| ID | Crate | Enters via | Assessment |
| --- | --- | --- | --- |
| RUSTSEC-2023-0089 | `atomic-polyfill` 1.0.3 | heapless 0.7 ← postcard ← ant-core/ant-node | Polyfill selects real core atomics on every target we build (x86_64, wasm32); embedded-target shim code is dead here. Fix = upstream moving to heapless 0.8/portable-atomic; an ant-core-bump item |
| RUSTSEC-2025-0141 | `bincode` 1.3.3 | heed-types ← heed ← ant-node | Its own team declares 1.3.3 complete/final. No antseal byte is bincode-serialized (D7: minicbor only); devnet LMDB values are upstream's format on a throwaway local store |
| RUSTSEC-2024-0436 | `paste` 1.0.15 | alloy-sol-macro-input (evmlib/alloy) | Proc-macro: compile-time only, zero runtime code in any binary; archived-not-vulnerable; alloy upstream tracks the replacement |
| RUSTSEC-2025-0134 | `rustls-pemfile` 2.2.0 | saorsa-transport ← saorsa-core | Per the advisory itself, a thin wrapper around the SAME parsing code maintained in rustls-pki-types ≥1.9 (also in this graph); touches transport TLS material only, never antseal formats |

`sources`: ok — crates.io is the sole registry across all 736 packages.
GPL boundary unchanged from P9 §3/D6: `self_encryption` and `evmlib` are the
two GPL-3.0 residents, transitive under ant-core, compiled only behind the
launcher's feature today and behind `antseal-net`'s S6 adapter tomorrow —
never near antseal-core or the verifier page (D35; the dep-graph lane now
proves the direct-dependency half on every run).

## 5. Containment proof (default lanes unchanged)

- `cargo tree --workspace -e normal --prefix none --locked | sort -u`:
  **96 entries at 96f1367 → 97 after** — the single addition is
  `devnet-launcher v0.0.0` itself (the featureless stub). Zero third-party
  packages entered any default build graph.
- `cargo test --workspace --locked` compiles the stub only; suite runtime is
  unchanged (see the P16 commit gates). Only
  `scripts/devnet/local-up` (`cargo build --release -p devnet-launcher
  --features devnet`) compiles the heavy graph. P20 turns this containment
  into a standing CI assertion.
- Cost note, eyes open: lanes that RESOLVE the full union (`audit-deny`; the
  dep-graph lane's inverse-parent check, which runs `cargo tree
  --all-features`) now read ~700 manifests — a fetch-and-cache cost on fresh
  CI runners, not a compile cost.

## 6. Footguns and instructions for the next bump review

1. **Stale-sparse-index footgun** (memo §5, reproduced during the feasibility
   probe): a stale local sparse-index cache can serve a pre-2026-07-23
   ant-node listing and fail the resolve with what LOOKS like a yank but is
   not. Refresh the index (any `cargo update --dry-run -p ant-node`, or
   remove the sparse cache entry under `~/.cargo/registry/index/`) before
   concluding anything about upstream.
2. **Bump procedure** for this graph (policy §4 + this record): bump
   ant-core and ant-node together (ant-node must satisfy ant-core's
   requirement); re-extract the new packaged lock; re-run the §2 tested-set
   diff and precise-pin the first-party family in the §2 unwind order;
   re-record the transitive `self_encryption` version (D35 — recorded, never
   pinned); re-run the deny sweep and re-assess the §4 ignores (they expire
   2026-11-01).
3. **blake3 at S4**: the direct edge S4 adds resolves to the already-locked
   1.8.5 — no lock movement expected; if the lock moves, stop and look.
