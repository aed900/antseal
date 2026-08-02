# P — Project setup, toolchain & dependency governance

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### P1 — Finalize the product name (upstream blessing or non-ant rename)
- Milestone: pre-M0
- Size: M
- Deps: none (start immediately — longest-latency item in the project)
- Spec: Working name / pre-M0 task (MVP-SPEC.md lines 3, 97)
- Do: Decide the final product name. The `ant-` prefix reads as official Autonomi tooling (upstream's binaries are `ant`/`antnode`), so either obtain written blessing from the WithAutonomi/Saorsa upstream (issue, email, or governance channel — keep the artifact) for an ant-prefixed name, or select a non-ant name. Enumerate every name-bearing identifier the decision propagates into — crate names, CLI binary name, vault dir (`~/.antseal/`), the M0-frozen signature context string (`"antseal-manifest-v1"`), format/domain strings, verifier domain, repo/org name — and hand the final name plus that checklist to the owning domains before any M0 freeze.
- Accept:
  - A written decision record exists: either upstream's written blessing (link/copy archived in-repo) or a chosen non-ant name with rationale
  - The identifier-propagation checklist is committed and each item has a named owning domain (C: context string, F: format strings, U: vault dir/binary, P: crates/domain/repo)
  - Decision lands before P2/P3 execute and before the M0 Definitions freeze (the signature context string embeds the name and is frozen permanently at M0)
- Notes: Spec says "rename freely" — but only until M0 freeze; after that the name is baked into a permanent format. Upstream response latency is the risk: set a deadline after which the non-ant fallback is chosen unilaterally.

### P2 — Reserve crates.io names
- Milestone: pre-M0
- Size: S
- Deps: P1
- Spec: Working name (MVP-SPEC.md line 3)
- Do: Reserve the chosen crate names on crates.io by publishing 0.0.0 placeholder versions (crates.io has no reservation mechanism other than publishing) from the maintainer's account: the product name plus `<name>-core`, `<name>-anchor`, `<name>-net`, `<name>-cli`. At execution time, re-verify availability: `antseal` was free as of 2026-07-27; `seal-core`/`seal-cli` are taken by an unrelated project (which is why the spec uses the `antseal-*` prefix) — confirm this is still the state and that no squatter has taken `antseal` since.
- Accept:
  - All chosen crate names show the maintainer account as owner on crates.io
  - Placeholder publishes recorded (versions, date); note filed that crates.io publishes are permanent (yank hides but keeps the name claimed)
  - If `antseal` (or the chosen name) is no longer free at execution time, this feeds back into P1 as a forced re-decision
- Notes: Open decision to record (spec tree is normative, so record disagreement only): whether the CLI crate should eventually publish as the bare product name so `cargo install antseal` works, vs. the spec's `antseal-cli` crate + `antseal` binary. Reserve both names either way.

### P3 — Check and register the verifier domain
- Milestone: pre-M0
- Size: S
- Deps: P1
- Spec: Working name; Page provenance (MVP-SPEC.md lines 3, 139)
- Do: Check availability of a domain matching the final name for the static verifier page, register it, and enable auto-renew under maintainer control. This domain becomes the substrate for the one canonical URL that all docs and the CLI `reveal` output will print (the canonical-URL string itself and page hosting/deploy are R's M3 work).
- Accept:
  - Domain registered, auto-renew on, registrar/account access documented for the maintainer
  - Registration record handed to R for the M3 canonical-URL/page-hosting deliverable
  - If the natural domain is taken, the finding feeds back into P1 before the name is frozen
- Notes: The canonical URL is a trust point (malicious-host mitigation, spec line 139/186) — losing the domain later is a provenance incident; document renewal ownership.

### P4 — Git init and remote repo hosting
- Milestone: pre-M0
- Size: S
- Deps: P1 (soft — placeholder name acceptable until publish/freeze)
- Spec: Architecture — "greenfield in /home/deb/Documents/code0" (MVP-SPEC.md lines 40–58)
- Do: Initialize the git repository (the directory is not a repo today), make the initial commit containing `MVP-SPEC.md`, `MVP-SPEC.orig.md`, and `SPEC-REVIEW.md`, create the remote repository on the chosen hosting platform, and push. Settle the layout question first: whether `/home/deb/Documents/code0` itself is the workspace root or contains an `antseal/` subdirectory (the spec's tree is rooted at `antseal/`).
- Accept:
  - `git log` shows an initial commit with the spec files; remote configured and pushed; default branch set
  - Layout decision (repo root vs `antseal/` subdir) recorded and reflected in the tree
  - Hosting platform decision recorded (CI provider in P8 depends on it)
- Notes: GitHub + Actions is the working assumption (`gh` tooling, Actions cron for P13/P19); record if a different platform is chosen. Org/repo name follows P1.

### P5 — Cargo workspace scaffold per the Architecture tree
- Milestone: pre-M0
- Size: M
- Deps: P4; F: crate-internal module layout beyond stubs; R: verifier-web page content (M3)
- Spec: Architecture (MVP-SPEC.md lines 40–58)
- Do: Create the Cargo workspace exactly per spec lines 44–58: `crates/antseal-core` (lib; pure logic, WASM-safe — no I/O, no tokio in its normal-dependency graph), `crates/antseal-anchor`, `crates/antseal-net`, `crates/antseal-cli` (binary target named `antseal`), plus top-level `verifier-web/` (static-page stub — plain HTML placeholder, no framework, no build tooling beyond what wasm-pack will need) and `testdata/` (directory with a README describing intended layout: golden vectors, UTF-8 corpus, tamper matrix, fine-tree range-proof fixtures — fixture content is F/G/Q's). Configure: `[workspace.dependencies]` as the single version-declaration point (substrate for P7's pin governance), `[workspace.lints]` (rust + clippy; `unsafe_code` denied workspace-wide with documented per-crate opt-out), `rustfmt.toml`, `clippy.toml`, `.gitignore` (target/, devnet data dirs, local wallets/keys, editor droppings — no secret material can ever be committable by default), README stub (name, one-liner, "possession not authorship" positioning line, status), and commit `Cargo.lock`.
- Accept:
  - Tree matches spec lines 44–58 exactly (crate names, binary name `antseal`, `verifier-web/`, `testdata/`)
  - `cargo build`, `cargo test`, `cargo fmt --check`, `cargo clippy --all-targets` all green on the stubs
  - `cargo tree -p antseal-core -e normal` shows no tokio, no I/O/network crates
  - `[workspace.dependencies]` exists and stub crates inherit from it; `Cargo.lock` committed; `.gitignore` covers devnet data + key material
- Notes: Where wasm-bindgen bindings will live (feature-gated in `antseal-core` vs a thin wrapper crate) is an open decision affecting layout — see Open decisions; scaffold must not preclude either.

### P6 — Pin the Rust toolchain, targets, and edition
- Milestone: pre-M0
- Size: S
- Deps: P4
- Spec: Architecture; M0 WASM/CI; Page provenance reproducible build (MVP-SPEC.md lines 40–58, 139, 153)
- Do: Commit `rust-toolchain.toml` pinning an exact stable Rust version (chosen at execution time — current stable), with components `rustfmt` + `clippy` and target `wasm32-unknown-unknown`. Decide and record the Rust edition and the MSRV policy (MSRV = pinned toolchain for MVP). Document that toolchain bumps follow the same deliberate-event procedure as dependency bumps (P7) — the M3 reproducible wasm-pack build makes the toolchain version itself format-provenance-relevant.
- Accept:
  - `rust-toolchain.toml` committed with exact version, components, and the wasm32-unknown-unknown target; local rustup and CI both honor it
  - Edition + MSRV policy recorded
  - Toolchain-bump procedure cross-referenced in P7's policy doc; R/Q pointed at the pin for the M3 reproducible-build recipe

### P7 — Dependency pin governance policy and lockfile discipline
- Milestone: pre-M0
- Size: S
- Deps: P5; Q: bump procedure hooks into golden-vector re-runs; C/G/U: nominate their crypto/Unicode/vault crates into the exact-pin class
- Spec: Key external dependency; Risks — ant-core churn; PQC maturity (MVP-SPEC.md lines 60, 179, 183)
- Do: Write and commit the dependency governance policy: (1) exact `=x.y.z` pins mandatory for every format-, crypto-, or network-consensus-affecting dependency — `ant-core`, the CBOR encoder, `ed25519-dalek`, `ml-dsa`, `fips204`, `opentimestamps`, `self_encryption`, the AEAD/HKDF/SHA-2 stack, the Unicode/NFC data crate (its data version is frozen into manifests per line 83), Argon2/scrypt, `zeroize`; (2) all version specs live only in `[workspace.dependencies]`; (3) `Cargo.lock` committed, CI builds with `--locked`; (4) version bumps are deliberate, reviewed events — a bump PR requires changelog review, RUSTSEC check, golden-vector re-run, and (for ant-core) devnet E2E — never drive-by (upstream cadence is weekly-to-biweekly); (5) toolchain and dev-tool (wasm-pack, wasm-bindgen-cli, cargo-deny) versions are pinned under the same rules.
- Accept:
  - Policy doc committed; every current dependency complies (checked mechanically or by review)
  - CI fails on lockfile drift (`--locked` in every lane)
  - Bump-procedure checklist exists and is referenced from PR/CONTRIBUTING docs
  - The pin-class list explicitly includes the Unicode/NFC data crate (G nominates crate + version at M0)

### P8 — CI skeleton: fmt, clippy, test, advisory hook, wasm build lane
- Milestone: pre-M0
- Size: M
- Deps: P4, P5, P6; Q: extends this skeleton with fuzz lanes (nightly toolchain), golden-vector retention lanes, wasm bit-match lanes, release CI + binary signing
- Spec: M0 — "wasm32 build in CI from day one"; M4 CI list (MVP-SPEC.md lines 153, 157)
- Do: Stand up the CI skeleton on the chosen provider so it is green before M0 coding starts: lanes for `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace --locked`, plus a `cargo build -p antseal-core --target wasm32-unknown-unknown` lane (enforcing WASM-safety from the stub stage; P14 upgrades it with the getrandom recipe once crypto deps land) and a dependency-graph assertion that fails if `antseal-core`'s normal-dep tree gains tokio or I/O crates. Structure workflows as extensible units (named jobs / reusable workflows) so Q can add fuzz, bit-match, and release lanes without rewriting.
- Accept:
  - All lanes green on the P5 scaffold; runs on every PR and on the default branch
  - wasm32 lane demonstrably fails when a non-WASM dep is added to antseal-core (verified once with a throwaway commit)
  - Rust build caching configured; toolchain taken from `rust-toolchain.toml`
  - Extension points for Q documented in the workflow files
- Notes: This satisfies "wasm32 build in CI from day one" at M0 day one because it exists before M0 starts. Fuzz lanes themselves are F/A (targets) + Q (lanes) — not here.

### P9 — Re-verify and land the `ant-core = "=0.5.0"` pin at M0 start
- Milestone: M0
- Size: S
- Deps: P5, P7; S: antseal-net consumes the pin at M1
- Spec: Network decision; Key external dependency; Risks — ant-core churn (MVP-SPEC.md lines 20, 60, 179)
- Do: Execute the spec-mandated re-verification at M0 start: the `=0.5.0` pin was published only 4 days before the spec revision (2026-07-27) and upstream releases weekly-to-biweekly. At execution time check crates.io for the current ant-core version and 0.5.0's yank status; review the upstream ant-client changelog/commits since 0.5.0 for storage/payment-surface changes (`prepare→pay→finalize`, external-signer flow) or critical fixes; make a deliberate keep-or-bump decision per P7's procedure. Land the pin in `[workspace.dependencies]`. Record which exact `self_encryption` version ant-core's dependency graph locks (input to P15).
- Accept:
  - Dated written verification record: versions found, yank status, changelog delta summary, keep-or-bump decision with rationale
  - `ant-core = "=0.5.0"` (or the deliberately-bumped exact version, with spec-reference flag raised) in `[workspace.dependencies]`
  - ant-core's locked `self_encryption` version recorded for P15
- Notes: If a bump is chosen, flag it loudly — spec references (`DataUploadResult` shape, prepare/pay/finalize names, devnet example names) were verified against 0.5.0 and S must re-verify its surface. Complementary to S1 (API-shape survey).

### P10 — Select and pin the deterministic-CBOR encoder crate (joint with F)
- Milestone: M0
- Size: M
- Deps: P5, P7; F: co-owns the evaluation and implements the canonical profile + strict decoder on the pinned crate (see F1); Q: golden-vector cross-check harness
- Spec: Definitions & encoding — deterministic CBOR (MVP-SPEC.md line 73)
- Do: Evaluate candidate crates (spec candidate: `minicbor` with integer keys; compare at least `ciborium` and one other) against the line-73 requirements: ability to emit RFC 8949 §4.2.1 Core Deterministic Encoding (definite lengths, shortest-form ints, bytewise-sorted map keys, no floats, no indefinite items) and — critically — decoder hooks sufficient to hard-reject every non-canonical input class (duplicate keys, non-shortest int/length encodings, indefinite-length items, out-of-order keys, unknown/extra keys in fixed schemas, trailing bytes), plus no_std/WASM-safety and compatibility with F's allocation caps. Pin the winner `=x.y.z` in `[workspace.dependencies]`. Also nominate the independent CBOR implementation (different crate or non-Rust tool, itself version-pinned) that M0 golden vectors will be cross-checked against.
- Accept:
  - Decision record committed: candidates, evaluation against each line-73 rejection rule, rationale
  - Exact pin landed; F sign-off that every canonical-form rejection rule is implementable on this crate (natively or via a strict wrapper F owns)
  - Independent cross-check implementation named and pinned for F/Q's golden-vector work
- Notes: This decision is inside the M0 Definitions freeze — it must land early in M0, before any format bytes are golden-vectored.

### P11 — Decide and pin `ed25519-dalek` (2.x vs 3.0.0)
- Milestone: M0
- Size: S
- Deps: P5, P7; C: confirms strict-verification semantics and consumes the pin (see C11)
- Spec: Cryptography — author signature (MVP-SPEC.md line 97)
- Do: Execute the M0 decision between the 2.x line and 3.0.0 (three weeks old at spec date — at execution time check its current maturity, adoption, and advisory status). Evaluation criteria: availability and exact semantics of `verify_strict`-class RFC 8032 strict verification (reject `S ≥ L`, reject small-order/non-canonical `R`/`A` — C's conformance requirement), zeroize integration, WASM compatibility, RUSTSEC status, and which `getrandom` major it (or its rand_core chain) pulls — the last feeds P14's recipe audit. Pin exactly.
- Accept:
  - Decision record with the criteria above filled in from execution-time sources (docs.rs/changelog/RUSTSEC)
  - Exact `=` pin in `[workspace.dependencies]`; C sign-off that the strict-verification API the spec requires exists on the pinned version
  - The crate's getrandom line recorded in P14's audit table

### P12 — Pin `ml-dsa = "=0.1.1"` and `fips204 = "=0.4.6"` with advisory assessment
- Milestone: M0
- Size: S
- Deps: P5, P7; C: consumes both crates, owns the WASM-probe verdict and the `sig_policy=[ed25519]` fallback decision (see C11)
- Spec: Cryptography — author signature; Risks — PQC crate maturity (MVP-SPEC.md lines 97, 183)
- Do: Land both exact pins in `[workspace.dependencies]`: `ml-dsa = "=0.1.1"` (pre-1.0, unaudited) and `fips204 = "=0.4.6"` (dormant since 2024-12) as fallback. At execution time: fetch the two Jan-2026 RUSTSEC advisories against `ml-dsa`, assess whether they affect our usage profile (deterministic keygen from a 32-byte HKDF-derived seed ξ, signing with `ctx`, canonical verification), and write the assessment; check whether newer versions of either crate exist and record a deliberate stay-or-bump decision (default: the spec pin); confirm both crates enter P13's tracking and P14's WASM probe harness.
- Accept:
  - Both exact pins landed; advisory-applicability assessment committed with the RUSTSEC IDs named
  - Stay-or-bump decision recorded per P7 procedure
  - Both crates listed in P13's deny.toml scope and built by P14's wasm32 lane (or failure escalated to C for the fallback decision)

### P13 — RUSTSEC advisory tracking hookup (cargo-deny/audit lane)
- Milestone: M0
- Size: S
- Deps: P5, P7, P8, P12; Q: licenses section of deny.toml awaits the M4 license decision (Q29)
- Spec: Cryptography — "track RUSTSEC"; Risks — PQC crate maturity (MVP-SPEC.md lines 97, 183)
- Do: Configure cargo-deny (or cargo-audit — record the choice) with a committed `deny.toml`: advisories section (RUSTSEC DB), bans (duplicate-version awareness), sources (crates.io only). Wire two CI triggers: per-PR and a weekly schedule, so a new advisory against a pinned dep surfaces even with no pushes. Every ignored/accepted advisory (starting with the two Jan-2026 ml-dsa ones, per P12's assessment) gets a written justification and a review date in the config. Leave the licenses section stubbed with a pointer to Q's M4 license decision. Pin the cargo-deny version used in CI per P7.
- Accept:
  - CI advisory lane green on PRs; scheduled weekly run visible in CI history
  - `deny.toml` committed; each ignore entry carries justification + review date
  - Demonstrated (once, with a synthetic entry or known advisory) that a new advisory on a pinned dep turns the scheduled lane red

### P14 — WASM toolchain: getrandom recipe, wasm-pack/wasm-bindgen pins, wasm test execution
- Milestone: M0
- Size: M
- Deps: P6, P8, P11, P12; C: crypto dep list + ML-DSA probe verdict/fallback decision; Q: builds the native↔WASM bit-match lanes on this harness (Q5); R: reproducible wasm-pack build (M3) consumes these pinned versions
- Spec: M0 — WASM probe with exact getrandom recipe, wasm32 in CI (MVP-SPEC.md line 153)
- Do: Implement the spec's exact getrandom recipe for the mixed workspace: feature `js` for getrandom-0.2-line dependencies, feature `wasm_js` plus `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` for 0.3/0.4-line dependencies — both simultaneously, since a mixed workspace needs both. Encode it durably: getrandom entries in Cargo manifests, the `--cfg` via `[target.wasm32-unknown-unknown]` rustflags in `.cargo/config.toml`, mirrored in CI. At execution time audit `cargo tree -i` for both getrandom majors to enumerate which dependency sits on which line (ed25519-dalek/rand chain, ml-dsa, CBOR crate, self_encryption when it lands). Install and exact-pin wasm-pack and wasm-bindgen-cli (CLI version must match the wasm-bindgen crate pin), and wire wasm-bindgen-test with a headless runner so antseal-core's unit tests execute on wasm32 in CI — the substrate for the "WASM build must bit-match native verification" requirement.
- Accept:
  - `cargo build -p antseal-core --target wasm32-unknown-unknown` green locally and in CI with the full M0 crypto dependency set (ed25519-dalek, ml-dsa, fips204, CBOR, HKDF/SHA-2/AEAD stack)
  - antseal-core unit tests run to completion on wasm32 in CI via the headless runner
  - Recipe documented in-repo (which dep is on which getrandom line, where each knob lives); wasm-bindgen crate and CLI pins equal
  - Probe results (compile + test outcome for ml-dsa/fips204 on wasm32) handed to C as the go/no-go input for the `sig_policy=[ed25519]` fallback
- Notes: antseal-core's verification path is deterministic and needs no runtime RNG; the recipe exists so transitive rand/getrandom deps compile. The fallback decision itself is C's (C11); this task only produces the evidence.

### P15 — `self_encryption` containment: CI prohibition on any direct dependency + the `blake3` exact pin
*(re-scoped 2026-08-01 by D35 — formerly "Pin `self_encryption` to ant-core's exact version and verify WASM-safety"; that task is retired, because under D32's blob-=-one-chunk model no antseal crate uses `self_encryption` for anything.)*
- Milestone: M1
- Size: S
- Deps: P9, P14; S: S4 consumes the `blake3` pin (BLAKE3-256 address recomputation); R: the M3 storage-linkage layer inherits S4's primitive
- Spec: Architecture — antseal-core address recomputation; seal flow; storage-linkage layer (MVP-SPEC.md lines 47–51, 34, 119); D35 (docs/decisions/D35-self-encryption-dependency-mode.md)
- Do: (1) Land the `blake3` exact pin in `[workspace.dependencies]` (`default-features = false`; exact version chosen at S4 execution against the locked graph so the workspace resolves ONE blake3) — the sole dependency S4's `compute_storage_address` needs. (2) Implement the CI **prohibition**: `self_encryption` must never appear as a *direct* dependency of any antseal crate — it remains exactly what it is today, a transitive, never-invoked-by-us dependency inside ant-core's graph, linked only into net/cli binaries. Extend the existing core-dep-graph lane with a workspace-wide direct-dependency assertion. (3) Retire the old lockstep clause from P7's policy: the pin-moves-only-in-lockstep rule applied to a direct pin that no longer exists; the transitive `self_encryption` version simply follows ant-core's lock and is *recorded* (not pinned by us) at every ant-core bump per S20.
- Accept:
  - `blake3` exact-pinned in `[workspace.dependencies]` with default features off; `antseal-core`'s wasm32 build stays green with it
  - CI lane red when any antseal crate declares `self_encryption` as a direct dependency (red direction proven once, throwaway commit or scripted negative test); green on the real tree with `self_encryption` present only under `ant-core`
  - P7 policy updated: lockstep clause removed, replaced by the D35 containment rule + the record-at-bump note
  - D35 cited from both the lane and the policy text; D6's CRITICAL GPL flag recorded as discharged (no GPL code approaches `antseal-core` or the WASM page)
- Notes: P20 extends this containment class to the devnet era (default `--workspace` lanes never compile `ant-node`; alloy↔evmlib lockstep). D35's revisit triggers stand: the P19 weekly check watches for an upstream relicense, and the v1.1 large-blob decision would reopen the dependency question. — **[2026-08-01 execution, lane γ]** DONE. Deviation from Do(1): the exact version was chosen at P15, not S4 (wave brief): `=1.8.5` = current stable AND ant-core 0.5.0's locked version, and the P16 lock event confirms the workspace resolves ONE blake3 — the clause's motive satisfied early. wasm32 probe green on 1.92.0 (official BLAKE3 spec vectors matched on both the x86-asm and `pure` paths; graph is pure no_std Rust). Prohibition live in `scripts/ci-lanes.sh dep-graph`: declared-manifest scan (self-tested against a planted fake on every run) + `[workspace.dependencies]` grep + resolved-graph immediate-parent check; red direction proven in both declaration shapes; live parent set = {ant-core} exactly.

### P16 — Local devnet environment (in-process nodes + Anvil; configurable count, default 14)
- Milestone: M1
- Size: M
- Deps: P5, P9; S: M1 E2E scripts consume this environment (S17); U: `--network devnet` config values
- Spec: Network decision; Key external dependency — devnet examples; M1 E2E (MVP-SPEC.md lines 20, 69, 154, 172)
- Do: Produce one-command scripts (`scripts/devnet/local-{up,down,reset}`) plus docs to run a local devnet per the P16 feasibility memo (docs/research/P16-devnet-feasibility.md, 2026-08-01): a thin launcher crate of our own (`publish = false`, the wasm-bitmatch precedent) behind its **own non-default feature**, so default `--workspace` lanes never compile `ant-node` (P20 asserts this). The launcher spawns Anvil as a subprocess (alloy node-bindings) and deploys the two contracts fresh per run (premine → Anvil account 0); nodes are **in-process tokio tasks** (LMDB/heed stores, per-node ML-DSA identity) — no docker, no separate `antnode` binary. **Node count is configurable — 25 is merely upstream's default; our default is 14** (the count upstream's own e2e uses for paid uploads; presets 5 = smoke / 10; CLOSE_GROUP_SIZE = 7, node quorum 4, client witnessed quorum 5-of-7). Build the launcher in **release** (debug PQC handshakes burn node-stabilization timeouts; first release build 45–90 min on 2 cores). The upstream example ships **inside the pinned crate archive, so the crate pin IS the ref pin** — no separate repo-ref pinning step exists; `anvil` is host tooling on PATH (1.5.1 verified present). Export the environment surface (EVM RPC URL, contract addresses, bootstrap/peer info, data dirs) as a machine-readable manifest in repo-local gitignored `.devnet/` — NOT `~/.local/share/ant/` — because the manifest embeds the Anvil dev key. Wallet funding story: document the Anvil pre-funded developer keys and which one the test flows use.
- Accept:
  - `local-up` from a clean machine per docs yields a running devnet (default 14 nodes + Anvil); `local-down`/`reset` leave no residue
  - Launcher feature off ⇒ default `--workspace` build/test graphs unchanged (byte-identical cargo-tree diff; P20 makes this a standing lane)
  - ANT-provisioning (premine) and ETH-funding steps documented and working; environment manifest exported for S and U from `.devnet/`; nothing devnet-generated is committable
  - The lockfile event is executed as ONE deliberate joint P7 §4 review with S2 (see Notes)
- Notes: Landing early in M1 is required — S's E2E (seal→kill→resume→restore) runs on this. Documentation must state there is no public Autonomi 2.0 testnet today (see also P17). RAM at 10–14 nodes measured 0.5–1.7 GiB. **Lockfile event, pre-recorded** (memo §6): +36 packages (the ant-node subtree), 652 → 688; ~600 new lock entries vs today's 110 — THE M1 lockfile event, one joint P7 §4 review with S2. Recommendations recorded now: pin `ant-node = "=0.15.0"` **exact** (a caret is un-deterministic the day 0.15.1 ships); decide accept-vs-`--precise` on the saorsa-core drift (fresh resolve pulls 0.26.4, upstream tested 0.26.2); the duplicate-major wave (reqwest 0.12+0.13, RustCrypto 0.10 generation, ark-*) is absorbed by deny `multiple-versions = warn` per D19's rationale. Runbook footgun: a stale local sparse-index cache served a pre-2026-07-23 ant-node listing and failed the resolve until refreshed — it looks like a yank but is not; the S2 lockfile-event runbook must carry the note. — **[2026-08-01 execution, lane γ]** DONE. Boot evidence (docs/devnet/local-devnet.md §Boot evidence): **14 nodes stable in 6.2 s** on the 2-core host (5-node smoke 1.6 s; no count fallback needed); first release build 12 m 45 s (~19 min cold incl. the check pass) — well under the 45–90 min estimate; contracts + funding verified on-chain (chain 31337, token/vault code present, full 2.5 M ANT premine on account 0); down/reset leave zero residue. Deviations: (1) the lockfile event ran in this lane ALONE — S2 landed without the ant-core edge (deferred to S6), so "joint P7 §4 review with S2" became one review covering base graph + devnet subtree, recorded for S6's future edge (docs/upstream/P16-lockfile-event.md); (2) real numbers **128 → 736** (652/688 were the memo's scratch-manifest figures); (3) the drift decision WIDENED: ant-protocol 2.3.1→2.3.0 and saorsa-transport 0.35.3→0.35.1 precise-pinned alongside saorsa-core 0.26.4→0.26.2 — the drifts are coupled (ant-protocol 2.3.1 requires saorsa-core ^0.26.4); unwind order ant-protocol → saorsa-core → saorsa-transport recorded for the next bump; (4) advisory sweep: 4 findings, all unmaintained-class, D19-ignored with review-by 2026-11-01, zero vulnerability-class.

### P17 — Arbitrum-Sepolia devnet environment (start-devnet-sepolia) and funding runbook
- Milestone: M1
- Size: M
- Deps: P5, P9, P16 (shares scripting/skeleton); S: paid-upload smoke against real contracts; U: `--network arbitrum-sepolia` config; Q: M4 gate runs Sepolia-mode E2E on this (Q32)
- Spec: Network decision; devnet examples; M4 gate (MVP-SPEC.md lines 20, 69, 149, 157, 175)
- Do: Scripts + docs for upstream's `start-devnet-sepolia` example: local in-process nodes paying the real deployed Arbitrum Sepolia contracts — chain id 421614, and both scripts and docs must state explicitly this is Arbitrum Sepolia, NOT Ethereum Sepolia. The example ships inside the pinned crate archive (crate pin = ref pin, as P16) and deliberately embeds no wallet — the developer connects their own funded Sepolia wallet. Write the per-developer funding runbook per **D38** (docs/decisions/D38-sepolia-test-ant-acquisition.md): Arbitrum Sepolia ETH via ordinary public gas faucets (account-gated), and **test ANT via an ordinary ERC-20 `transfer` from an existing holder — the only mechanism that exists** (the deployed test token has no mint function, upstream operates no faucet, no bridge is involved; token + payment-vault addresses recorded in D38). The transfer ask is **maintainer-owned** per the external-actions rule. Record the **contingency, scripted but dormant**: self-deploy our own instances of the two verified contract artifacts on 421614 and run the devnet in Custom-network mode — a recorded deviation for development only, never a substitute for the canonical-contract M4 gate. Keys never committed. Docs state plainly: no public Autonomi 2.0 testnet exists today — the self-hosted local and Sepolia devnets are the only development networks.
- Accept:
  - One-command up/down; chain id 421614 asserted in script/config; the "Arbitrum Sepolia, not Ethereum Sepolia" warning present in script output and docs
  - Funding runbook complete per D38 (holder-transfer route + maintainer ownership + gas faucets) and exercised once end-to-end (funded wallet, at least one paid operation against the real Sepolia contracts — jointly with S's backend smoke)
  - The self-deploy contingency documented as a recorded deviation with its non-substitution rule stated; environment surface exported for S/U; "no public testnet" note present
- Notes: The only hard spec gate is the M4 Sepolia-mode E2E; landing at M1 derisks the funding unknowns — D38 resolved the acquisition mechanism 2026-08-01. If the maintainer-side transfer proves slow, the local devnet (P16) carries M1–M3 development without spec violation.
- **[2026-08-02 EXECUTED — environment + runbook land; the node boot is BLOCKED on a launcher change (P22) and the funding is ⛔ MAINTAINER, both stated rather than papered over.]**
  - **Landed**: `scripts/devnet/sepolia-preflight` (read-only chain/contract/funding verification + the `.devnet/sepolia-env` export, with an offline `--self-test`), `scripts/devnet/sepolia-up` (P16's shape end to end; stops at a named blocker today), `docs/devnet/sepolia-devnet.md` (the complete funding runbook, the environment surface, the contingency, the verification record), and the cross-link from the P16 runbook. Down/reset are **deliberately not duplicated**: one launcher, one pidfile under `.devnet/` in either mode, so `local-down`/`local-reset` are the down for both and a second copy could only drift.
  - **Chain-identity assertion, executed live and read-only (2026-08-02)**: `eth_chainId` → `0x66eee` = **421614**; both canonical contracts carry code at the D38-pinned addresses (token `0x4bc1…689C` **7 889 bytes**, vault `0xd742…6522` **12 828 bytes**). The "Arbitrum Sepolia, NOT Ethereum Sepolia" warning is in the script banner, in every failure message (it names Ethereum Sepolia by number when 11155111 is what answered), in the export header and in the doc's first block. Nothing was created, registered, requested or sent — four `eth_*` reads.
  - **Two findings the live run produced, both recorded in the doc.** (1) The Sepolia token is **byte-for-byte the artifact the local devnet deploys** — 7 889 bytes both places (P16 boot evidence) — so local token semantics transfer. (2) The **vault does not**: 3 937 bytes locally against 12 828 on Sepolia, which makes D38 residual risk 3 concrete rather than theoretical (it is a proxy; its behaviour can change under the same address with no pin moving) and gives S20/P19 a specific thing to re-smoke.
  - **A bug the live run caught, and the discipline point**: the funding check compared the `eth_call` result against the string `"0x0"`, so a **zero test-ANT balance was reported as FUNDED**. `eth_call` returns a full 32-byte word. Fixed to a numeric comparison — and the self-test fixtures were themselves wrong (they carried the narrow `0x0` an endpoint never emits), which is why the planted-fault run had stayed green. Both directions are now fixtured in the wide form, funded and unfunded.
  - **Maintainer-blocked residue, stated precisely.** Accept row 2's second half — "exercised once end-to-end (funded wallet, at least one paid operation against the real Sepolia contracts)" — is **NOT done and cannot be done by an agent**. Per D38 the only acquisition route is an ERC-20 transfer from an existing holder: it needs a maintainer's accounts (community ask), account-gated public gas faucets, and a real wallet key. The runbook makes each step executable — fresh unlinked address (Q25), gas, the ask, evidence recording (addresses/amounts/token address, never keys), sizing from real quotes plus margin (Q33 pattern) — and marks the whole section ⛔ maintainer. The paid operation additionally needs P22, so it is blocked twice over.
  - **The self-deploy contingency (D38 route D3)** is documented as dormant with its non-substitution rule stated in full (development unblocking only; the M4 gate still targets the canonical contracts; the deviation is recorded with date and self-deployed addresses so gate reviewers can tell them apart by token address). **No script is shipped**, deliberately: deploying is transaction-sending (⛔ maintainer) and the Custom-network wiring it needs is the same launcher change as P22 — a dormant deploy script before either exists is untested code with a loaded gun attached.
  - **Environment surface for S/U** mirrors P16 exactly — same `KEY='value'` shape, same `ANTSEAL_DEVNET_*` names, so `DevnetEnv` needs no second parser — with one deliberate absence: **the wallet key is never written to any file**. Unlike the local devnet's public Anvil constant, a Sepolia key is real key material. The documented recipe passes it through the process environment (`set -a; . .devnet/sepolia-env; set +a` + an exported key) so `from_process_env` sees all ten keys and none touched disk. **Known gap, recorded**: `DevnetEnv` currently *requires* all ten keys, so a nine-key Sepolia file alone will not parse — an optional-wallet variant is part of P22.
  - **Follow-up, same day**: writing the export into `.devnet/` collided with P16's no-residue contract — `local-down` asserts the directory is EMPTY after a clean stop, so a subsequent local devnet would have died on `sepolia-env` as "unexpected residue". Fixed by narrowing the contract to what it was always a statement about: the **launcher's** cleanup. `sepolia-env` is preflight-written, not launcher-written, and does not expire with a devnet (the chain and contract addresses are the same before, during and after any run), so it is exempted by exact filename — and a real leftover beside it still fails the check, verified in all four combinations. `local-reset` still removes it; the preflight regenerates it in seconds. Recorded in both runbooks.
  - Discovered: **P22** (below) — the launcher's Sepolia mode, which is what "one-command up" is waiting on.

### P18 — Pin `opentimestamps = "=0.2.0"` scoped as wire-format codec only
- Milestone: M2
- Size: S
- Deps: P7, P14; A: builds the in-house calendar HTTP client on top, owns the fallback if the crate is unusable in-core (A11 / A-OD6)
- Spec: Anchoring — OTS crate reality (MVP-SPEC.md line 108)
- Do: Pin `opentimestamps = "=0.2.0"` (the crates.io name; the GitHub repo is `rust-opentimestamps`; 2023-era, codec only) in `[workspace.dependencies]`, with the scope constraint written into P7's policy: wire-format codec only — the calendar HTTP client (submit, upgrade polling, attestation merge) is A's committed in-house M2 work, and no networking surface of the crate may be used. Because `.ots` parse + op execution live in antseal-core (spec lines 49–51), verify at execution that 0.2.0 compiles for wasm32-unknown-unknown without I/O/rand baggage; if it fails, escalate to A/F for an in-house `.ots` codec decision.
- Accept:
  - Exact pin landed; codec-only scope recorded in the dependency policy
  - wasm32 compile check of the crate inside antseal-core recorded (pass, or escalation filed with A)
  - At execution, crates.io checked for yank status/newer releases with a deliberate stay decision recorded

### P19 — Weekly upstream-bump check (post-release chore)
- Milestone: continuous
- Size: S
- Deps: P7, P13; Q: release/CI ownership handoff for the post-release period (Q36)
- Spec: M4 — post-release chore; Risks — ant-core churn (MVP-SPEC.md lines 157, 179)
- Do: Stand up the user-accepted weekly upstream-bump check as a scheduled CI job plus a short runbook: each week, check crates.io for new releases of ant-core and every exact-pinned dependency, scan upstream ant-client repo activity for breaking storage/payment changes, and fold in the P13 scheduled advisory delta. Output surfaces as an issue/report — never an automatic bump; any resulting bump follows P7's deliberate-event procedure (changelog review, golden-vector re-run, devnet E2E for ant-core).
- Accept:
  - Scheduled job live by release (mechanism may land earlier); runbook committed
  - First weekly report produced post-release; a new upstream ant-core release demonstrably generates a report entry
  - No automation path exists that changes a pin without a human-reviewed PR
- Notes: Q36 owns the equivalent chore from the release side — implement once, cross-referenced.

### P20 — Dependency-graph containment assertions for the devnet era
- Milestone: M1
- Size: S
- Deps: P15, P16, S2
- Spec: Architecture — crate layout + churn-isolation boundary (MVP-SPEC.md lines 44–58, 60–69); D35 §consequences; P16 feasibility memo §6 (docs/research/P16-devnet-feasibility.md); D52
- Do: Extend P15's containment discipline to the graph the devnet era creates, as standing CI assertions rather than convention: (1) the default `--workspace` build and test lanes never compile `ant-node` — the P16 launcher crate participates only behind its own non-default feature, and the lane proves the default unit graph is free of the +36-package ant-node subtree (cargo-tree/unit-graph assertion); (2) `self_encryption` is never a **direct** dependency of any antseal crate — D35's prohibition; P15 lands the check, this task extends it across the grown 688-package graph and keeps its red direction tested; (3) the workspace's resolved `alloy` version(s) stay in lockstep with what the pinned `evmlib` resolves — S5/S6 wallet validation and the payment path are defined as "what the pinned evmlib/alloy parse accepts" (D44), so independent alloy drift would silently fork the accepted set.
- Accept:
  - Default `cargo build`/`cargo test --workspace --locked` demonstrably compiles zero ant-node-subtree packages, asserted mechanically; proven able to fail (feature flipped once in a scratch run)
  - The D35 direct-dep prohibition and the alloy↔evmlib lockstep check run in the same lane; each carries a recorded red-direction proof
  - Lane documented beside the existing core-dep-graph assertion — one containment story, three rules
- Notes: Discovered by the D35/D52/P16 planning round, 2026-08-01. The 652 → 688-package jump is the M1 lockfile event (P16 memo §6, reviewed jointly with S2 under P7 §4); this task is the standing guard that the event's boundaries hold afterwards.
- **Landed 2026-08-02** — three rules appended to `lane_dep_graph` in `scripts/ci-lanes.sh`, documented in `docs/dependency-policy.md` §1. Deviations, each deliberate:
  1. **Rule 1 checks the whole upstream stack, not `ant-node` alone.** `ant-core`, `ant-protocol`, `evmlib` and `alloy` sit behind the same two non-default gates by the same recorded decisions (D33/D35/D52), so they are one boundary; checking one member of it would leave the other four to a future review. Naming them individually is what lets the failure message say which edge broke it — the scratch flip printed all five.
  2. **Rule 1's self-test uses the real graph, not a planted string.** The lane runs the identical command with `devnet-launcher/devnet` on and requires `ant-node` to *appear*. A planted string proves the regex matches itself; this proves the command and the pattern can still see the thing they forbid.
  3. **Rule 2 was already present; what was missing was its falsifiability.** P15 self-tested the declared-manifest detector but not the resolved-parent one (`grep -F ' (/'`), so a typo there would have been permanently, silently green. Added the self-test rather than a second copy of the check — the task's "extend, don't duplicate" applied one level down.
  4. **Rule 3 is expressed through Cargo.lock's own encoding.** A lock dependency entry is version-**qualified** (`"alloy 1.7.0"`) if and only if that package resolves to more than one version, so `evmlib` listing a bare `"alloy"` *is* the statement "one alloy, and we are both on it" — no version arithmetic, no re-derivation of evmlib's caret. Backed by two more: the whole `alloy-*` family single-versioned, and the recorded `=` pin literal equal to the resolved version.
- Measured, and recorded because it is the size of what the gate holds back: **120 packages** in the default `--workspace` graph (normal+build+dev), **475** with `devnet-launcher/devnet`.
- Red directions executed: `default = ["devnet"]` flipped in a scratch run (rule 1 red, all five packages named, exit 1); both new self-tests broken in place and confirmed red; rule 3's three branches run against a doctored `Cargo.lock` (two alloy versions → count branch; `"alloy 1.7.0"` → qualified-entry branch; family duplicate → family branch). **One branch has no end-to-end red**: the pin-literal-vs-lock comparison, because a `=` pin that disagrees with the lock fails every `--locked` cargo call earlier in the lane — a stronger guard, so the branch is a backstop for a *comment* drifting rather than a resolution drifting. Its two inputs are proven extractable and the comparison is string equality.
- **Watchpoint (2026-08-02): rule 1's self-test failed three times, non-reproducibly**, always with `cargo tree --workspace --features devnet-launcher/devnet` exiting 0 but yielding a tree without `ant-node`; the same command run standalone was correct every time (1 755 lines, `ant-node` twice), and the lane has since run 6/6 green when the machine was quiet. Probable cause: a concurrent `cargo` in another worktree contending for the shared `~/.cargo` package-cache lock — every failure landed immediately after a heavy cargo invocation, and none has recurred since. **Handled, not hidden**: the self-test now checks cargo's exit code explicitly and prints it, the tree's line count, and cargo's stderr, so the next occurrence says whether cargo failed or the pattern did. If it recurs on a quiet machine the command itself is the suspect, not the rule.

### P22 — devnet-launcher Sepolia mode (`--network arbitrum-sepolia`)
- Milestone: M1
- Size: S
- Deps: P16 (the launcher), P17 (the scripts and runbook that call it); S5 (`DevnetEnv`, whose ten-key requirement it changes)
- Discovered by: **P17** (2026-08-02) — the environment half landed and immediately ran into the one thing scripts cannot supply.
- Problem: `devnet-launcher` boots Anvil unconditionally. It calls `assert_anvil_on_path` before anything else, builds `DevnetConfig` leaving `evm_network` at `None`, and writes `ANTSEAL_DEVNET_CHAIN_ID` as the literal `'31337'`. Upstream already supports the other mode — `DevnetConfig.evm_network: Option<EvmNetwork>` (`ant-node-0.15.0/src/devnet.rs:164-167`), which upstream's own `start-devnet-sepolia` example sets to `EvmNetwork::ArbitrumSepoliaTest` — so nothing is missing upstream; the launcher simply never exposes it.
- Do: add `--network local|arbitrum-sepolia` (default `local`, so every existing invocation is unchanged). In Sepolia mode: set `evm_network = Some(EvmNetwork::ArbitrumSepoliaTest)`, skip the Anvil requirement entirely, write `ANTSEAL_DEVNET_CHAIN_ID='421614'`, and **omit `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY`** — the Sepolia devnet embeds no wallet by upstream's design and ours. Then give `DevnetEnv` (crates/antseal-net/src/network.rs) an optional-wallet path, since it requires all ten keys today and a Sepolia export has nine. `scripts/devnet/sepolia-up` is already written against this interface and probes for it; delete the probe when the flag lands.
- Accept:
  - `sepolia-up` boots N nodes against chain 421614 with no Anvil anywhere in the process tree, and `local-up` is byte-identically unaffected (a `--network local` default that changes no existing behaviour).
  - The export carries chain id 421614 and **no** wallet key; a consumer can still assemble a complete `DevnetEnv` via the process-environment recipe (docs/devnet/sepolia-devnet.md).
  - `local-down` stops a Sepolia devnet with the same no-residue contract.
- Notes: booting is cheap to *try* and expensive to *use* — nodes need no funds, but any paid operation needs the maintainer-owned funding of D38, so this task's Accept deliberately stops at "boots", and the paid smoke stays P17's Accept row 2 (⛔). The self-deploy contingency (D38 D3) would reuse the same `Network::Custom` plumbing; it stays dormant.

## Open decisions (P)
- Final product name — keep `antseal` with upstream's written blessing vs a non-ant rename; blocks P2, P3 (and, cross-domain, the C/F M0 freezes of the signature context string and format identifiers); must land pre-M0. — **[2026-07-27]** OPEN (provisional): working name stays `antseal`; blessing request drafted (docs/naming/upstream-blessing-request.md) for the maintainer to file at WithAutonomi/ant-client issues; no reply by M0 start → unilateral fallback `sealstone` (docs/decisions/D1-product-name.md). — **[2026-07-27]** RESOLVED: **`antseal` maintainer-confirmed final** (third path — no upstream blessing, deviation + residual risk recorded; blessing request now optional courtesy; fallback retired; availability re-verified at confirmation — 5 crates FREE + dry-run green, .org/.dev FREE). P2/P3 executable; C12/F4/U1 unblocked on the name.
- Repo hosting platform + CI provider (working assumption GitHub + Actions, needed for scheduled lanes in P13/P19); blocks P4, P8; pre-M0. — **[2026-07-27]** RESOLVED: GitHub + GitHub Actions, private repo **`aed900/antseal`** (docs/decisions/D2-hosting-ci.md; remote-CI verification status in docs/ci-verification.md; commit identities normalized to the maintainer identity pre-first-push per the D2 amendment).
- Repo root layout — `/home/deb/Documents/code0` as workspace root vs containing `antseal/` per the spec tree; blocks P4, P5; pre-M0. — **[2026-07-27]** RESOLVED: repo root = workspace root; the repo root IS the spec tree's `antseal/`, no nested subdir (docs/decisions/D3-repo-layout.md).
- Rust edition + MSRV policy; blocks P6; pre-M0. — **[2026-07-27]** RESOLVED: edition 2024; toolchain pinned =1.92.0; MSRV = the pin, moves only via the dependency-policy bump procedure (docs/decisions/D4-edition-msrv.md).
- CLI crate published name — spec tree says `antseal-cli` (binary `antseal`); `cargo install antseal` UX argues for publishing the CLI as the bare name. Spec tree is normative, so recorded as disagreement only; reservation (P2) covers both names; pre-M0. — **[2026-07-27]** RESOLVED as recorded deferral: spec tree stays normative (`antseal-cli` crate, `antseal` binary); both names reserved at P2; bare-name publish decided at release, Q31/M4 (docs/decisions/D5-cli-crate-name.md).
- wasm-bindgen surface location — feature-gated exports inside `antseal-core` vs a thin wrapper crate; partially blocks P14 (test harness), finally blocks R's M3 page build (R22); decide by M0, final by M3.
- Deterministic-CBOR crate (candidate `minicbor` with integer keys) — joint P/F decision; blocks P10 and F's M0 Definitions freeze; M0. — **[2026-07-27]** RESOLVED: `minicbor = "=2.3.0"`, features `alloc` only; strict-decode layer feasible on native probes; independent cross-check = Python `cbor2 ==6.1.3` dev-only (docs/decisions/D7-cbor-crate.md).
- `ed25519-dalek` 2.x vs 3.0.0; blocks P11 and C's signature work; M0. — **[2026-07-27]** RESOLVED (D13): **`=3.0.0`** — strict-verify semantics probe-identical to 2.2.0, single RustCrypto generation shared with ml-dsa (2.x doubles the stack); declaration-only pin landed (docs/decisions/D13-ed25519-dalek-pin.md).
- cargo-deny vs cargo-audit (or both) for the advisory lane; blocks P13; M0. — **[2026-07-27]** RESOLVED (D19): **cargo-deny only**, `=0.19.8` CI pin; deny.toml advisories/bans/sources active, licenses stubbed → Q29; amended same day: **GHSA/osv.dev sweep mandatory** — RUSTSEC covers only 1 of 3 ml-dsa advisories (docs/decisions/D19-advisory-lane.md).
- Test-ANT acquisition mechanism on Arbitrum Sepolia (chain 421614) — upstream faucet/mint/bridge, verified at execution; blocks P17's funding runbook; must land by the M4 Sepolia-mode gate (targeted M1). — **[2026-08-01]** RESOLVED (D38): an ordinary ERC-20 `transfer` from an existing holder — no mint/faucet/bridge exists; maintainer-owned transfer request + account-gated gas faucets; scripted self-deploy contingency recorded as a deviation, never a substitute for the canonical-contract M4 gate (docs/decisions/D38-sepolia-test-ant-acquisition.md).

## Cross-domain expectations
- F: co-executes the CBOR crate evaluation (P10) and implements the RFC 8949 §4.2.1 canonical profile + strict decoder + fuzz targets on the pinned crate; consumes the final name for format identifier strings before M0 freeze.
- C: confirms strict-Ed25519 (`verify_strict`) semantics on the P11 pin; supplies the M0 crypto dep list for P14's getrandom audit; owns the ML-DSA WASM-probe verdict and the `sig_policy=[ed25519]` fallback decision; nominates AEAD/HKDF/SHA-2 crates into P7's exact-pin class.
- G: nominates the Unicode/NFC normalization crate + exact Unicode data version for P7's exact-pin class at M0.
- S: consumes the ant-core pin (P9) in `StorageBackend`, the self_encryption pin (P15), and the devnet environments (P16/P17) for M1 E2E; provides the paid-Sepolia smoke that closes P17's funding runbook.
- A: consumes the opentimestamps codec pin (P18) with the codec-only scope; owns the in-house `.ots` codec fallback if the crate fails the wasm32 check; supplies DER/`.ots` fuzz targets for Q's lanes.
- R: consumes the registered verifier domain (P3) for the M3 canonical URL + page deploy; consumes P14's pinned wasm-pack/wasm-bindgen versions and P6's toolchain pin for the reproducible build + published hash; decides the wasm-bindgen surface location with P.
- U: wires `--network arbitrum-one|arbitrum-sepolia|devnet` to the P16/P17 environment surfaces; reuses the funding runbooks in `init`'s printed funding instructions.
- Q: extends the P8 CI skeleton (fuzz lanes + nightly pin, golden-vector retention forever, native↔WASM bit-match lanes on the P14 harness, release CI, binary signing); owns the M4 license decision that completes P13's deny.toml licenses section; owns M4 docs (wallet funding, vault loss/theft) that build on P16/P17 runbooks.

### P23 — Govern the two pre-release pins and the one mandatory advisory ignore
- Milestone: M2
- Size: S
- Deps: D60 (which chooses them); P7 (the pin class); P13/D19 (`deny.toml`, the advisory lane)
- Spec: Risks — dependency churn (MVP-SPEC.md line 181); docs/dependency-policy.md §1/§4/§5
- Discovered by: **D60** (2026-08-02).
- Problem: D60 puts two pre-release versions into the exact-pin class — `cms =0.3.0-pre.2` and `rsa =0.10.0-rc.18` — and both are load-bearing for `antseal-core`'s anchor verification. The project has the precedent (`argon2 =0.6.0-rc.8`, `blake2 =0.11.0-rc.6`) but not the watch: a pre-release can be **yanked** without a successor, and `cargo deny`'s `yanked` check is on by default, so the first symptom would be a red advisory lane on an unrelated PR. Separately, `rsa` at **any** version carries RUSTSEC-2023-0071 (`introduced: 0.0.0-0`, no fixed version), and `cargo deny check advisories` was **verified red** against the D60 set with the project's own pinned tool: `advisories FAILED … rsa v0.10.0-rc.18 … Solution: No safe upgrade is available!`. The ignore entry is therefore not a nicety; without it every PR and every weekly cron is red from the moment A5 lands.
- Do: land the `[advisories].ignore` entry verbatim from D60 §7.5 — it carries the applicability argument (`antseal-core` performs RSA **public-key verification only** and holds no RSA private key, so the private-key timing channel has nothing to leak), the reason the advisory has no fixed version, the revisit condition, and a `Review by 2027-02-01` date, all per `deny.toml`'s own IGNORE DISCIPLINE. Add **no** entry for `GHSA-9c48-w39g-hm26` (`fixed: 0.9.10`; `0.10.0-rc.18` is outside it, so `cargo-deny` does not report it and an ignore would be dead config — the shape the header already rejects). Then record both pre-release pins in `docs/dependency-policy.md` with their stabilisation trigger: `cms 0.3.0` and `rsa 0.10.0` final are **reviewed bumps**, taken deliberately with the D60 measurement re-run (package delta, duplicate scan, wasm32 check, the nine real-token fixtures), never drive-by.
- Accept:
  - `cargo deny check advisories bans sources` is green on the tree that contains the D60 pins, and the ignore's `reason` string names the applicability argument rather than pointing at a document.
  - Removing the ignore turns the lane red with RUSTSEC-2023-0071 (the red direction, run once and recorded).
  - The dependency-policy entry names both pre-release pins, their stable successors, and the exact re-measurement a bump must repeat.
  - A deliberate check that the two rc versions are not yanked at landing time, with the date recorded — so a later yank is a change rather than a discovery.
- Notes: the applicability argument is the load-bearing part and it must not be paraphrased into "we think it's fine". It is falsifiable: it holds exactly as long as no antseal code path performs an RSA private-key operation, which is structurally true (authorship signatures are Ed25519 + ML-DSA-65, MVP-SPEC.md line 97) and which A30's containment rules keep true.

### P24 — D60's "zero new duplicate pairs" is false at the workspace level
- Milestone: M2
- Size: S
- Deps: D60 (landed pins)
- Do: D60 §1.6 reports *"**zero** new duplicate-version pairs"* and *"**No
  second copy of** `sha2`, `digest`, `signature`, `der`, `spki`, `const-oid`
  or `pkcs8`"*. Both are true of `antseal-core`'s **own** graph and **false**
  of the workspace, because D60 measured on scratch probe crates that contain
  no `antseal-net`. Measured on the real tree at the pin commit:
  `cargo tree -d -e normal` goes from **2** name-pairs (`rand_core`, `syn` —
  both pre-existing) to **10**. The eight new ones are `base16ct`,
  `const-oid`, `crypto-bigint`, `der`, `elliptic-curve`, `ff`, `group`,
  `sec1`. Cause, traced: `antseal-net`'s D89 `k256 =0.13.4` sits on the
  RustCrypto 0.13 / der-0.7 generation and nothing opposed it until `p384
  =0.14.0` put the 0.14 generation beside it —
  `der v0.7.10 <- sec1 v0.7.3 <- elliptic-curve v0.13.8 <- k256 v0.13.4 <- antseal-net`.
  Nothing goes red (`deny.toml` sets `multiple-versions = "warn"`, P13's
  recorded choice; D89's rule 5 guards `k256` itself, not its closure) and no
  antseal type crosses the two generations. Amend D60 §1.6 with a dated note,
  and decide whether the pair is worth a `deny.toml` skip entry or a
  standing note beside the existing `syn` record.
- Accept:
  - D60 carries a dated amendment with the measured workspace numbers.
  - `deny.toml`'s duplicate-version comment lists the k256-vs-p384 generation
    split alongside the three pairs it already names, or records why not.
- Notes: The claim matters because it is the sentence D60 uses to justify
  taking two **pre-release** pins over their stable lines. The justification
  still holds — the stable lines are disqualified on other, stronger grounds
  (`rsa 0.9.10` fails the `dep_graph` forbidden-name regex outright) — but the
  headline number is not the number.

### P25 — Record the rejected-dependency register, opening with `opentimestamps`
- Milestone: M2
- Size: S
- Deps: P7 (the pin policy this extends), P18 (retired by D58), D58
- Spec: Dependency policy (docs/dependency-policy.md §1/§5); Anchoring — crate reality (MVP-SPEC.md line 108)
- Do: Add a **rejected nominees** section to `docs/dependency-policy.md`: one row per crate that was evaluated for the workspace and not adopted, carrying crate + version evaluated, date, the one-sentence reason, and a link to the deciding record. Open it with `opentimestamps =0.2.0` → `docs/decisions/D58-opentimestamps-viability.md`. The row must state that the crate **compiles fine on the pinned toolchain and on wasm32**, because that is the check a re-nominator will run first and pass; without that sentence the register invites exactly the re-nomination it exists to prevent. State the readmission condition in the same row (D58 §14's first trigger), so the register records a door rather than a wall.
- Accept:
  - Section exists with the `opentimestamps` row; the row names the four defect classes by their D58 section numbers, not by paraphrase.
  - `scripts/check-traceability.py` (or the doc-link check it already performs) resolves the D58 link; a broken link fails.
  - A grep-level review item: `opentimestamps` appears in no manifest and in no `[workspace.dependencies]` entry — the same shape as the `self_encryption` prohibition, without the CI lane (the crate is not dangerous, only rejected).
- Notes: Discovered by D58 (2026-08-02). P18's whole deliverable was the pin D58 declines to land, so P18 is retired rather than amended; this task is where its Accept rows come to rest. The re-nomination risk is concrete: MVP-SPEC.md line 108 currently *instructs* a reader to reuse the crate as the wire-format layer, and D58 §12.4 corrects that sentence — but a corrected spec line and a dependency register are looked up by different people at different times.

### P26 — A30's `from_ber` ban needs one carve-out, and it is the one D60 requires
- Milestone: M2
- Size: XS
- Deps: A5 (landed), A30
- Do: `cms 0.3.0-pre.2` forces `der`'s `ber` feature on for the whole graph,
  making `Decode::from_ber` reachable from antseal source. A30 bans the token
  at lane level, correctly. But D60 §7.4 **requires** one use of it:
  `der_pin_rejects_indefinite_length` must assert that the BER fixture is
  accepted by `from_ber`, because without that leg the test cannot distinguish
  "rejected for being BER" from "rejected for being garbage" — and a merely
  corrupt fixture would satisfy the rejection assertion forever while proving
  nothing. A30's detector must allow exactly
  `crates/antseal-core/tests/der_pin_eval.rs` and nothing else, with the
  allowance written as a named exception rather than a path-glob that widens
  by accident.
- Accept:
  - A30's lane greps `from_ber` across the workspace and passes with the one
    committed occurrence present.
  - A **self-test** in A30's own house pattern: a planted `from_ber` in a
    second file makes the lane red.
- Notes: One line of source, and the lane it belongs to has not landed yet —
  recording it now is what stops A30 landing a rule that immediately fails on
  committed code.

### P29 — Land the `ureq` pin and its dependency-policy row
- Milestone: M2
- Size: S
- Deps: P7 (pin governance); D90; lands **with or before** A3
- Spec: Architecture (lines 52–53), Anchoring (lines 108–109)
- Discovered by: **D90** (2026-08-02). A3's `Deps` line names "P: workspace scaffold + HTTP-client crate pin" and **no such P task exists** — P18 is the (D58-superseded) opentimestamps codec pin and excludes networking explicitly. This is that task, with the crate chosen by D90 rather than left open.
- Do: Add `ureq = { version = "=3.3.0", default-features = false, features = ["rustls"] }` to `[workspace.dependencies]` with D90 Decision 1's comment verbatim, and consume it from `crates/antseal-anchor/Cargo.toml` alone. Add the `docs/dependency-policy.md` §1 row: exact-pinned in the `rpassword` class (no format byte flows through it, but it is the sole path by which adversary-controlled bytes enter the process before any parser of ours sees them, and three of its behaviours are load-bearing contracts a minor bump could move silently); **no lockstep with anything**; the bump procedure must state which `webpki-roots` the bump moves to, since that snapshot is a TLS trust input arriving transitively and frozen only by §3. Amend the rule-1 paragraph at `docs/dependency-policy.md:87-96` with the dated measurement "129 → 144 (D90, 2026-08-02); 475 → 479 with `devnet-launcher/devnet`". Correct the false sentence in `Cargo.toml`'s tokio entry (~line 160): "the default `--workspace` graph resolves no tokio at all" is true of `-e normal` (100 packages) but **false** of `-e normal,build,dev`, which is what the `dep-graph` lane measures and where `antseal-net`'s dev edge puts tokio.
- Accept:
  - `cargo tree --workspace -e normal,build,dev --prefix none --locked` counts **144**; with `antseal-net/ant-backend` **451**; with `devnet-launcher/devnet` **479**. A different number is a resolution that must be explained before the pin lands.
  - Exactly four names are new to `Cargo.lock`: `ureq`, `ureq-proto`, `utf8-zero`, `webpki-roots`. Any fifth is a finding.
  - `cargo deny check advisories bans sources` passes; `bans` reports `getrandom` at three versions as a **warning**, not a failure.
  - No workspace crate other than `antseal-anchor` names `ureq` (grep + `cargo metadata --no-deps`).
  - `cargo tree -i rustls --workspace --locked` shows one `rustls` version, `0.23.43` — the pin adds no TLS generation to a graph that already carries two.
- Notes: Deliberately not folded into A3: the pin is governance with its own Accept numbers, and P7's discipline is that a pin is a reviewed event with its own evidence, not a side effect of the first task that wants the crate.

### P30 — Make the transitively-acquired `webpki-roots` TLS trust snapshot a reviewed value
- Milestone: M2
- Size: S
- Deps: P29 (the ureq pin); D90 residual risk 2
- Spec: Anchoring (line 109), Risks — hostile bundles / upstream churn (lines 182, 187)
- Discovered by: **P29 implementation** (2026-08-02). D90 records the risk ("`webpki-roots` is a trust input that arrives transitively … a `cargo update` moves it without any lane commenting") and leaves the mitigation procedural — a sentence in the bump row. Measured while landing the pin: `ureq =3.3.0` declares a **caret** requirement, this workspace resolved **`webpki-roots 1.0.9`**, and the local registry cache alone already holds 1.0.4 through 1.0.9 — so the version genuinely floats, and the only thing holding it is `Cargo.lock` plus a human remembering to mention it. Every TLS acceptance decision for A16's and A17's endpoints — the two whose replies are unsigned and whose *only* integrity control is the transport — is made against that snapshot.
- Do: Make the resolved version a value a lane states rather than one a reviewer must notice. Cheapest sufficient form: extend `scripts/ci-lanes.sh dep-graph` to print and assert the resolved `webpki-roots` version against a committed literal, with the two-direction self-test the lane's other rules carry (must match the current version; must fail on a planted different one). Consider, and record the decision either way, whether the stronger form D90 declined to pre-commit — a direct exact-pinned `webpki-roots` declaration in `[workspace.dependencies]` — is now warranted; if it is not, say why in the same commit so the next reader does not re-open it.
- Accept:
  - A `cargo update` that moves `webpki-roots` turns the lane red naming the old and new versions (proven by planting the change, not by argument).
  - The dependency-policy `ureq` row's "state which webpki-roots the bump moves to" sentence points at the asserted literal, so the procedural rule and the mechanical one cannot drift apart.
  - A stale-snapshot failure is still diagnosable: the assertion must not be confusable with A25's liveness signal (a root rotation the snapshot predates surfaces as `AnchorHttpError::Tls`, which is a different thing and already named).
- Notes: The failure mode this guards is silent and one-directional — a snapshot that has moved is not detectable from any test output, because every endpoint we contact today chains to roots that are in both versions. It becomes visible only when it is already a liveness incident.
