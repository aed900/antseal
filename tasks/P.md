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

### P15 — Pin `self_encryption` to ant-core's exact version and verify WASM-safety
- Milestone: M1
- Size: S
- Deps: P9, P14; S: uses it via ant-core for the seal-time address computation (S4); F/R: in-core deterministic address recomputation (bundle storage-linkage layer, M3)
- Spec: Architecture — antseal-core address recomputation; seal flow; storage-linkage layer (MVP-SPEC.md lines 47–51, 34, 119)
- Do: Pin `self_encryption` in `[workspace.dependencies]` to exactly the version locked by `ant-core = "=0.5.0"` (from P9's record; re-verify via `cargo tree` at execution) — antseal-core recomputes Autonomi ciphertext addresses offline, and any version skew between our recomputation and the network's actual chunking would break the storage-linkage layer and the seal flow's pre-quote address computation. Verify the pinned version compiles for wasm32-unknown-unknown inside antseal-core with no I/O/rand baggage (extend P14's audit). If it is WASM-unsafe or ant-core's graph would force two versions, escalate to S/R with options (vendor the address derivation logic).
- Accept:
  - One `self_encryption` version across the whole workspace graph, equal to ant-core 0.5.0's locked version, with the match rationale recorded
  - wasm32 build of antseal-core green with self_encryption as a dependency
  - Version-skew risk documented in P7's policy: this pin may only move in lockstep with the ant-core pin
- Notes: Spec assigns no explicit milestone; M1 chosen because the pin's source of truth (ant-core's resolved graph) lands at M1. The in-core recomputation consuming it is S4 (used from M1; consumed by R's linkage layer at M3).

### P16 — Local devnet environment (start-local-devnet: 25 nodes + Anvil)
- Milestone: M1
- Size: M
- Deps: P5, P9; S: M1 E2E scripts consume this environment (S17); U: `--network devnet` config values
- Spec: Network decision; Key external dependency — devnet examples; M1 E2E (MVP-SPEC.md lines 20, 69, 154, 172)
- Do: Produce one-command scripts (e.g. `scripts/devnet/local-{up,down,reset}`) plus docs to run upstream's `start-local-devnet` example: 25 nodes + Anvil. At execution time, locate the example in the upstream ant-client repo at the ref matching the P9 ant-core pin and pin that ref in the script; verify at execution what host tooling it needs (foundry/anvil version) and how the example provisions devnet ANT tokens on the local Anvil chain. Wallet funding story: document the Anvil pre-funded developer keys and which one the test flows use. Capture and export the environment surface (EVM RPC URL, deployed contract addresses, bootstrap/peer info, data dirs) in a machine-readable form S's E2E and U's `--network devnet` wiring can consume. Ensure devnet data dirs and any key material are gitignored.
- Accept:
  - `local-up` from a clean machine per docs yields a running 25-node + Anvil devnet; `local-down`/`reset` leave no residue
  - Upstream ref pinned in the script and recorded; ANT-provisioning and ETH-funding steps documented and working
  - Environment endpoints/addresses exported for S and U; nothing devnet-generated is committable
- Notes: Landing early in M1 is required — S's E2E (seal→kill→resume→restore) runs on this. Documentation must state there is no public Autonomi 2.0 testnet today (see also P17).

### P17 — Arbitrum-Sepolia devnet environment (start-devnet-sepolia) and funding runbook
- Milestone: M1
- Size: M
- Deps: P5, P9, P16 (shares scripting/skeleton); S: paid-upload smoke against real contracts; U: `--network arbitrum-sepolia` config; Q: M4 gate runs Sepolia-mode E2E on this (Q32)
- Spec: Network decision; devnet examples; M4 gate (MVP-SPEC.md lines 20, 69, 149, 157, 175)
- Do: Scripts + docs for upstream's `start-devnet-sepolia` example: 25 local nodes paying the real deployed Arbitrum Sepolia contracts — chain id 421614, and both scripts and docs must state explicitly this is Arbitrum Sepolia, NOT Ethereum Sepolia. At execution time: verify the example at the pinned upstream ref, identify the deployed contract addresses it targets, and determine upstream's mechanism for obtaining test ANT on chain 421614 (faucet, mint, bridge — whatever the example expects). Write the per-developer funding runbook: Arbitrum Sepolia ETH faucet procedure + test-ANT acquisition + wallet setup, with keys never committed. Docs state plainly: no public Autonomi 2.0 testnet exists today — the self-hosted local and Sepolia devnets are the only development networks.
- Accept:
  - One-command up/down; chain id 421614 asserted in script/config; the "Arbitrum Sepolia, not Ethereum Sepolia" warning present in script output and docs
  - Funding runbook complete and exercised once end-to-end (funded wallet, at least one paid operation against the real Sepolia contracts — jointly with S's backend smoke)
  - Environment surface exported for S/U; "no public testnet" note present
- Notes: The only hard spec gate is the M4 Sepolia-mode E2E; landing at M1 derisks the funding unknowns (test-ANT acquisition on 421614 is the open item — see Open decisions). If funding proves slow, the local devnet (P16) carries M1–M3 development without spec violation.

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

## Open decisions (P)
- Final product name — keep `antseal` with upstream's written blessing vs a non-ant rename; blocks P2, P3 (and, cross-domain, the C/F M0 freezes of the signature context string and format identifiers); must land pre-M0.
- Repo hosting platform + CI provider (working assumption GitHub + Actions, needed for scheduled lanes in P13/P19); blocks P4, P8; pre-M0.
- Repo root layout — `/home/deb/Documents/code0` as workspace root vs containing `antseal/` per the spec tree; blocks P4, P5; pre-M0.
- Rust edition + MSRV policy; blocks P6; pre-M0.
- CLI crate published name — spec tree says `antseal-cli` (binary `antseal`); `cargo install antseal` UX argues for publishing the CLI as the bare name. Spec tree is normative, so recorded as disagreement only; reservation (P2) covers both names; pre-M0.
- wasm-bindgen surface location — feature-gated exports inside `antseal-core` vs a thin wrapper crate; partially blocks P14 (test harness), finally blocks R's M3 page build (R22); decide by M0, final by M3.
- Deterministic-CBOR crate (candidate `minicbor` with integer keys) — joint P/F decision; blocks P10 and F's M0 Definitions freeze; M0.
- `ed25519-dalek` 2.x vs 3.0.0; blocks P11 and C's signature work; M0.
- cargo-deny vs cargo-audit (or both) for the advisory lane; blocks P13; M0.
- Test-ANT acquisition mechanism on Arbitrum Sepolia (chain 421614) — upstream faucet/mint/bridge, verified at execution; blocks P17's funding runbook; must land by the M4 Sepolia-mode gate (targeted M1).

## Cross-domain expectations
- F: co-executes the CBOR crate evaluation (P10) and implements the RFC 8949 §4.2.1 canonical profile + strict decoder + fuzz targets on the pinned crate; consumes the final name for format identifier strings before M0 freeze.
- C: confirms strict-Ed25519 (`verify_strict`) semantics on the P11 pin; supplies the M0 crypto dep list for P14's getrandom audit; owns the ML-DSA WASM-probe verdict and the `sig_policy=[ed25519]` fallback decision; nominates AEAD/HKDF/SHA-2 crates into P7's exact-pin class.
- G: nominates the Unicode/NFC normalization crate + exact Unicode data version for P7's exact-pin class at M0.
- S: consumes the ant-core pin (P9) in `StorageBackend`, the self_encryption pin (P15), and the devnet environments (P16/P17) for M1 E2E; provides the paid-Sepolia smoke that closes P17's funding runbook.
- A: consumes the opentimestamps codec pin (P18) with the codec-only scope; owns the in-house `.ots` codec fallback if the crate fails the wasm32 check; supplies DER/`.ots` fuzz targets for Q's lanes.
- R: consumes the registered verifier domain (P3) for the M3 canonical URL + page deploy; consumes P14's pinned wasm-pack/wasm-bindgen versions and P6's toolchain pin for the reproducible build + published hash; decides the wasm-bindgen surface location with P.
- U: wires `--network arbitrum-one|arbitrum-sepolia|devnet` to the P16/P17 environment surfaces; reuses the funding runbooks in `init`'s printed funding instructions.
- Q: extends the P8 CI skeleton (fuzz lanes + nightly pin, golden-vector retention forever, native↔WASM bit-match lanes on the P14 harness, release CI, binary signing); owns the M4 license decision that completes P13's deny.toml licenses section; owns M4 docs (wallet funding, vault loss/theft) that build on P16/P17 runbooks.
