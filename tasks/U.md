# U — CLI, vault, config, UX

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.
> Note: several U milestones are inferences (the spec assigns no milestone to init/vault/config) — placed in the milestone whose deliverables need them (init/vault before M1's E2E, seal orchestration M1, status M2, reveal/verify M3), as the agents noted per task.

### U1 — Scaffold `antseal-cli` crate with full canonical clap surface
- Milestone: M1
- Size: M
- Deps: P: workspace scaffold + pinned clap/tokio/tracing versions; P: final product name decision (binary name, `~/.antseal/` dir name, crate prefix)
- Spec: Working name / pre-M0 (line 3); Architecture (lines 44–58); CLI surface (lines 147–149)
- Do: Create `crates/antseal-cli` (binary `antseal`, clap derive + tokio main). Define the complete canonical command tree up front — `init`, `seal <path>…`, `list`, `show <work-id>`, `status <work-id> [--upgrade]`, `restore <work-id> [-o dir]`, `reveal <work-id> (--all | --units …) [-o file] [--include-receipt] [--yes]`, `verify <bundle> [--online] [--live]`, `vault export|import` — with all `seal` flags (`--title`, `--split blank-lines`, `--force-text`, `--no-fine-tree <glob>`, `--dry-run`, `--yes`, `--force-degraded`, dev-only `--no-anchor`) and globals `--network arbitrum-one|arbitrum-sepolia|devnet` (default `arbitrum-one`) and `--json`. Later-milestone handlers return a clean "not implemented until M<x>" error, so the surface is frozen from day one and never drifts from spec. Initialize `tracing`/`tracing-subscriber` writing to stderr only, env-filter driven (no new verbosity flags — the canonical surface is closed).
- Accept:
  - `antseal --help` and every subcommand `--help` snapshot-tested; snapshot enumerates exactly the canonical surface, nothing extra
  - `--network` rejects unknown values; `--split` accepts only `blank-lines`; `--no-fine-tree` takes a glob value; `reveal` enforces exactly-one-of `--all`/`--units` at parse time
  - `--no-anchor` is present but hidden from release help output (dev-only), and gated as in U13
  - tracing output goes to stderr; stdout stays reserved for command output
- Notes: If the pre-M0 rename lands, binary/dir/env names must be single-constant parameterized here.

### U2 — Define exit-code scheme and thiserror CLI error taxonomy
- Milestone: M1
- Size: M
- Deps: U1; C: library error enums; G: canonicalization errors; S: storage/payment error classes (incl. insufficient-token vs insufficient-gas); F: codec errors
- Spec: Core user flows (line 34); CLI surface (lines 147–149); Seal journal (line 145)
- Do: Design a documented, stable exit-code scheme: 0 success; distinct codes for usage error, user-declined consent / non-TTY-without-`--yes` abort, insufficient ANT token, insufficient ETH gas, anchor-gate abort, vault authentication failure (bad passphrase / AAD-detected tamper), network failure, resume-safety abort (changed source / missing staged bytes), and verification-failure classes (finalized in U30). Implement a top-level `thiserror` CLI error type that wraps every library-domain error (C/G/S/A/R/F) into user-facing messages carrying the possession-language style and never any secret material. Wire `main()` so every error path maps deterministically to its code and, under `--json`, to a structured error object.
- Accept:
  - exit-code table committed and unit-tested (each error class → asserted code)
  - insufficient-token and insufficient-gas produce different messages and different exit codes
  - error `Display` output for every wrapped class is snapshot-tested; no secret-bearing fields exist in any CLI error variant (enforced by U21 harness)
- Notes: Verify-verdict exit mapping is deferred to U30 (open decision).

### U3 — Build `--json` output framework covering every command
- Milestone: M1
- Size: M
- Deps: U1, U2
- Spec: CLI surface (lines 147–149)
- Do: Define the machine-output contract: with `--json`, stdout carries exactly one JSON document per invocation (versioned envelope: `command`, `network`, `ok`, `result`|`error`), all human copy/prompts/nags/warnings go to stderr, and exit codes are unchanged. Build a schema-registry harness in which every command registers its `--json` result schema and CI validates emitted output against committed schema fixtures — so a command cannot ship without a defined JSON shape. Define the interactivity contract: confirmation prompts are TTY-only; a consent-bearing command run with `--json` (or a non-TTY stdin) and without `--yes` aborts with the dedicated exit code instead of hanging.
- Accept:
  - envelope schema committed; harness fails CI when any command lacks a registered `--json` fixture
  - `--json` output parses as a single JSON document with zero stray stdout bytes (nags/warnings verified on stderr)
  - non-TTY + no `--yes` on `seal`/`reveal` aborts with the defined code, in both plain and `--json` modes
- Notes: Accept criteria extend per command as U11–U30 land (each adds its fixture). Open decision 15 (prompt × `--json` contract details) must close before U14.

### U4 — Implement config file with network mapping and override slots
- Milestone: M1
- Size: M
- Deps: U1, U5; S: network → contracts/RPC mapping schema (S5); A: TSA list + endpoint config schema (slots only in M1)
- Spec: Vault (line 143, "config + per-work records"); MVP scope decision 4 / networks (line 20); Anchoring (line 109); Verifier page online mode (line 137)
- Do: Implement `~/.antseal/config.toml` (plaintext-readable location inside the vault dir; see open decision 4 on the encryption boundary): default network, per-network contracts/RPC endpoints (schema from S), and reserved sections for the TSA list override (wired M2, U26) and pinned online-endpoint overrides for `verify --online` (wired M3, U30). Precedence: CLI `--network`/flags > config > built-in defaults (`arbitrum-one`). `init` writes the initial config (U11). Loader tolerates missing file (defaults) but hard-errors on malformed content with a precise message.
- Accept:
  - precedence tested: flag beats config beats default; `arbitrum-one` is the built-in default with no config present
  - `--network devnet` and `arbitrum-sepolia` resolve to distinct endpoint/contract sets supplied by S's schema
  - malformed config → distinct exit code; unknown keys warn (forward-compat) rather than crash
- Notes: Milestone inference — config is unassigned in spec; M1 needs network mapping for the devnet E2E.

### U5 — Design vault store layout, versioned header, and crash-safe file discipline
- Milestone: M1
- Size: M
- Deps: U1; P: dir/file naming constants
- Spec: Vault (lines 141–145)
- Do: Design the on-disk `~/.antseal/` layout: config file, vault header + encrypted store, per-work record area, and anchor-artifact area. Header is versioned (format version, KDF block per U6) to permit future migration. All mutating writes are atomic (temp file + fsync + rename) and a single-writer lockfile prevents concurrent `antseal` processes from corrupting the journal. Decide and document the encryption-boundary partition (what lives inside the passphrase AEAD vs beside it — see open decision 4) without weakening the mandate that per-work records (`W`, journal, receipts, `.ots`, TSA tokens, addresses, paths, costs) are encrypted at rest.
- Accept:
  - layout documented in-crate; header round-trips with version field; unknown future version → clean "vault created by newer antseal" error
  - kill-during-write test leaves the store readable (old or new state, never torn)
  - second concurrent invocation fails fast with a clear lock-held message
- Notes: Lockfile and atomicity are inferred hygiene (the M1 pay/finalize kill-tests depend on journal integrity). Boundary decision blocks U24's no-prompt upgrade hook.

### U6 — Implement vault encryption: Argon2id/scrypt KDF with header-bound AAD
- Milestone: M1
- Size: M
- Deps: U5; C: XChaCha20-Poly1305 AEAD primitive + zeroizing key types; P: argon2/scrypt crate pins
- Spec: Vault (line 143)
- Do: Implement vault-at-rest encryption: passphrase → KDF → vault key → AEAD over the store. Default KDF Argon2id with m ≥ 256 MiB, t = 3, p = 1; alternative scrypt N ≥ 2²⁰; random 16-B salt; the header records algorithm id + full parameters. Bind the entire serialized KDF header into the vault AEAD as AAD so any parameter downgrade (e.g. lowered m/N) or header edit is an authentication failure, never a silent weakening. Bad passphrase and tampered header are distinguishable from corrupt store only insofar as safe (all surface as vault-auth failure exit code).
- Accept:
  - test: decrypt with correct passphrase succeeds; wrong passphrase fails with vault-auth code
  - downgrade test (spec-mandated): lower `m` (and `N` for scrypt) in the header of a valid vault → AEAD authentication failure, not a successful open with weak params
  - parameter floor enforced at creation: attempts to create below-floor params are rejected
  - default-params vault creation measured (Argon2id 256 MiB) and documented; scrypt path covered by the same tests
- Notes: 256 MiB Argon2id on low-RAM machines may need a documented fallback prompt — decision folded into open decision 2.

### U7 — Build passphrase UX: prompts, strength floor, non-interactive supply, zeroization
- Milestone: M1
- Size: M
- Deps: U6; C: zeroizing buffer types (C5)
- Spec: Vault (line 143, "`init` enforces a passphrase-strength floor", zeroize)
- Do: Implement no-echo passphrase prompting (entry + confirmation at creation), a passphrase-strength floor enforced at `init`/`vault import`-to-new-passphrase (choose and document the measure, e.g. zxcvbn-class estimation with a minimum score/entropy), and a non-interactive supply channel for scripts and the M1 E2E (open decision 3: env var vs fd — `--yes` covers confirmations only, not passphrases). All passphrase buffers are held in zeroizing types (C) and never logged.
- Accept:
  - weak passphrase at `init` rejected with actionable message; floor value documented
  - non-interactive path drives a full scripted `init`+`seal` without a TTY
  - passphrase bytes appear in no log/error/JSON output (exercised by U21 harness)
  - prompt aborts cleanly (dedicated exit code) when no TTY and no non-interactive supply
- Notes: Strength-floor metric choice is an open decision; must land with U11.

### U8 — Implement optional keyfile / OS-keystore wrap for `W`
- Milestone: M1
- Size: M
- Deps: U6, U7 (offered during U11's init flow — interface only, not an ordering dep); C: key-wrap primitive (AEAD) + zeroizing types
- Spec: Vault (line 143, "offers a high-entropy keyfile / OS-keystore wrap for `W`")
- Do: At `init`, offer wrapping the master-secret material with either a generated high-entropy keyfile (stored wherever the user directs, required alongside the passphrase) or an OS-keystore-held key (keyring-class integration; platform scope per open decision 14). Record the chosen wrap mode in the vault header (bound via U6's AAD). Unlock path combines passphrase KDF with the wrap; absence of the keyfile/keystore entry yields a precise, distinct error.
- Accept:
  - round-trip tests for each wrap mode: create → lock → unlock; missing keyfile → distinct error, not generic auth failure
  - wrap mode recorded in header; header tamper (mode flip) → AEAD auth failure
  - declining the offer leaves a passphrase-only vault byte-compatible with U6 tests
- Notes: Not on the M1 E2E critical path — may land late-M1. OS-keystore CI coverage on headless Linux needs a mock keystore.

### U9 — Implement per-work record store (vault records + journal persistence API)
- Milestone: M1
- Size: L
- Deps: U5, U6; S: journal record shapes (S10 supplies the content schema — input, not an ordering dep; S10 in turn builds on this store); A: `.ots`/TSA artifact shapes (slots exercised M2); C: zeroizing `W` type
- Spec: Vault (lines 141–145); Architecture receipt contents (line 69); Seal journal (line 145)
- Do: Implement the encrypted per-work record store: for each work — `W`, `seal_id`, title, network, file paths (paths live in the vault, not the manifest), per-work cost, completion state, the seal journal area (staged ciphertext bytes + per-unit nonce + target address; content shapes owned by S), the journaled `PaymentReceipt`, and anchor-artifact slots (`.ots` files, TSA tokens, fetch dates). Provide the write API the seal pipeline uses, with the receipt write being a single atomic, fsync'd operation so "journaled the instant the tx lands" is real under crash. Provide read/query APIs for `list`/`show`/`status`/`reveal`/`restore`.
- Accept:
  - record schema versioned and round-trip tested with fixture works (complete, incomplete-pre-pay, incomplete-post-pay/pre-finalize, degraded, UNANCHORED)
  - receipt-write atomicity test: simulated kill immediately after the write API returns leaves the receipt readable on reopen (feeds S's no-double-pay E2E)
  - all record content unreadable without vault unlock; `W` exposed to callers only as C's zeroizing type
  - staged-ciphertext retention policy after successful finalize implemented per open decision 5
- Notes: This is the storage substrate for S's resume semantics — S owns *when/what* to journal, U9 owns *where/how durably*.

### U10 — Store Arbitrum wallet key under its own vault sub-key
- Milestone: M1
- Size: S
- Deps: U6, U9; C: HKDF-based sub-key derivation + AEAD; S: wallet key material type
- Spec: Vault (line 143, "wallet key lives inside the encrypted vault but under its own sub-key")
- Do: Derive a dedicated sub-key from the vault master key (label-separated) and encrypt the Arbitrum wallet key record under it, separately from work records, so the wallet's blast radius is decoupled and future external-signer support can remove it cleanly. Expose a narrow accessor used only by S's payment path.
- Accept:
  - wallet record decrypts only via the sub-key path; corrupting the wallet record leaves work records readable, and vice versa
  - wallet key bytes never appear outside C's zeroizing types; U21 harness covers wallet-path errors

### U11 — Implement `init`: vault create, wallet generate/import, funding instructions, network config
- Milestone: M1
- Size: M
- Deps: U4, U6, U7, U8, U9, U10; S: wallet keygen + address derivation + import-format validation (S5)
- Spec: CLI surface (lines 147–149, `init`); Vault (line 143); Networks (line 20); Positioning (line 28)
- Do: Implement `init`: create the vault (passphrase per U7, KDF choice per open decision 2, optional wrap per U8); wallet key **generate** (OS CSPRNG via S) or **import** (format per open decision 6), stored per U10; print the wallet address plus per-network funding instructions (Arbitrum One: ANT token + ETH for gas; sepolia/devnet: faucet/Anvil notes); write network choice into config (U4). Re-running `init` over an existing vault refuses by default with a clear message. Interaction model (wizard vs flags) per open decision 1.
- Accept:
  - E2E: fresh machine → `init` → funded devnet wallet → U13 seal succeeds (feeds M1 devnet E2E)
  - both generate and import paths tested; invalid import material rejected with a precise error
  - address + funding instructions printed for all three networks; copy uses possession language, no "notary"
  - `--json` fixture registered (address, network, vault path; no key material)
  - existing-vault refusal tested
- Notes: Milestone inference — `init`/vault must precede M1's E2E (spec assigns no milestone). Q23 (M4) later harmonizes the printed funding copy with the docs — consumer, not a dep.

### U12 — Implement `vault export` / `vault import`
- Milestone: M1
- Size: M
- Deps: U5, U6, U9
- Spec: CLI surface (lines 147–149, `vault export|import`); Vault (line 143); M1/M4 verification (lines 172, 175)
- Do: Implement `vault export` producing a single encrypted backup file (format per open decision 9) capturing everything needed to reveal/restore every work (all records, journal, anchors, wallet, config), and `vault import` reconstructing `~/.antseal/` on a clean machine. Import refuses to overwrite an existing vault without explicit confirmation. This pair is what the M1 "restore from vault backup on a clean tree" E2E and the M4 disk-loss drill exercise.
- Accept:
  - round-trip test: export → wipe `~/.antseal/` → import → `restore` of a fixture work succeeds byte-identically
  - export file is unreadable without the passphrase (and wrap factor if configured)
  - import-over-existing-vault refusal tested; `--json` fixtures for both subcommands
  - incomplete works (journal state) survive the round trip so a resumable seal stays resumable
- Notes: Milestone inference — needed by M1 E2E's vault-backup restore (S19); M4 drill (Q32) consumes it.

### U13 — Orchestrate the seal pipeline in exact normative order (M1 scope, `--no-anchor`)
- Milestone: M1
- Size: L
- Deps: U2, U3, U9, U11, U14, U4; G: canonicalization + unit split + fine-tree build (G14); C: unit encryption, manifest encryption, hybrid signing; F: manifest body build/encode, `work_id`; S: address computation, `quote_batch`/`pay`/`finalize_batch`, journal/resume semantics (S12)
- Spec: Core user flows 1 (line 34); Cryptography DAG (line 90); Seal journal (line 145); M1 (line 154); CLI surface (line 149)
- Do: Implement `seal <path>…` driving the exact normative order: canonicalize → encrypt units (local, journaled via U9 as S directs) → build + sign manifest → encrypt manifest → compute all ciphertext addresses (units + encrypted manifest) → `quote_batch` over the full blob set → permanence consent (U14) → [anchor stage: M2, U22 — in M1 reachable only as `--no-anchor`] → `pay` with the receipt journaled via U9's atomic write **before** `finalize_batch` is invoked → `finalize_batch` → print work-id + cost (and in `--json`). Plumb `--title` (embedded in manifest via F), `--split blank-lines`, `--force-text`, and `--no-fine-tree <glob>` (CLI-side glob → per-file opt-out set handed to G). Enforce statically that `--no-anchor` is rejected when the effective network is `arbitrum-one` (this guard is born in M1 with the flag), and that M1 seals without `--no-anchor` fail with "anchoring arrives in M2" rather than silently sealing unanchored.
- Accept:
  - integration test (MockBackend) asserts the step order — no payment call before consent returns affirmative, no `finalize_batch` before the receipt is persisted, no upload before payment
  - kill-between-pay-and-finalize and kill-mid-upload scenarios pass S's M1 E2E via this orchestration (no double payment; byte-identical re-upload)
  - `--no-anchor` + `--network arbitrum-one` (flag or config default) → rejection with dedicated exit code, tested
  - multi-file seal with `--split` produces expected unit set (G asserts content; U13 asserts wiring); `--no-fine-tree` glob matches recorded per-file in the descriptor
  - final line prints `work_id` + actual cost; `--json` fixture registered; cost persisted to the work record (U9)
- Notes: Directory-argument handling per open decision 8. Committed path normalization is G/F's; U13 passes original paths and stores them in the vault.

### U14 — Implement the permanence-consent gate
- Milestone: M1
- Size: M
- Deps: U2, U3, U13 (interface only — the consent-hook signature; U13 invokes this gate); S: ANT + ETH balance queries (S8); S: quote totals; G: file list + byte totals
- Spec: Core user flows 1 (line 34, "permanence consent")
- Do: Before anchoring/payment, render the consent report: file list, byte totals, the *true, complete* quote (every blob including the encrypted manifest), and current ANT + ETH balances displayed beside it; the exact warning "upload is permanent, public, and irreversible"; then require interactive confirmation, with `--yes` bypassing for scripts. Pre-flight balance-vs-quote comparison and pay-time failures must surface as **distinct** insufficient-ANT-token vs insufficient-ETH-gas errors (U2 codes). Non-TTY without `--yes` aborts (U3 contract).
- Accept:
  - consent text snapshot-tested and contains the exact permanence wording, file list, byte totals, quote, and both balances
  - declining aborts before any anchor submission or payment (asserted via mock call log)
  - insufficient-token and insufficient-gas each tested → distinct message + exit code
  - `--yes` path and non-TTY-abort path both tested; consent report reproduced on stderr under `--json`

### U15 — Implement seal warning moments: title visibility, `--no-fine-tree`, fine-tree cost estimate
- Milestone: M1
- Size: S
- Deps: U13; G: fine-tree cost estimator (G10)
- Spec: Core user flows 1 (line 34, title warning); Canonicalization (line 85)
- Do: When `--title` is set, warn that the title is embedded in the plaintext manifest every proof bundle carries and will be visible to all bundle recipients. When `--no-fine-tree` matches files, warn those files are **permanently** whole-file-reveal only. For large files, print G's estimated fine-tree cost before consent so the user sees it ahead of the quote. All three surface before the consent prompt.
- Accept:
  - each warning snapshot-tested; emitted on stderr; present in the pre-consent flow (mock-ordered)
  - `--no-fine-tree` warning names the matched files; cost estimate appears above a configurable size threshold and is absent below it
- Notes: Threshold for "large files" is a U-owned constant — document it.

### U16 — Implement `seal --dry-run`
- Milestone: M1
- Size: S
- Deps: U13, U14, U15
- Spec: CLI surface (line 149, `--dry-run`)
- Do: Define and implement `--dry-run`: run every cheap, failable, local step (canonicalize, encrypt in memory, manifest build/sign, address computation) plus `quote_batch` (per open decision 11), then print the full consent report and all warnings (U14/U15) and exit — no consent prompt, no anchor submission, no payment, no upload, and **zero vault mutation** (no journal entries, no work record).
- Accept:
  - after `--dry-run`, the vault byte-state is unchanged (hashed before/after in test); MockBackend records only `quote_batch`
  - output includes files, byte totals, cost, and all applicable warnings; `--json` fixture registered
  - `--dry-run` combined with `--yes`/`--force-degraded`/`--no-anchor` still performs no side effects
- Notes: Semantics are a U-defined inference (spec names the flag only) — documented in help text.

### U17 — Implement seal resume and abandonment UX
- Milestone: M1
- Size: M
- Deps: U9, U13, U14; S: resume/abandon decision logic (S11)
- Spec: Seal journal (line 145); M1 (line 154)
- Do: Wire the CLI entry to S's resume logic: re-running `seal` detects a matching incomplete work (keying per open decision 7), prints a resume plan (what's staged, whether a receipt is journaled, what remains), and proceeds — re-consent via U14 when no payment has happened yet; no re-consent when a receipt is journaled (money already spent, finalize only). Surface S's safety aborts loudly: changed source file → abort explaining re-encryption under a journaled nonce is forbidden; staged bytes unavailable → the work is **abandoned**, message states any payment is forfeited as a deliberate safety choice and a fresh seal will use a new `seal_id` and fresh nonces.
- Accept:
  - resume-pre-pay path re-prompts consent; resume-post-receipt path skips consent and calls only `finalize_batch` (mock-asserted)
  - changed-source and missing-staged-bytes scenarios produce the two distinct messages/exit codes; neither ever re-encrypts (asserted via C/S mock)
  - abandoned work is marked in the record store and shown by `list` as incomplete/abandoned
- Notes: Consent-on-resume rule is a U inference (spec silent); recorded in help/docs.

### U18 — Implement vault loss/theft double nag and first-seal export nag
- Milestone: M1
- Size: S
- Deps: U12, U13
- Spec: Vault (line 143); Risks (line 184)
- Do: After the first successful `seal` in a vault with no recorded export, nag: run `vault export` and store the backup safely. The nag (and `init`'s closing message) states both failure modes in possession language: **loss** — lose vault + backup and reveal/restore are gone forever, the sealed data itself stays safely unreadable; **theft** — retroactive, permanent decryption of public undeletable ciphertexts with no rotation possible; treat passphrase and exports as long-term high-value keys. Track "export performed" in the vault so the nag stops.
- Accept:
  - first seal without prior export → nag on stderr (also under `--json`); after `vault export`, subsequent seals don't nag
  - nag copy snapshot-tested, contains both loss and theft framings, no "notary"/unqualified-"priority" wording
- Notes: Q24 (M4) later harmonizes the doc pages with these nags — consumer, not a dep; CLI nag copy is U's.

### U19 — Implement `list` (works, incomplete state, per-work cost)
- Milestone: M1
- Size: M
- Deps: U3, U9
- Spec: CLI surface (line 149, `list`); Seal journal (line 145, "`list` shows `incomplete` works")
- Do: Implement `list`: every work in the vault with work-id, title, seal date, network, completion state (`complete` / `incomplete` with resume hint / `abandoned` / `UNANCHORED`), and per-work cost from the record store. Pending-anchor nag column arrives M2 (U25) — leave the slot. Registered `--json` fixture with the full record set.
- Accept:
  - fixture vault with complete, incomplete-pre-pay, incomplete-post-receipt, abandoned, and `--no-anchor` works renders all states distinctly (snapshot)
  - per-work cost matches the value journaled at seal; `--json` fixture registered
- Notes: Milestone inference — journal section (M1) requires `list` to show incomplete works.

### U20 — Implement `restore <work-id> [-o dir]` CLI wiring
- Milestone: M1
- Size: M
- Deps: U2, U3, U9; S: restore engine (S14)
- Spec: Core user flows 4 (line 37); M1 (line 154); CLI surface (line 149)
- Do: Wire `restore`: resolve the work record, invoke S's restore engine, write recovered original files under `-o dir` (default directory and overwrite policy per open decision 10 — never silently clobber). Report per-file verification results; any commitment mismatch fails loudly with a distinct exit code. This is the door of the permanent vault — the M4 clean-machine drill runs `vault import` (U12) then this command.
- Accept:
  - devnet/MockBackend E2E: seal → wipe originals → `restore` reproduces byte-identical files (raw bytes via raw-mirror where applicable)
  - existing-file collision behavior tested per chosen policy; unknown work-id → clean error
  - commitment-mismatch (S-injected) → distinct failure exit code; `--json` fixture registered

### U21 — Build the secret-hygiene test harness (no secrets in logs/errors/output)
- Milestone: M1
- Size: M
- Deps: U2, U7, U9, U10, U13; C: zeroizing types with redacted `Debug`
- Spec: Vault (line 143, zeroize); project rule 6; CLI surface domain mandate
- Do: Build an automated harness that runs representative flows (init, seal happy + every error class, resume aborts, restore, vault export) with **known sentinel secret values** injected (`W`, unit keys, salts, passphrase, wallet key) and scans all stdout, stderr, tracing output at max verbosity, `--json` documents, and persisted non-vault files for any sentinel bytes (raw, hex, base64). Assert CLI error types and record-store `Debug` impls redact. Runs in CI on every change.
- Accept:
  - harness fails when a deliberately-leaky log line is introduced (self-test); passes on the real CLI
  - covers trace-level logging; covers panic messages (panic hook output scanned)
  - wired into CI as a required check
- Notes: Extended by U32 as new commands land (M2/M3 surfaces get added to the flow list).

### U22 — Wire the anchor stage: ≥1-TSA-or-abort gate, `--force-degraded`, degraded reporting
- Milestone: M2
- Size: M
- Deps: U13, U9, U2; A: OTS calendar submit + TSA submission engine (A20); A: minimum-anchor policy primitives
- Spec: Core user flows 1 (line 34); MVP scope decision 3 (line 19); M2 (line 155); Risks (line 189)
- Do: Insert the anchor-submission stage into U13's pipeline between consent and `pay`: submit `anchor_digest` to ≥2 OTS calendars (pending `.ots` journaled) and ≥2 configured TSAs; enforce the gate — if zero TSA tokens return, **abort before any payment** (cheap, reversible, distinct exit code) unless `--force-degraded` is passed, which proceeds with a loud warning and records the degraded anchor set in the work record. Anchor failures always downgrade the seal report explicitly, never silently. Remove the M1 "anchoring arrives in M2" stub so plain `seal` now requires the gate; `--no-anchor` continues to skip the stage entirely (still mainnet-rejected per U13).
- Accept:
  - mock-A matrix: all-TSAs-fail → abort pre-payment (mock asserts zero `pay` calls) with dedicated exit code; one-TSA-succeeds → proceeds; `--force-degraded` with zero tokens → proceeds with snapshot-tested warning
  - journaled artifacts (pending `.ots`, TSA tokens, fetch dates) land in U9 slots
  - seal summary output names each anchor's outcome; degraded seals labeled as such in `list`/record

### U23 — Implement `status <work-id> [--upgrade]`
- Milestone: M2
- Size: M
- Deps: U3, U9; A: per-anchor verdict-state machine + OTS upgrade engine (A15/A18)
- Spec: Core user flows 2 (line 35); M2 (line 155); Verifier verdict taxonomy (lines 127–137)
- Do: Implement `status`: load the work's anchor artifacts, evaluate each anchor's current state via A (offline evaluation; states worded consistently with R's taxonomy), and render per-anchor status plus the Arbitrum receipt as "supporting evidence — no independently proven time". `--upgrade` drives A's OTS calendar polling to completion where possible, persisting upgraded `.ots` (with embedded header + fetch date) back into the record store. Pending anchors render with the "not yet independently provable" hint.
- Accept:
  - fixture works covering `pending`, `attested`, `proven`(TSA), degraded, and UNANCHORED render distinct snapshot-tested output; receipt never rendered as an anchor
  - `--upgrade` against A's mock calendar transitions pending → attested and persists the upgraded `.ots` (re-run shows the new state)
  - `--json` fixture registered (machine-readable per-anchor states)
- Notes: State names come from A18 at M2; when R18 freezes the authoritative wording at M3, re-align `status` output (alignment check, not an ordering dep).

### U24 — Wire opportunistic OTS upgrade hook into every CLI invocation
- Milestone: M2
- Size: M
- Deps: U1, U5, U9, U23; A: bounded-time opportunistic upgrade API (A15)
- Spec: Core user flows 2 (line 35); Anchoring (line 108); Risks (line 182)
- Do: Add a shared hook in the command dispatch path so **every** invocation opportunistically attempts pending OTS upgrades for all works: enumerate pending `.ots`, call A's engine with a short time budget, persist any upgrades, and never fail or delay the primary command on hook errors (silent-degrade, debug-level trace only). Behavior when the vault is locked or absent (e.g. bare `verify` on a third-party machine) per open decision 4: skip silently — the hook must never trigger a passphrase prompt the command didn't already need. Hook output (if any) goes to stderr and never corrupts `--json` stdout.
- Accept:
  - running unrelated commands (`list`, `show`) upgrades a pending fixture via mock-A and persists it; primary command output unchanged
  - hook failure (mock network error) leaves the primary command's exit code and output untouched
  - vault-less `verify` performs no vault access and no prompt (asserted)
  - hook lives in the shared dispatch path — a test enumerates subcommands and asserts each passes through it

### U25 — Add pending-anchor nags to `list`
- Milestone: M2
- Size: S
- Deps: U19, U23; A: per-work anchor-state summary (A15)
- Spec: Core user flows 2 (line 35, "`list` nags"); Risks (line 182)
- Do: Extend `list` to nag on every work whose **only strong anchor is still pending** (no headline-eligible TSA token or proven OTS): a visible marker plus "run `antseal status <id> --upgrade`" hint. Reflect degraded/UNANCHORED works distinctly from pending ones.
- Accept:
  - fixture matrix: work with valid TSA token → no nag; `--force-degraded` work with only pending OTS → nag; UNANCHORED `--no-anchor` work → labeled UNANCHORED, not "pending"
  - nag appears in human output (stderr or marked column) and as a structured field in the `--json` fixture

### U26 — Wire TSA-list override from config into the anchor stage
- Milestone: M2
- Size: S
- Deps: U4, U22; A: TSA client accepting a configured list (A10). Q26 (M4) documents the alternates — consumer, not a dep.
- Spec: Anchoring (line 109); Config mandate (domain scope)
- Do: Activate the U4 config slot: a user-supplied TSA URL list overrides the built-in defaults (FreeTSA + DigiCert) for `seal`'s anchor stage; empty/absent config uses defaults. Validate entries at load (URL shape) and pass through to A. The ≥1-TSA-or-abort gate applies to the effective list.
- Accept:
  - config with two custom TSAs → A's mock receives exactly those; no config → defaults
  - malformed TSA URL in config → clean config error before any pipeline work

### U27 — Implement `show <work-id>` unit preview
- Milestone: M3
- Size: M
- Deps: U3, U9; G: unit/byte-range metadata semantics; C: decrypt (if snippet sourced from staged/local ciphertext per open decisions 5/14); R: preview computation (R15)
- Spec: CLI surface (line 149, `show`); Core user flows 3 (line 36); M3 (line 156)
- Do: Implement `show`: for every unit of the work — `unit_id`, file (path from the vault), kind (raw-mirror units clearly marked as not selectable via bare `--units`), byte-range, size (`true_length`), and a local snippet when available (source per open decision — decrypted staged ciphertext for exact sealed bytes, else current local file marked "may differ if modified since sealing", else omitted). This is the documented preview surface users consult before `reveal --units`.
- Accept:
  - fixture work with text (multi-unit via `--split`), binary, `--no-fine-tree`, and raw-mirror units renders all fields; raw-mirror marked with the not-directly-revealable note
  - snippet provenance labeled; missing local data degrades gracefully (no error)
  - `--json` fixture registered (full unit table, snippet omitted or flagged by provenance)

### U28 — Implement `reveal <work-id>` command core
- Milestone: M3
- Size: L
- Deps: U2, U3, U9, U27; R: reveal-flow library API + disclosure preview (R16/R15, over R13); S: `get_data` ciphertext fetch when no local copy exists (via R16)
- Spec: Core user flows 3 (line 36); Raw mirror selection rule (line 92); Reveal bundle (lines 112–114); M3 (line 156); CLI surface (line 149)
- Do: Implement `reveal` wiring: parse selection (`--all` | `--units` comma list per open decision 12; exactly one required — clap-enforced in U1), resolve the work, reject a bare `--units <raw-mirror-id>` with a message explaining mirrors are includable only via whole-file reveal or `--all` (enforced belt-and-braces here and in R's builder), fetch any missing ciphertexts from Autonomi via S, invoke R's builder, and write the bundle to `-o file` (default name per open decision 12). Pass `--include-receipt` through to R. Print the closing lines: bundle path + the canonical verifier page URL (URL constant owned by R).
- Accept:
  - `--all` and `--units` paths produce R-verified bundles (R's verify API round-trip in test); unknown unit ids and mirror-id rejection each produce distinct errors
  - local-copy-absent path exercises S's fetch (mock asserts `get_data`)
  - `--include-receipt` present/absent toggles receipt embedding (asserted via R)
  - output includes the canonical verifier URL; `--json` fixture registered (bundle path, revealed unit ids, receipt-included flag)

### U29 — Implement reveal disclosure consent and receipt-exposure warning
- Milestone: M3
- Size: S
- Deps: U28; R: disclosure-preview data (R15)
- Spec: Core user flows 3 (line 36); Anchoring receipt opt-in (line 110); Risks wallet linkability (line 185)
- Do: Before writing any bundle, render R's disclosure preview — exactly which units will be **irreversibly disclosed**: file, byte-range, size, snippet — and require interactive confirmation (`--yes` for scripts; non-TTY without `--yes` aborts per U3). When `--include-receipt` is passed, add a warning that the receipt exposes the paying wallet and links the user's seals. Copy uses possession language throughout.
- Accept:
  - preview snapshot-tested (unit rows with file/range/size/snippet + "irreversibly disclosed" wording); declining writes no bundle file
  - `--include-receipt` warning snapshot-tested; absent otherwise
  - `--yes` and non-TTY-abort paths tested; preview on stderr under `--json`

### U30 — Implement `verify <bundle> [--online] [--live]` CLI
- Milestone: M3
- Size: M
- Deps: U1, U2, U3, U4; R: full offline verification API + verdict rendering + online must-agree checks (R21); S: `--live` re-fetch (S15); A: online Bitcoin-block confirmation path (via R's API)
- Spec: Core user flows 5 (line 38); Verifier page online mode (line 137); M3 (line 156); CLI surface (line 149)
- Do: Implement `verify`: load the bundle file, run R's full offline verification, and render R's verdict output (one headline, per-anchor states, redaction view data — wording owned by R). `--online` activates R's two-pinned-must-agree endpoint confirmation (endpoints from U4 config overrides or R's pinned defaults; disagreement renders as R specifies). `--live` (CLI-only) drives S's re-fetch + byte-compare for the storage-linkage layer. `verify` must run with **no vault present** and never prompts. Finalize the verdict-class → exit-code mapping (open decision 13) so CI/scripts can gate on results; register the `--json` verdict fixture (machine-readable verdict data from R).
- Accept:
  - runs on a vault-less machine against R's golden bundles (valid, tampered, UNANCHORED, pending-only) with correct verdict rendering and mapped exit codes; tampered → nonzero
  - `--online` endpoint-disagreement fixture renders the advisory distinctly (M3 verification item); `--live` mismatch (mock) fails the storage-linkage layer distinctly from the evidence layer
  - `--online`/`--live` off by default; `--live` without network → clean error, offline verdict unaffected
  - `--json` fixture registered; CLI verdict output bit-consistent with R's snapshot-tested wording (no U-local paraphrase)

### U31 — Continuous positioning-and-copy conformance
- Milestone: continuous
- Size: S
- Deps: U1; R: verdict wording ownership boundary (R18); Q: docs positioning language (Q20)
- Spec: Positioning constraints (line 28); Verifier page (lines 127–137)
- Do: Maintain a single catalog module of all user-facing CLI strings (consent texts, warnings, nags, errors, help copy) so copy is reviewable in one place, and enforce discipline on every addition: possession language ("holder of key X possessed this content by time T"), never "notary", never unqualified "priority". Add a CI lint that greps the catalog and help output for banned tokens (`notar`, standalone "priority" flagged for review) and a checklist gate for new strings. Applies to every task above that adds copy (U11, U14, U15, U18, U22, U25, U29).
- Accept:
  - banned-token lint in CI; seeded violation fails
  - all snapshot-tested copy sourced from the catalog; new-command PRs adding uncataloged user-facing strings fail the lint
- Notes: Verdict wording stays R's — the catalog embeds R's strings verbatim, never rephrases them. Complementary to Q20's repo-wide style guide + lint — implement the lint once, apply to both scopes.

### U32 — Freeze CLI UX for release: help/JSON/exit-code freeze and final audits
- Milestone: M4
- Size: M
- Deps: U1–U30, U21, U31; Q: docs cross-check + release/CI gates (Q28/Q31); S/Q: clean-machine + disk-loss drill execution (Q32)
- Spec: M4 (line 157); Verification M4 gate (line 175); Positioning (line 28)
- Do: Final release pass on the CLI surface: freeze and document the exit-code table, every `--json` schema, and all help text (snapshot baselines become compatibility promises); confirm release default `--network arbitrum-one` and that `--no-anchor` remains hidden and mainnet-rejected in the release build; run the final positioning + secret-hygiene audits (U21/U31 extended over M2/M3 surfaces: status, show, reveal, verify); polish the `init` → `vault import` → `restore` path that the M4 clean-machine and disk-loss drills (Q/S-run) exercise, fixing any UX defects they surface.
- Accept:
  - exit-code and JSON schema docs shipped with the release; CI schema-freeze check active
  - hygiene harness green across the full command set at trace verbosity
  - drill feedback items closed; release binary's `--help` snapshot matches the frozen canonical surface exactly
- Notes: Binary signing, sha256sums, and distribution channel are Q's (Q30/Q31).

## Open decisions (U) — each: the decision, blocking task IDs, milestone it must land by
1. `init` interaction model — pure interactive wizard vs convenience flags (canonical surface enumerates no `init` flags) — blocks U1, U11 — M1
2. KDF selection mechanism — how the scrypt N ≥ 2²⁰ alternative is chosen at vault creation, and behavior on machines that cannot allocate Argon2id's 256 MiB — blocks U6, U11 — M1
3. Non-interactive passphrase supply for scripts/E2E (env var vs fd vs keystore; `--yes` covers confirmations only) — blocks U7, U13 — M1
4. Vault encryption-boundary partition — whether config and anchor artifacts (`.ots`, TSA tokens; no key material) sit inside or beside the passphrase AEAD, and therefore whether the every-invocation upgrade hook can run without an unlock (hook must never add a passphrase prompt) — blocks U5 (M1), U24 (M2)
5. Staged-ciphertext retention after successful `finalize_batch` — keep as local cache (serves `show` snippets, reveal/restore without network) vs prune (lean vault) — blocks U9, U27, U28 — M1
6. Wallet import format(s) — raw hex private key only vs also mnemonic — blocks U11 — M1
7. Resume detection keying (match incomplete work by input paths vs interactive selection) and whether resume-before-pay re-runs the consent gate (proposed: yes) — blocks U17 — M1
8. Directory arguments to `seal <path>…` — recurse vs files-only error — blocks U13 — M1
9. `vault export` format — verbatim encrypted-store archive under the existing passphrase vs re-encrypted single file with optional separate passphrase — blocks U12 — M1
10. `restore` default output directory and overwrite policy — blocks U20 — M1
11. `--dry-run` network semantics — call `quote_batch` for a true cost (proposed) vs fully offline estimate — blocks U16 — M1
12. `--units` syntax (comma list per spec example; ranges like `3-5` in or out for MVP) and `reveal` default output filename when `-o` absent — blocks U28 — M3
13. Verify exit-code mapping per verdict class — in particular whether UNANCHORED (integrity-only) exits 0 or a distinct nonzero — blocks U2 (scheme reserves the space), U30 — M3
14. OS-keystore platform scope for the `W` wrap (Linux Secret Service / macOS Keychain / Windows at MVP?) — blocks U8 — M1
15. `--json` × interactivity contract — prompts on stderr, and whether consent-bearing commands under `--json` without `--yes` always hard-abort (proposed: yes) — blocks U3, U14 — M1

## Cross-domain expectations
- P: final product name decision (binary, `~/.antseal/` dir, crate names) before M1 code lands; workspace scaffold with `antseal-cli` crate and pinned deps (clap, tokio, tracing, argon2, scrypt, keyring)
- C: zeroizing secret types (`W`, unit keys, `k_m`, wallet key, passphrase buffers) with redacted `Debug`; XChaCha20-Poly1305 AEAD + HKDF sub-key derivation usable for vault encryption and wallet sub-key; unit/manifest encryption and hybrid signing invoked by the seal pipeline
- G: canonicalization + `--split blank-lines` / `--force-text` / per-file `--no-fine-tree` option semantics; unit tables and byte totals for consent and `show`; fine-tree cost estimator for U15
- F: manifest body build/sign/encode, `work_id`/`anchor_digest` computation, deterministic-CBOR codecs the pipeline calls
- S: batch-first `StorageBackend` (`quote_batch`/`pay`/`finalize_batch`/`get_data`); ciphertext-address computation for all blobs; ANT + ETH balance queries with distinct insufficient-token/insufficient-gas error classes; journal/resume/abandon business logic incl. the `(k_u,nonce)` single-use guard; restore engine with commitment verification; network → contracts/RPC mapping schema for config; wallet keygen/import validation/address derivation
- A: TSA submission client with per-TSA results and configurable list; OTS calendar submit + pending `.ots` production; bounded-time opportunistic upgrade API; per-anchor verdict-state machine consumed by `status`/`list` nags
- R: bundle builder with selection rules (raw-mirror inclusion rule, `--include-receipt`) and disclosure-preview computation; full offline/online/live verification APIs with verdict taxonomy wording and machine-readable verdict data; canonical verifier page URL constant printed by `reveal`
- Q: docs (vault loss/theft, funding, wallet hygiene, positioning limits, compelled disclosure); M1 devnet kill-test E2E harness and M4 clean-machine/disk-loss drills that drive U11/U12/U13/U20; CI wiring for snapshot, schema-freeze, hygiene, and copy-lint checks; threat-model doc consuming U's degraded/UNANCHORED behaviors
