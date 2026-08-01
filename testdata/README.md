# testdata/

Fixture tree for antseal (MVP-SPEC.md line 57: "golden vectors, UTF-8
corpus, tamper matrix, fine-tree range-proof fixtures"). Layout and
conventions are owned by Q (Q2); fixture *content* is contributed by the
component domains named per directory and lands with their milestones.

This file supersedes the P5 stub layout (which sketched `golden/` and
`tamper-matrix/`; those names were never populated — the authoritative
homes are `vectors/<format-version>/` and `tamper/` below).

## Layout and ownership

| Directory | Contents | Contributors |
| --- | --- | --- |
| `vectors/<format-version>/` | Golden vectors in the Q4 envelope schema (see `vectors/README.md`): today the migrated HKDF label vectors (`v1/hkdf/`); next manifest/bundle (F12/F13), crypto (C16), fine-tree/canonicalization (G3/G15), report (R), anchor (A, M2) kinds. Retained forever, per version (policy below), frozen per version by Q6's `FROZEN.sha256`. | F, C, G, A, R (harness: Q) |
| `utf8-corpus/` | UTF-8 canonicalization corpus: CRLF, NFD-vs-NFC, BOM, emoji/ZWJ, mixed scripts — idempotence + cross-platform stability inputs (MVP-SPEC.md line 170). | G (G3) |
| `tamper/` | Tamper-matrix fixtures: pre-mutated manifests/bundles/tokens for the Q7 harness; every mutation must fail with its distinct expected error. Q8's `MATRIX.json` completeness registry (the spec's M0/M2 enumeration mapped 1:1 onto implemented rows) lives here — see `tamper/README.md`. | Q (harness + registry), rows fed by F, C, G, A, R |
| `fine-tree/` | Fine-tree fixtures that are **not** Q4 vectors (e.g. bulk streaming corpora for G18). G15's range-proof golden vectors — leaf/node domain separation, boundary ranges, and the unbalanced n=6 MSB-first GGM vector (MVP-SPEC.md line 169) — landed in the envelope as `vectors/v1/fine-tree/`, per contribution rule 5; see `fine-tree/README.md`. | G (G15, G18) |
| `anchors/` | **Reserved for M2**: recorded real OTS calendar responses, `.ots` upgrade states, and TSA tokens (FreeTSA ECDSA P-384, DigiCert) captured per the Q16 runbook, replayed by CI so the anchor lane never touches real anchor networks. | A (A24/A25) |
| `fuzz-seeds/` | Committed fuzz seed corpora, one subdirectory per cargo-fuzz target; seeded from golden vectors + tamper fixtures, minimized per the Q9 cadence. | Q (Q9), targets from F (M0), A (M2) |

Byte-exactness guard: `.gitattributes` sets `testdata/** -text`, so fixture
bytes survive checkout unchanged on every OS (the Windows CI image sets
`core.autocrlf=true`). Never remove that guard; it covers every current and
future path under `testdata/`.

## Contribution rules

1. **Nothing here is ever silently skipped.** Vector files must conform to
   the envelope schema (`vectors/README.md`); unclassifiable files under
   `vectors/` fail the runner. Put prose in `README.md` files, generators
   in `*.py`.
2. **Fixtures are deterministic**: seeded RNG only, no time/machine
   dependence; independent reference generators are committed beside their
   output and are run to *verify*, never to silently regenerate.
3. **Committed vectors are append-only once frozen** (Q6): a byte change to
   a frozen fixture is a format event with an explicit justification and a
   format-version bump, never a drive-by regeneration. See the retention
   policy below.
4. Cross-OS-sensitive suites consume fixtures via tests whose names carry
   the reserved `corpus_`/`vector_` markers (CONTRIBUTING.md) so the
   three-OS CI lane proves byte-identical behavior.
5. New fixture *categories* (top-level directories) are a Q-reviewed layout
   change to this README, not an ad-hoc mkdir.

## Vector retention policy (Q6 — normative)

MVP-SPEC.md line 123 makes format stability normative ("every released
manifest/bundle format version remains verifiable by all future CLI and
page releases"), and line 167 requires "empty-anchor and per-version
vectors retained in CI forever". Concretely:

1. **`vectors/v<n>/` is the unit of retention.** A format-version directory
   is kept **indefinitely** once created. Nothing ages out, is archived, or
   is pruned — not when a newer version lands, not when the old format
   stops being *emitted*. Old bundles must keep verifying, so the vectors
   that pin the old format must keep running.
2. **Every future release's CI runs all of them.** Discovery is a directory
   walk in both the Q4 runner and the Q6 freeze guard, so a retained
   version needs no per-version wiring and cannot be forgotten. Adding
   `v2/` neither disturbs nor releases `v1/`.
3. **Freezing is per version.** Each version directory carries its own
   `FROZEN.sha256`, which pins each vector's bytes *and* serves as that
   version's must-exist list (a deleted file is caught there, since a
   runner can only fail on files it finds). A version directory without a
   manifest is a hard CI failure. Mechanism, directive vocabulary, and the
   before/after-Q14 rules: `vectors/README.md`.
   Alongside it each version carries an `INDEX.json` **roster** (F10): what
   exists, who owns it, what it pins, and what the version still owes. The
   two are mutually enforcing (`tests/vector_index.rs`) and the roster's
   `format_version` must name a version
   `antseal_core::format::SUPPORTED_VERSIONS` lists — so a retained
   version's vectors and its decoder can never drift apart.
4. **`vectors/README.md` is the authoritative statement of this policy's
   mechanics**; this section states the policy itself. **Q27** (format-
   stability policy doc) must reference both rather than restate them, and
   owns the *criteria* for cutting a new version — retention and freezing
   are settled here.
5. **Deleting a retained version is not a maintenance action.** It would
   silently drop the guarantee that its format still verifies; the only
   thing that could ever justify it is a decision record saying the version
   was never released.

## Secret-material convention (project rule 6 — normative)

Real secret material — a real master secret `W`, unit keys, salts derived
from real secrets, vault exports, wallet keys/keystores, mnemonics — must
**never** be committed anywhere in this repository, fixtures included.

- **Every fixture secret derives from the documented fixed test seed**: the
  32-byte pattern `00 01 02 … 1f` (`0x00..=0x1F`), exposed to Rust tests as
  `antseal_core::test_util::TEST_MASTER_SECRET_W`. Fixture values that are
  secret-*shaped* (a `W`, a key, a salt, a seed) are either this seed
  itself or deterministically derived from it via the crate's own public
  derivation functions. (In-memory values generated by property-test
  strategies during a test run are fine — this convention governs
  *committed* material.)
- **Label it**: every vector file carries a `non_secret` field containing
  the `NON-SECRET` marker (schema-enforced); non-vector fixture files and
  generators state it in a header comment; directory READMEs repeat it.
- **No real vault or wallet material, ever** — not even "expired" or
  "empty" ones. The CI `secret-guard` lane greps the tree for
  vault-export/wallet-key file signatures (PEM private-key blocks, EVM
  keystore JSON, age/minisign secret keys, and the reserved antseal
  vault-export magic `ANTSEAL VAULT EXPORT`, which the U-domain vault
  format must embed precisely so strays are detectable) and fails on any
  hit; the lane self-tests by planting fakes in a temp directory each run.
  Prose (`*.md`) and the workflow file itself are excluded from the scan so
  formats can be *discussed*; if source code ever legitimately needs a
  matching literal (e.g. a keystore import parser), extend the guard's
  exclusions in the same PR as a reviewed event.
  **Recorded exclusion events:** [2026-08-01, U12] the vault-export magic
  literal landed in `crates/antseal-cli/src/vault/export.rs` (the module
  that defines `EXPORT_MAGIC`); the guard excludes exactly that path from
  pattern (3), by exact path rather than basename, in the same commit.
  Tests and every other source file reference the constant, never the
  literal — a second literal occurrence anywhere is still a scan failure.
- Anchor fixtures (M2) contain real *public* cryptographic material (TSA
  certificates, timestamp tokens, calendar proofs over fixture digests) —
  that is fine; the rule bars *private/secret* material only.
