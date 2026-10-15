# D172 — The M4 gate runs on the **draft** release, whose assets reach the clean machine **by courier**; nothing is published — full or pre-release — before the gate's evidence is committed; after the consented publication a credential-less **channel witness** proves the published bytes are the gated bytes; one version, one signed set, ever

- **Status: RESOLVED. The orchestrator's lean fell on its premise, and its central
  step is unbuildable; the recorded question's premise held and its dilemma
  dissolved.**
  - **The recorded question** (`Q31` Notes, wave 35, found by the clean-machine
    procedure's lane): D166 §2 R2 has the pipeline publish a **draft**, `Q34`'s gate
    installs the release on a clean machine holding no credential, and a draft is
    invisible without push access — *"so resolving it means either publishing (at
    least as a pre-release) before the gate — an act with no rollback — or giving the
    clean machine a credential, which breaks the gate's own premise."* **The premise
    holds and is sharper than recorded**: three REST endpoints agree that drafts are
    served only to accounts with **push** access, so the only credential that could
    work is a write credential. §1.1.
  - **The two-option framing is incomplete.** A third route exists and the committed
    procedure already contains most of it: the gate packet already carries the bundle
    *"by any file transfer"*, and the procedure's integrity rests on three roots that do
    not depend on how bytes travel — the key from DNS, the trusted comment compared
    exactly against the packet's tag and commit, and `sha256sum -c`. §1.2.
  - **The orchestrator's lean — publish a pre-release from a release-candidate tag,
    gate it, then promote the same bytes — is UNBUILDABLE.** Every signature's trusted
    comment carries the version (`scripts/sign-release.sh:36`, `:250`); genuine
    signatures presented under another version are a whole-release replay that
    `scripts/verify-release.sh`'s self-test requires to be refused
    (`REJECT[manifest-comment]`, `:245-252`); the procedure's steps 6b and 8 STOP on it;
    a crate-version bump changes the CLI, the page module and the commit; and a flag
    flip ships a version string `docs/user/versioning.md` forbids. §1.3.
  - **"Acceptable because nothing claims it is the release" falls too**: a GitHub
    pre-release exists *"to notify users"*, its publication is broadcast on the public
    event stream with every asset URL, a minisign signature has no revocation (D71 §2
    R9), and a public mainnet-default candidate lets strangers seal on mainnet before
    the gate, against the spec's single accepted exposure. §1.4.
- **Date: 2026-09-15**
- Owner rows: **`Q31`** (the draft stands; the rulings a `release.yml` lane would
  otherwise get wrong), **`Q32`** (`Do` (b)'s procedure is rewritten to this sequence),
  **`Q34`** (its gate runs on the draft; publication follows the verdict).
- Related: **D71** (signing, the trusted-comment shape, no revocation), **D72** §2 R5–R6
  (one documented channel; the credential argument), **D141** §2 R1 and §3 item 6,
  **D166** §2 R2 (the draft), **`Q65`** (no rollback), MVP-SPEC.md line 175 (the M4
  gate) and line 180 (one pre-release mainnet exposure).

## 0. What was measured against

`HEAD` `3473ab2`. Planning lane P6 (wave 36) read the rows, D71/D72/D141/D166, the two
drill documents, `docs/user/release-checklist.md`, `docs/user/versioning.md`,
`scripts/sign-release.sh` and `scripts/verify-release.sh`; fetched GitHub's REST
documentation for releases and immutable releases (2026-09-15); and took live
anonymous reads of a third-party public repository's pre-release as a control. It made
GET requests only — no release, tag, dispatch or setting was touched. The orchestrator
re-read the procedure's unresolved-ordering section (`docs/drills/clean-machine-verify.md:74-90`),
its step 3 (`:248-261`), the signing script's trusted-comment line, the verifier's
replay arm, `Q34`'s `Do` and MVP-SPEC.md line 175 before this record was written.

## 1. What was measured

### 1.1 Drafts, pre-releases, and what anonymity can see

- **Drafts**, documentation only (no draft exists on this repository, and creating one
  is a write): *List releases* — *"Only users with push access will receive listings
  for draft releases"*; *Get a release by tag* — *"Get a published release with the
  specified tag"*; *Get a release* — *"Gets a public release"*.
- **Pre-releases**, live and anonymous, against a third-party public pre-release:
  lookup by tag `200` with `prerelease: true`; `releases/latest` skipped it for an
  older full release; an asset downloaded `200` from
  `release-assets.githubusercontent.com` and its SHA-256 matched the API's per-asset
  `digest`; the public events feed carried a `ReleaseEvent` `published` payload listing
  every asset URL.
- **Immutable releases** on this repository: `GET …/immutable-releases` answered
  **`200` with `{"enabled":false}`**, where the documentation says a disabled setting
  answers `404`. **A read-back of this setting must read the `enabled` field; the status
  code cannot fail.**

### 1.2 The route the framing missed

The packet (`clean-machine-verify.md:124-138`) already delivers the bundle by file
transfer and the tag and commit by a second channel; the one exclusion it gives a
reason for is the **key** (*"that route is under test"*). The procedure trusts DNS for
the key (step 5), exact equality of the trusted comment against the packet (step 6b)
and `sha256sum -c` (step 6) — none of which depends on which wire the bytes used. The
one property only a channel fetch can show is that the documented download works, and
**no route can show that before a publication**: a channel check is a check of a
publication, so every route runs it after something irreversible.

### 1.3 Why "promote the same bytes" cannot be built

1. Re-releasing a candidate's files under the final tag re-signs every `.minisig`,
   because the trusted comment is `antseal <version> <artifact> commit:<40-hex> <ts>`;
   the candidate's genuine signatures under the final version are the replay the
   verifier refuses. The final signatures are bytes the clean machine never checked.
2. A candidate crate version (`0.1.0-rc.1`) needs a bump commit for the final: a new
   CLI, a new `app_version`, a new source commit stamped into the page module.
3. The final crate version under a candidate tag breaks `versioning.md`'s one version
   in three places, and step 8 STOPs on a version that differs from the tag.
4. Flipping the candidate to a full release ships version `v0.1.0-rc.1`, which
   `versioning.md` and `release-checklist.md` (`v<major>.<minor>.<patch>` only) refuse.
5. The strongest variant — publish the **final** tag as a pre-release and flip it after
   the gate — is buildable, but the whole gate then runs **after** a broadcast,
   unrevocable publication, and a failure either burns the version or creates two
   genuine conflicting signed sets under one version, the downgrade shape D71 §2 R4
   exists to defeat. The courier route runs the same checks with strictly fewer
   irreversible acts before the verdict.

### 1.4 The spec and the checklist

MVP-SPEC.md line 175 gates on *"one small real mainnet seal, verified end-to-end from a
clean machine using only the released signed binary + the hosted verifier page"*, and
line 180 accepts **one** pre-release mainnet exposure. `Q34`'s `Do` orders the
clean-machine verification **before** *"Then complete the Q31 checklist, publish the
release"*. `release-checklist.md:387-389` (at `3473ab2`): *"Every row above is a gate precisely
because there is nothing after it."* — a sentence the implementing lane scoped to the
checklist's gate sections, because §2 R6's witness section now sits after them.

## 2. RULING

### §2 R1 — Nothing is published before the gate's evidence is committed

D166 §2 R2's `--draft` is **affirmed**. Until `Q34`'s evidence — the clean-machine
verdict included — is committed, no release for the candidate version exists in any
published state, full or pre-release. Publication is a separate maintainer act, with
in-the-moment consent, after that commit. *Check*: the clean machine's own anonymous
`releases/tags/$TAG` read records `404` at gate time (§2 R4).

### §2 R2 — The candidate's tag does not exist on the remote before publication

The draft carries `tag_name` and `target_commitish` (the 40-hex release commit); no
`refs/tags/v*` is pushed before publication. *Check*: `git ls-remote --tags origin
'refs/tags/v*'` is empty while the release is a draft; after publication the tag
resolves to the packet's commit. **[Corrected in place before this record landed,
2026-09-15, by the lane implementing it]**: as first written the check was the whole
`refs/tags/v*` namespace, which is empty only before the **first** publication — after it,
earlier releases' tags exist. The check is per tag: `git ls-remote --tags origin
"refs/tags/$TAG" | wc -l` is `0` while that release is a draft. **Premise at risk**: that a draft creates no tag is
reported by third parties only; `Q31`'s dry run is its first observation, and its tag
shape (still owed) must be chosen so that observation consumes no release version.

### §2 R3 — Assets reach the clean machine by courier, never by credential

The release manager downloads the draft's asset set with their own credential on their
own machine and delivers it with the bundle as packet Part B; Part A is unchanged and
travels separately. The packet's exclusion rule becomes **"never supplies a key the
procedure trusts"** — `minisign.pub` may arrive as an asset, and step 5 still compares
it against DNS. **`Q32` `Accept` row 2's "released artifacts" is read as the
candidate's release asset set, byte-identified to the published set by §2 R6** — the
one interpretive ruling in this record, taken on `Q34`'s own `Do` order (verify, then
publish) and on the row's parenthetical contrasting input *categories* (released
artifacts versus a repository checkout), not publication states. **Reopen trigger**:
if the maintainer reads "released" as "already published", this record returns to a
decision, and the only compliant route is §1.3 item 5 with §2 R7 and §2 R11 taken
before the gate.

### §2 R4 — At gate time step 3 inverts

The anonymous `releases/tags/$TAG` read is expected to answer **`404`**, recorded
verbatim; step 4 reads Part B and never `browser_download_url`, and records the Part B
inventory as `courier.sha256`.

### §2 R5 — A drift check immediately before publication

The draft's asset names, count and SHA-256 must equal `courier.sha256` (the API's
per-asset `digest` if drafts carry it — not established — otherwise an authenticated
download and `sha256sum`). A non-empty difference means do not publish; re-gate.

### §2 R6 — After publication, a channel witness — a witness, not a gate

A credential-less machine (the kept gate VM, or a fresh one with the reason recorded)
runs the original channel steps: `200`, `draft: false`, `prerelease: false`, `tag_name`
equal to the packet's; every asset downloaded from `/releases/download/$TAG/`; the name
set, every `sha256sum` and every anonymous API `digest` equal to `courier.sha256`;
`releases/latest` naming the tag. The success metric's `release_date` and any "gate
passed" sentence in the release notes are written only after it passes. **Replacing a
published asset's bytes in place is forbidden** — it voids the witness's own premise.
A red witness is detection, not rollback: the remedy is a new version.

### §2 R7 — One version, one signed set, ever

Once an artifact set signed under a version has left the maintainer's machine — the
courier handoff counts — that version is never signed again over different bytes or a
different commit. A candidate that fails the gate after handoff consumes its version.
Re-running the gate on the same signed set is allowed. *Check*: across committed gate
evidence, each tag maps to exactly one (commit, timestamp).

### §2 R8 — No release-candidate tag kind

`versioning.md` §4 keeps exactly two tag kinds. A release candidate is a draft carrying
the final `v<major>.<minor>.<patch>` name. The pre-release route is refused on §1.3 and
§1.4.

### §2 R9 — The smoke seal is made with the candidate, and the gate reads it back

The single mainnet smoke seal uses the draft's binary — never a public pre-release,
never a development build — and the procedure's offline-verify step checks
`"app_version":"antseal/<tag without v>"`. The report says that field is the sealer's
own text checked against nothing, so this catches an honest wrong-build seal, not a
lying sealer.

### §2 R10 — No credential of any kind on the clean machine

Refused permanently, on the sharper reason: a draft needs **push** access. Step 1 adds
that neither `GH_TOKEN` nor `GITHUB_TOKEN` is set.

### §2 R11 — Immutable releases are decided before the first publication

The maintainer decides and records it before the first publication; recommended
**enable** (GitHub's immutable flow is draft → attach → publish, exactly §2 R1 with
D166 §2 R2, and it makes §2 R7 mechanical). Read back on the field:
`gh api repos/aed900/antseal/immutable-releases --jq .enabled`. That setting is an
external act and this record is not consent; entitlement is not established.

## 3. What turns each rule red

§2 R1/R4 — a `200` at gate time; §2 R2 — the candidate's own tag on the remote while that
release is a draft, or GitHub creating one at draft time (premise falsified: re-rule); §2 R3 —
a credential path, a key mismatch, or a Part B file absent from the draft; §2 R5 — a
non-empty digest difference; §2 R6 — any inequality after publication; §2 R7 — two
evidence records sharing a tag with different commits; §2 R8 — a suffixed tag or any
`prerelease: true` release; §2 R9 — an `app_version` other than the tag's; §2 R10 — a
token variable present; §2 R11 — `.enabled` false at first publication with no recorded
decision, or a read-back that asserts on the status code.

## 4. What this record does NOT decide

The dry-run tag shape; the release asset names; the dated runner image and the glibc
floor; the licence venue's collision with `scripts/pages-publish.sh`'s file-set check;
whether draft assets carry `digest`; whether draft creation appears in the public event
stream; whether this account may enable immutable releases. And a trap recorded for the
future `release.yml` lane: GitHub's *Create a release* answers `404` when the target
commit changes `.github/workflows/` and the token cannot modify workflows — a `404` that
does not mean "not found".

## 5. Edit list — per write scope, with the lane named before this record was written

### L-REL (the release-procedure documentation lane — these four files only)
- `docs/drills/clean-machine-verify.md`: the unresolved-ordering section replaced by
  this sequence; claim 1 (courier at the gate, the channel at the witness); the
  permitted and forbidden inputs (Part B's draft assets; token variables forbidden);
  the packet's exclusion rule; step 3 per §2 R4; step 4 reading Part B and writing
  `courier.sha256`; the offline-verify step's `app_version` line per §2 R9; a new
  closing section for the §2 R6 witness.
- `docs/drills/clean-machine-verify-evidence-template.md`: step 3's heading and
  expectation, step 4's courier digests, the `app_version` paste line, a witness block.
- `docs/user/release-checklist.md`: the credential row gains the courier and the gate's
  `404`; a §2 R5 drift-check row before publication; §2 R7/R8 in the tag section; a §2
  R11 row read back on `.enabled`; a new section *After publication — a witness, not a
  gate* per §2 R6, which says it detects and cannot undo; one sentence pointing at it
  from the no-rollback paragraph.
- `docs/user/versioning.md` §4: one paragraph stating §2 R7/R8.

### Registrar — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, dated addenda
- `Q31`, `Q32`, `Q34` Notes per §2 R1–R4.
- Dated addenda on D166 §2 R2 (the draft affirmed against the visibility objection),
  D141 §3 item 6 (draft visibility now documented, still not live-measured, and no
  longer needed) and D72 §2 R6 (the credential argument now concerns a draft needing
  push access, answered by courier).
- `docs/instrument-ledger.md`: `immutable-releases` answers `200` with `enabled:false`
  where its documentation promises `404`.
- Index row and register row for this record.

## Closing — this record is not consent

It creates no release, tag or setting. Publication, the immutable-releases setting and
every other act it names need the maintainer's express consent naming the action, the
destination `github.com/aed900/antseal` and the account `aed900`.
