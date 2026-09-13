# Clean-machine verification — evidence record (template)

Copy this file, fill every field **during** the run (never afterwards from
memory), and file the copy with the `Q34` gate evidence. Instructions for each
step: [`clean-machine-verify.md`](clean-machine-verify.md). A field that does
not apply is written `n/a` with one line saying why — never left blank.

**Provenance rule.** Every captured value names where it came from: the
command as typed, the UTC time it ran (`date -u +%Y-%m-%dT%H:%M:%SZ`), and the
file under `~/gate/evidence/` that holds its full output. Output is pasted
**verbatim** inside code fences — never paraphrased, never trimmed to the
"important" line. `REAL_EXIT` is read from `$?` immediately after the command.

**No secrets, no personal identifiers.** No passphrase is used anywhere in this
procedure. The operator is a role; the machine is a description; the account is
`user`. Public keys, digests, versions and commits are not secrets and are
recorded in full.

## Run identity

| Field | Value |
| --- | --- |
| Run start (UTC) | |
| Run end (UTC) | |
| Operator (role, e.g. "non-author executor") | |
| Procedure followed (`clean-machine-verify.md` at commit, 40 hex, as shown where it was read) | |
| Gate packet part A received (UTC, channel described generically) | |
| Gate packet part B received (UTC, channel described generically — must differ from part A's) | |
| Terminal recording (`session.log` + `timing.log`: where filed) | |
| Screen recording (kind + where filed) | |
| Step 13 screenshots (file names + where filed) | |

## Gate packet part A (as received)

| Field | Value |
| --- | --- |
| Release tag (`TAG`) | |
| Release commit (`COMMIT`, 40 hex) | |
| Bundle SHA-256 (`BUNDLE_SHA256`) | |
| Work id (`WORK_ID`, 64 hex) | |
| Network sealed on | |
| Receipt included in the bundle (yes / no) | |

## Step 0–1 — machine

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| Hypervisor / host (generic description) | | |
| Base image file name | | |
| Base image SHA-512 — Debian's published value | | |
| Base image SHA-512 — measured | | |
| `PRETTY_NAME` from `/etc/os-release` | | |
| `uname -m` | | |
| `ldd --version \| head -1` | | |
| Browser and version (`firefox-esr --version`) | | |
| VM snapshot taken before step 1 (name) | | |

Step 1 output, verbatim (tool absence, state directory, credentials, repository-marker count):

```
(paste here)
```

## Step 2 — the checking tool

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| `.deb` file name | | |
| `.deb` SHA-256 — measured | | |
| `.deb` SHA-256 — pinned for `0.11-1` | `878264fbb6cfd39c7a67262f712ca73d1bfd0d8533f37c2a92c4af2b42b062fd` | from the procedure |
| Equal? (a newer package differing is a deviation, not a STOP) | | |
| `apt-cache policy minisign` (the line naming the Debian archive) | | |
| `minisign -v` | | |
| `curl --version \| head -1` | | |
| `dig -v` | | |

## Step 3 — the release is published

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| API URL fetched | | |
| HTTP status | | |
| `tag_name` | | |
| `draft` (must be `false`) | | |
| `prerelease` | | |
| `published_at` | | |

## Step 4 — release assets

`sha256sum` output, verbatim (`~/gate/evidence/downloaded.sha256`):

```
(paste here)
```

| Asset | Size (bytes) | Present? | Notes (name differs from the procedure's, etc.) |
| --- | --- | --- | --- |
| Linux archive | | | |
| Linux archive `.minisig` | | | |
| `SHA256SUMS` | | | |
| `SHA256SUMS.minisig` | | | |
| `minisign.pub` | | | |
| `minisign.pub.ots` | | | |
| page manifest (`verifier-web-SHA256SUMS` or as named) | | | |
| page manifest `.minisig` | | | |
| module (`antseal_wasm_bg.wasm` or as named) | | | |
| module `.minisig` | | | |

- [ ] No `DOWNLOAD FAILED` and no `REFUSED` lines
- [ ] `tarball_url` / `zipball_url` ("Source code") were **not** downloaded

## Step 5 — the key

`dig +short TXT antseal.org`, verbatim:

```
(paste here)
```

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| Well-formed `antseal-minisign-key=` records (must be `1`) | | |
| Key length (must be `56`) | | |
| Key (`KEY`, 56 characters) | | |
| `minisign.pub` line 2 equal to the `TXT` key? (`KEY-MATCH` / `KEY-MISMATCH`) | | |
| `dig +short DS antseal.org` (empty = unsigned zone) | | |
| `minisign.pub.ots` SHA-256 | | |
| Proof state the release notes state for `minisign.pub.ots` (recorded, not verified) | | |

## Step 6 — signatures

6a, the human form, verbatim (both lines, then `REAL_EXIT`):

```
(paste here)
```

- [ ] The trusted-comment line names this `TAG`, this archive and this `COMMIT`

6b, the gate form — the manifest, verbatim (`REAL_EXIT`, the comment, `TS=` or the mismatch line):

```
(paste here)
```

| Artifact (as listed in `SHA256SUMS`) | `MATCH` / `NO-MATCH` line, verbatim |
| --- | --- |
| | |

`sha256sum -c SHA256SUMS`, verbatim, with `REAL_EXIT`:

```
(paste here)
```

## Step 7 — tamper arms (on copies)

| Arm | Expected | Observed, verbatim (minisign message, then the `gate_check` line) | REAL_EXIT | Rejected by its own message? |
| --- | --- | --- | --- | --- |
| T1 byte flipped (and no `PLANT DID NOT CHANGE THE FILE`) | `Signature verification failed`, 1; `NO-MATCH <archive> rc=1 got=[]` | | | |
| T2 trusted comment edited (grep count `1` first) | `Comment signature verification failed`, 1; `NO-MATCH <archive> rc=1 got=[]` | | | |
| T3a genuine signature presented for another artifact | `Signature and comment signature verified` naming `SHA256SUMS`, 0; `NO-MATCH <archive> rc=0 got=[antseal <TAG> SHA256SUMS …]` | | | |
| T3b genuine signatures held to another release's expectation | one `NO-MATCH <name> rc=0` per artifact, no `MATCH` | | n/a | |
| T3 replay of the previous release (previous tag: ____) | step 6a on it: verified, comment names the previous version, 0; `NO-MATCH <archive> rc=0 got=[antseal <previous tag> …]` | | | |
| T4 key that is not antseal's | `Signature key id in … is …` / `but the key id in the public key is E7620F1842B4E81F`, 1 | | | |
| T5 digest list | `<archive>: FAILED` + `WARNING: 1 computed checksum did NOT match`, 1 | | | |

On a first release the replay row is `n/a — first release`, **and** it is
listed under "Deviations and findings" as a gap: D71's replay case could not be
run.

## Step 8 — the binary

`tar -tzf` listing, verbatim (`archive-listing.txt`):

```
(paste here)
```

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| Absolute or `..` entries (must be `0`) | | |
| Installed binary SHA-256 | | |
| `~/bin/antseal --version`, verbatim | | |
| `REAL_EXIT` | | |
| Version equals `TAG` without its leading `v`? | | |
| glibc floor the release notes declare (quote them) | | |
| Machine glibc (step 1) at or above it? | | |

## Step 9 — the bundle

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| Bundle file name | | |
| Size (bytes) | | |
| SHA-256 — measured | | |
| Equal to `BUNDLE_SHA256`? | | |

## Step 10 — CLI, offline

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| How the network was detached | | |
| `CONTROL_EXIT` (must be non-zero) | | |
| `verify` `REAL_EXIT` (must be `0`) | | |
| Headline line, verbatim (kind must be `tsa`) | | |
| `verify --json` `REAL_EXIT` (must be `0`) | | |
| `"network"` (must be `"arbitrum-one"`) | | |
| `work_id` | | |
| Equal to `WORK_ID`? | | |

`ip -brief link`, verbatim:

```
(paste here)
```

`verify-offline.txt`, the whole file, verbatim:

```
(paste here)
```

The `verdict` member, verbatim:

```
(paste here)
```

## Step 11 — CLI, `--online`

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| Positive control HTTP status (must be `200`) | | |
| `REAL_EXIT` (must be `0`) | | |
| Upgraded OTS anchors in the bundle (count, from the offline anchor rows) | | |
| Any anchor reported refuted? (must be no) | | |

`verify-online.txt`, the whole file, verbatim:

```
(paste here)
```

## Step 12 — hosted page provenance

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| URL exactly as the address bar shows it | | |
| Certificate issuer / expiry (browser page-information dialog) | | |
| Page SHA-256 (`page.html`) | | |
| Page-manifest `index.html` digest from the release | | |
| Equal? | | |
| Footer label and digest, verbatim (`grep` output) | | |
| SHA-256 of the module decoded out of the page | | |
| Footer digest equal to the decoded module's? | | |
| Released module SHA-256 | | |
| Footer digest equal to the released module's? | | |
| Browser footer build line, verbatim (`antseal-core … · formats … · source …`) | | |
| `source` equal to `COMMIT`? | | |
| Bounded key count between the footer markers (must be `1`) | | |
| Footer key equal to `KEY`? | | |
| Re-fetched after the 600 s cache window? (only after a mismatch) | | |

Response headers, verbatim (`grep` of `page.headers`):

```
(paste here)
```

## Step 13 — hosted page, offline

| Field | Value | Captured (UTC) |
| --- | --- | --- |
| `CONTROL_EXIT` with the network detached (must be non-zero) | | |
| "This bundle was refused." shown? (must be no) | | |
| Page headline line, verbatim | | |
| Identical, character for character, to step 10's headline? | | |
| Anchor slots and states identical to the CLI's? | | |
| `bundle format version` line, verbatim | | |
| Screenshot file names | | |
| Optional "confirm online" run (overlay lines verbatim, or `n/a`) | | |

## Verdict

- [ ] Steps 1–13 each met their expected observable (no STOP reached)
- [ ] Every tamper arm was rejected with its own message; on a first release the replay gap is listed under deviations
- [ ] The headline kind is `tsa`, and the CLI and page headlines are identical
- [ ] `work_id` equals the packet's; the bundle digest equals the packet's
- [ ] The key came from the `TXT` record and matched the release and the page footer
- [ ] No repository resource was used (no clone, no source archive, no repository file, no credential)
- [ ] Terminal recording, screen recording and screenshots filed, and named above
- [ ] No secret material and no personal identifiers in this record
- [ ] The machine was destroyed or reverted (step 15)

**STOP reached at step:** ____ (or `none`)

**Verification verdict (PASS / FAIL):** ____

**Signed (role, UTC date):** ____

## Deviations and findings

Anything the procedure did not predict — a step that needed the author, an
asset named differently, a message worded differently, an extra prompt. Each
finding names its fix (usually an edit to `clean-machine-verify.md`, or a defect
in the release that reopens its row).

| # | Step | What happened (verbatim output where there is some) | Fix owed to |
| --- | --- | --- | --- |
| | | | |
