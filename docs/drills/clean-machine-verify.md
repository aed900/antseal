# Clean-machine verification (Q32 Do (b))

**Status: WRITTEN, NEVER EXECUTED — and it CANNOT be executed today.** This
procedure has not been run by anyone. Writing it is the closed half of Q32
Do (b); *executing* it and *recording the walkthrough* is the open half of
Q32 Accept rows 2 and 3, and it belongs to the Q34 gate run. Four of its
preconditions are false as of 2026-09-13 (see "Why it cannot run today"), so
the first honest outcome of following it today is a STOP at step 4: no draft
release exists, so the courier has nothing to deliver. Nothing
in this document is evidence that a clean-machine verification has ever
succeeded. The first execution will find wrong assumptions; fix this
document, then re-run — never adjust the evidence to fit the document.

## What this procedure proves, and what it does not

The claim under test is the M4 gate's (`TODO.md`, M4 `Gate =` line;
`MVP-SPEC.md` lines 157 and 175): the gate's one mainnet smoke-seal bundle is
**verified end-to-end from a clean machine using only the released,
signature-checked binary and the hosted page**, with the headline time coming
from a TSA token. Concretely, a machine with no repository, no credentials and
no antseal state can:

1. take the release candidate's binary and signatures delivered **by courier**
   (gate packet Part B) while the release is still an unpublished draft, and —
   after the consented publication — fetch the same bytes from the documented
   channel, GitHub Releases
   (`docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md:506-512`),
   in the channel witness at the end of this document (D172 §2 R3, §2 R6);
2. check its signature against the published key through the documented route
   (`docs/signing/verifying-a-release.md` §2–§4), refusing a key that is not
   independently anchored;
3. verify the bundle with that binary offline and with `--online`;
4. verify the same bundle on `https://antseal.org/` offline, and get the same
   headline line as the CLI.

It does **not** prove, and its evidence must not be read as saying:

- that the software is safe, correct or the newest release — a good signature
  says the key holder released these bytes and nothing more
  (`docs/signing/verifying-a-release.md:132-147`);
- that the binary corresponds to the published source — the CLI build is not
  reproducible (`docs/decisions/D71-binary-signing-mechanism-and-key-custody.md:630-647`);
- anything about persistence on Autonomi, or restore. **This procedure never
  runs `verify --live` or `restore`.** In the `ant-backend` build both are
  wired (D170 §2 R1–R7): `restore` reads over the work's recorded network
  through a reader that holds no wallet and cannot pay, and `verify --live`
  connects only after the bundle has verified offline
  (`crates/antseal-cli/src/commands.rs`, `fn restore` and `fn verify`). A
  build with no storage backend compiled in still refuses both (D170 §2 R4).
  On the default network both commands now resolve `arbitrum-one`'s built-in
  bootstrap peers — a byte-identical copy of the list upstream published at
  the pinned `ant-core`'s release tag, and nothing more is claimed about it:
  not that any listed peer is live, who operates it, or that it is authentic
  (D173 §2 R1–R3, §2 R16; `S40`) — and would then contact the public Autonomi
  network, which this procedure's network policy never allows. The release
  binary's storage gate (`ANTSEAL_NO_REAL_STORAGE_NETWORK`, D173 §2 R9) does
  not stand in the way: unset, it arms only a build with debug assertions.
  Restore is the disk-loss drill's subject
  ([`vault-restore-drill.md`](vault-restore-drill.md));
- who wrote the sealed work, or that nobody else held it. A seal proves the
  holder of the sealing key possessed the content by the proven time — not
  authorship, and not exclusive possession
  (`crates/antseal-core/src/verify/wording.rs:181-183`). Nor does it carry any
  legal effect: it is evidence of existence and integrity by a proven time,
  not a notarial act.

## Why it cannot run today (measured 2026-09-13)

| Step | Blocker | Measurement | Owner |
| --- | --- | --- | --- |
| 4–8 | **No draft release exists**, so gate packet Part B cannot carry release assets. | `GET repos/aed900/antseal/releases` returned an empty list; the remote's only tag is `format-v1-freeze` (no `v*` tag). The release workflow is `Q31`'s and has not landed. Re-read 2026-09-14 (UTC): an empty list both anonymously and with an account that has push access. Only the second read can see a draft (D172 §1.1). | `Q31`, then `Q34` |
| 5 | **The key's independent pin does not exist.** | `dig +short TXT antseal.org` returned nothing, while the same query for `github.com` returned records (the resolver answers TXT). `dig +short DS antseal.org` returned nothing (not DNSSEC-signed). | maintainer, `docs/signing/maintainer-key-procedure.md` §2 (`Q30`) — an external act at the registrar |
| 12 | **The live page is stale and its stated commit cannot be fetched.** | `https://antseal.org/` serves 2 516 397 B, SHA-256 `ea7e9447584be131443a6948c70ea2f5a624882d6ea7d1f953e6c08d04f43951`, `last-modified: Sat, 15 Aug 2026 08:02:40 GMT`. Its footer reads `page build` with digest `70235b8b6192b983b1d1eb3b926e5e5925257cd806b6763eeb2aff76539403c0`, which does equal the SHA-256 of the module embedded in the page (1 853 031 B). The module carries the source stamp `9317a35b3adaef56b03eaa22a80a2b76e232a7d9`, which `GET repos/aed900/antseal/commits/<that id>` answers with HTTP 422 "No commit found" (the current `main` head resolves). The page carries no `minisign-public-key` marker at all, and its footer label predates the `module build` label the template now has (`verifier-web/index.template.html:150`). The last deploy was run `31873422229` on 2026-08-15 (`tasks/R.md`, `### R26 —` Notes). | a redeploy from the release commit, owed before the gate |
| 9–13 | **No gate bundle exists.** | The mainnet smoke seal has not been performed; it needs a funded wallet (`Q33`) and an `ant-backend` build. | `Q34` |

What that means for a digest comparison **today**: the footer digest is
internally consistent (the page carries the module it names), but the
documented reproduction — build at the deployed commit and compare
(`docs/user/release-checklist.md`, section B) — cannot be performed as written,
because the deployed commit cannot be fetched. A stamp is supplied rather than
discovered (`crates/antseal-wasm/build.rs:8-14`), so the digest reproduces only
at the commit it was built from and at no other
(`docs/user/versioning.md` §5). Treat the live digest as unreproducible
until a redeploy publishes a digest labelled with a commit that exists.

## The release order this procedure runs in (D172)

The first version of this document found an ordering it could not resolve. The
release checklist gates publication on this procedure's evidence
(`docs/user/release-checklist.md`, section A), and `Q34`'s `Do` runs the
clean-machine verification before "publish the release" (`tasks/Q.md`,
`### Q34 —` Do). But `Q31`'s pipeline creates a **draft** release, and GitHub
serves a draft only to accounts with **push** access ("Only users with push
access will receive listings for draft releases" — GitHub REST API
documentation, *List releases*; *Get a release by tag name* documents "Get a
published release with the specified tag"). A machine holding no credential
cannot see a draft. D172 resolves this without publishing first and without a
credential. The run happens in this order, and no step of it may be reordered:

1. **Draft.** The release pipeline builds and hashes the artifacts and creates a
   **draft** release; the maintainer signs locally and attaches the signatures
   (D166 §2 R2's draft, affirmed by D172 §2 R1). No `v*` tag for the candidate
   is pushed while it is a draft (D172 §2 R2).
2. **Smoke seal.** The one mainnet smoke seal is made with the draft's binary —
   never a public pre-release, never a development build (D172 §2 R9).
3. **Courier.** The release manager downloads the draft's assets with their own
   credential, on their own machine, and delivers them with the bundle as gate
   packet Part B (D172 §2 R3).
4. **This procedure.** At step 3 the release must **not** be published yet: the
   anonymous read of the tag answers `404` (D172 §2 R4).
5. **Evidence committed.** The gate's evidence, this procedure's evidence file
   included, is committed. Nothing for this version is published — as a full
   release or as a pre-release — before that commit (D172 §2 R1).
6. **Drift check.** Immediately before publishing, the release manager confirms
   the draft's asset names, count and SHA-256 still equal `courier.sha256` from
   this procedure's evidence. A difference means do not publish; re-gate
   (D172 §2 R5).
7. **Publication.** The maintainer publishes the draft, with express consent
   given at that moment. This procedure is not that consent.
8. **Channel witness.** A machine with no credential runs "After publication:
   the channel witness" at the end of this document (D172 §2 R6). It is a
   witness, not a gate: it can detect that the published release is not the
   gated one, and it cannot undo the publication.

Two shortcuts are refused, and a STOP in this document is never a reason to
take either. **Publishing a pre-release first**, so that this machine can
download it, is refused: a pre-release is a broadcast, unrevocable publication
made before the verdict. A candidate published under a version of its own
cannot be promoted either: its signatures name that version, so presented as
the final release they are the replay steps 6b and 8 refuse, and re-signing
them makes files this procedure never checked (D172 §1.3, §2 R8).
**Giving this machine a credential** is refused: a draft needs push access, so
the only credential that would work is one that can change the repository
(D172 §2 R10).

**One version, one signed set.** Once the courier has handed this set over, a
candidate that fails this procedure uses up its version: that version is never
signed again over different files or a different commit. Re-running this
procedure on the same signed set is allowed (D172 §2 R7).

## Zero repository resources, concretely

`Q32` Accept row 2: *"Clean-machine procedure uses zero repo-checkout resources
(released artifacts + hosted page only)"*. "Released artifacts" is read as the
candidate release's asset set, delivered by courier and shown byte-identical to
the published set by the channel witness (D172 §2 R3, §2 R6). If the maintainer
reads "released" as "already published", this reading and the order above
return to a decision.

**Permitted inputs, and nothing else:**

- the candidate release's assets — the draft's asset set, byte for byte — as
  delivered in gate packet Part B (D172 §2 R3);
- GitHub's unauthenticated API: at step 3 the read that must answer `404`, in
  step 7's replay arm (from the second release on) the previous, published
  release, and in the channel witness the published release;
- assets downloaded from `https://github.com/aed900/antseal/releases/download/`,
  only in step 7's replay arm and in the channel witness;
- the hosted page at `https://antseal.org/`;
- the `TXT` record on `antseal.org`;
- packages from the Debian archive;
- the gate packet below: which release to expect (Part A), and the bundle with
  the draft's assets (Part B).

**Forbidden, each a STOP:** cloning or fetching the repository; the release
page's auto-generated "Source code" archives (`tarball_url`/`zipball_url` —
they are the repository); any file from the repository, including
`scripts/verify-release.sh` (it needs the antseal source,
`docs/signing/verifying-a-release.md:86-93`) and this document itself; any key,
digest, version, commit or URL taken from the repository rather than from the
release assets, DNS, the page or the gate packet; a key the procedure trusts
taken from anywhere but the `TXT` record (step 5); the `gh` tool; any GitHub
login, token, SSH key or `.netrc` on the machine or in its browser, and a
`GH_TOKEN` or `GITHUB_TOKEN` variable in its environment. A draft is served
only to accounts with push access, so any credential that could see one could
also change the repository (D172 §2 R10).

Read this document on a **different** device. Type or paste its commands; no
file from the repository enters the clean machine.

## Who runs this

A **non-author**: someone who did not write antseal, did not build the release
and did not produce the bundle. If a step needs the author to explain it,
record that as a finding; the fix is to this document.

## The gate packet (assembled by the release manager beforehand)

Delivered out of band, in two parts over **two different channels**, so that
one compromised channel cannot substitute both a file and its digest:

- **Part A — statements** (e.g. read aloud, or on paper): the release tag
  (`v<major>.<minor>.<patch>`, `docs/user/versioning.md` §4); the 40-hex
  commit that release names; the bundle's SHA-256; the bundle's work id (64 hex);
  the network it was sealed on (`arbitrum-one` for the smoke seal); whether
  the bundle includes the Arbitrum receipt.
- **Part B — the files**, by any file transfer: the `.sealproof` bundle, and
  **every asset of the draft release**, exactly as the release manager
  downloaded them from the draft with their own credential on their own
  machine — nothing renamed, added, rebuilt or left out (D172 §2 R3). Keep the
  bundle apart from the assets, because step 4 records the assets alone.

The packet **never supplies a key the procedure trusts**, and it contains no
script and no repository file. The draft's own `minisign.pub` arrives in Part B
as one of its assets, but the key is still taken only from the documented route
(step 5), which compares it against the `TXT` record — that route is under test
(D172 §2 R3).

## The clean machine

### Base

**A fresh virtual machine, never used before, installed from official Debian
12 (bookworm) amd64 media**, whose image file is checked against Debian's
published `SHA512SUMS` before use. Why each property:

- **x86_64 Linux** — the only release target
  (`docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md:423-426`).
- **glibc at or above the release's declared floor.** The floor is `Q31`'s to
  choose and must be written into the release notes (`D72-…:437-462`);
  `GLIBC_2.34` was measured on a glibc 2.36 host (`D72-…:459-462`), which is
  evidence about that host and not a declared floor. Bookworm's glibc is
  2.36. If the release notes declare a floor above the machine's glibc, use a
  newer Debian release whose glibc meets it and record the deviation.
- **minisign from the Debian archive** — the tool pin the signing procedure
  was tested against: `0.11-1` on bookworm, `0.12-1` on trixie
  (`docs/signing/maintainer-key-procedure.md:262-268`).
- **A VM, not a container**, because step 13 needs a real browser with a
  display, and the gate's evidence must come from one machine.
- **Account name `user`** and a generic host name, so that nothing captured
  in a recording names a person (`user` is a reserved placeholder name,
  `scripts/check-personal-data.py:170`).

### Installed, and not installed

| Installed (Debian archive only) | Must be absent |
| --- | --- |
| `minisign`, `curl`, `ca-certificates`, `bind9-dnsutils`, `firefox-esr`, plus whatever desktop the operator needs to run the browser | `antseal` (until step 8), `git`, `cargo`, `rustc`, `rustup`, `gh`, any antseal state directory (`$ANTSEAL_DIR`, else `~/.antseal` — `crates/antseal-cli/src/vault/layout.rs:10,16,81-111`), any SSH key, `.netrc` or GitHub credential, a `GH_TOKEN` or `GITHUB_TOKEN` environment variable, any browser profile that has ever signed in to anything |

Everything else the procedure uses — `sha256sum`, `base64`, `dd`, `install`,
`grep`, `sed`, `awk`, `find`, `cmp`, `tar`, `ldd`, `script` — ships in Debian's
essential or required packages, and `ip` in `iproute2`, which every standard
installation carries.

### Network policy

| Phase | Steps | Network | Allowed destinations |
| --- | --- | --- | --- |
| setup | 0–9 | on | `deb.debian.org`; `api.github.com` (step 3's `404`; step 7's replay arm); `github.com` and `release-assets.githubusercontent.com` **only** for step 7's replay arm from the second release on (where release downloads redirect — measured 2026-09-13 on a third-party public release); `antseal.org`; DNS |
| offline verify | 10, 13 | **off** — detach the VM's virtual network adapter | none; proven by a control that must fail |
| online | 11 (and 13's optional online check) | on | `blockstream.info`, `mempool.space`, `arb1.arbitrum.io`, `arbitrum.drpc.org` (below) |
| channel witness | after publication (last section) | on | `api.github.com`; `github.com`; `release-assets.githubusercontent.com`; DNS |

## Procedure

Keep the evidence file open — a copy of
[`clean-machine-verify-evidence-template.md`](clean-machine-verify-evidence-template.md)
— and fill it **as you go**. Read every `REAL_EXIT` from `$?` immediately
after its command, never from memory. Every step names what you should see
(**Expected**) and when to stop (**STOP if**). A STOP ends the run: record
where and why, and do not continue to later steps.

**0. Start the recording.** Start a screen recording for the whole run. In the
terminal: `mkdir -p ~/gate/evidence && script -q -T ~/gate/evidence/timing.log ~/gate/evidence/session.log`.
Note the UTC time (`date -u`).
*Expected:* a recording running, and a shell inside `script`.
*STOP if* either recording cannot be made — Accept row 3 needs it.

Then, **inside the recorded shell**, set these once from gate packet part A:

```sh
TAG='<release tag, e.g. v0.1.0>'
COMMIT='<the 40-hex commit the release names>'
BUNDLE_SHA256='<64-hex bundle digest>'
WORK_ID='<64-hex work id>'
```

Later steps set `KEY` (step 5), `ART`, `TS` and `gate_check` (step 6) and `B`
(step 10). If the shell is ever restarted, set the four above again and re-run
the command that sets each later one before continuing.

**1. Machine identity and cleanliness.**

```sh
grep PRETTY_NAME /etc/os-release; uname -m; ldd --version | head -1
for t in antseal git cargo rustc rustup gh minisign; do command -v "$t" || echo "$t absent"; done
ls -d ~/.antseal 2>&1; echo "ANTSEAL_DIR=${ANTSEAL_DIR-unset}"
ls -d ~/.ssh ~/.netrc ~/.git-credentials ~/.config/gh 2>&1
env | grep -cE '^(GH_TOKEN|GITHUB_TOKEN)='
find / "$HOME" -xdev \( -name MVP-SPEC.md -o -name verify-release.sh -o -name '*.sealproof' \) 2>/dev/null | sort -u | wc -l
```

*Expected:* a Debian release, `x86_64`, a glibc version line; all seven tools
`absent`; `No such file or directory` for every listed path;
`ANTSEAL_DIR=unset`; `0` token variables (the count only — the command never
prints a value); `0` repository markers.
*STOP if* anything else — this machine is not clean. A token variable is a
STOP even if you believe it is read-only (D172 §2 R10).

**2. Install the checking tool from the Debian archive.** It must not come from
antseal (`docs/signing/verifying-a-release.md:18-21`).

```sh
sudo apt-get update
cd ~/gate && apt-get download minisign && sha256sum minisign_*.deb
sudo apt-get install --no-install-recommends ./minisign_*.deb curl ca-certificates bind9-dnsutils firefox-esr
apt-cache policy minisign; minisign -v
```

(`sudo` or a root shell, whichever the installation set up.)

*Expected:* `apt-cache policy` names the Debian archive; `minisign -v` prints
`minisign 0.11` on bookworm. The pinned `.deb` digest for `0.11-1` is
`878264fbb6cfd39c7a67262f712ca73d1bfd0d8533f37c2a92c4af2b42b062fd`
(`docs/signing/maintainer-key-procedure.md:268`).
*STOP if* the tool is older than 0.11 or did not come from the Debian archive.
A **different** digest for a newer Debian package is not a STOP — the pin
records what was tested, and apt's own signature checking protects the
download (`maintainer-key-procedure.md:270-278`) — record it as a deviation.

**3. Confirm the release is NOT published yet.** At gate time the candidate
is an unpublished draft, so an anonymous read of its tag must find nothing
(D172 §2 R4). This endpoint is documented as "Get a published release with the
specified tag", and a draft is never served to a caller without push access.

```sh
cd ~/gate/evidence
curl -sS -o release-tag.json -w '%{http_code}\n' "https://api.github.com/repos/aed900/antseal/releases/tags/$TAG"
cat release-tag.json
```

*Expected:* `404`, and a body whose `"message"` is `"Not Found"`. Record the
status and the body verbatim.
*STOP if* the status is `200`: a release under this tag is already published,
before its gate, which D172 §2 R1 forbids. Record the body's `draft`,
`prerelease` and `published_at` lines and tell the release manager; this run
cannot be the gate for that release. Any other status (`000` when curl could not
connect, `403` or `429` when rate-limited) is not an answer: wait five minutes,
run the command once more and record both attempts. A second status other than
`404` is a STOP.

**4. Stage the release assets from gate packet Part B.** Copy every asset file
from Part B into `~/gate/release/` — every file except the `.sealproof` bundle,
which step 9 stages. Download nothing at this step: the release is not
published, and a draft cannot be fetched without a credential (D172 §2 R3,
§2 R4). Never use `tarball_url` or `zipball_url`.

```sh
mkdir -p ~/gate/release && cd ~/gate/release
ls -la
find . -mindepth 1 \( ! -type f -o -name '.*' \) | wc -l
find . -mindepth 1 -name '*.sealproof' | wc -l
sha256sum -- * > ~/gate/evidence/courier.sha256; echo "REAL_EXIT=$?"
cat ~/gate/evidence/courier.sha256
```

*Expected:* `0` (nothing but plain files, and no hidden file); `0` (the bundle
is not among the assets); `REAL_EXIT=0`; one `courier.sha256` line per asset.
`courier.sha256` is the inventory of what the courier delivered. The release
manager's drift check before publication and the channel witness after it both
compare against this file (D172 §2 R5, §2 R6), so record it whole. The set a
release carries: `SHA256SUMS` and `SHA256SUMS.minisig`; every artifact with its own
`.minisig` (`D71-…:380-396`); `minisign.pub` and `minisign.pub.ots`
(`D71-…:480-485`, `:518-523`); the page's manifest, renamed
`verifier-web-SHA256SUMS` in the D71 proposal (`D71-…:398-405`); and the
pre-packaging module `antseal_wasm_bg.wasm` (`docs/decisions/D129-verifier-page-file-shape-and-the-in-artifact-csp.md:12-14`).
`Q31` fixes the real names, so record what is actually there. This document
writes the Linux archive as `antseal-x86_64-unknown-linux-gnu.tar.gz`, the
example name in `D71-…:412-415`.
*STOP if* either count is not `0`, or `SHA256SUMS`, `SHA256SUMS.minisig`,
`minisign.pub`, the Linux archive or the archive's `.minisig` is missing. Do
not fill a gap by downloading, and never accept a replacement file for one: a
Part B that is incomplete goes back to the release manager, and a new run
starts, on a clean machine, with the complete set.

**5. Obtain the key through the documented route — and stop if it is not
anchored.** **Today: this would STOP** — the `TXT` record does not exist.
The one publication of the key that does not share an account with the
binaries is the `TXT` record on `antseal.org`
(`docs/signing/verifying-a-release.md:101-118`; `D71-…:475-492`).

```sh
dig +short TXT antseal.org | tee ~/gate/evidence/txt.txt
sed -n 's/^"antseal-minisign-key=\(RW[A-Za-z0-9+/]\{54\}\)"$/\1/p' ~/gate/evidence/txt.txt | wc -l
KEY="$(sed -n 's/^"antseal-minisign-key=\(RW[A-Za-z0-9+/]\{54\}\)"$/\1/p' ~/gate/evidence/txt.txt)"
printf '%s' "$KEY" | wc -c
test "$(sed -n 2p minisign.pub | tr -d '[:space:]')" = "$KEY" && echo KEY-MATCH || echo KEY-MISMATCH
dig +short DS antseal.org
```

*Expected:* a `TXT` answer carrying `antseal-minisign-key=RW…`
(`maintainer-key-procedure.md:113-126`); `1`; `56`; `KEY-MATCH`. Record the
`DS` answer: empty means unsigned, which is the stated limit of this pin —
independent of the code host, not of an attacker on your network
(`verifying-a-release.md:115-118`).
*STOP if* the `TXT` answer is empty, the count is not `1`, the length is not
`56`, or `KEY-MISMATCH`. **Do not proceed on the release's `minisign.pub`
alone**: it travels beside the binary — in Part B here, and from the same
account once published — so a substituted key and a substituted binary verify
against each other (`D71-…:480-485`). The page
footer's copy is compared in step 12. `minisign.pub.ots` shows the key is old,
not whose it is (`D71-…:539-543`); verifying it needs an OpenTimestamps client
this procedure does not install, so record its SHA-256 and the proof state the
release notes state (`maintainer-key-procedure.md:165-169`) — it is not a gate
condition.

**6. Check the signatures: the human read, then the gate's form.**

6a — the documented human command (`verifying-a-release.md:33-60`):

```sh
ART='antseal-x86_64-unknown-linux-gnu.tar.gz'   # the Linux archive's name as SHA256SUMS lists it
minisign -H -Vm "$ART" -P "$KEY"; echo "REAL_EXIT=$?"
```

*Expected:* exactly `Signature and comment signature verified`, then
`Trusted comment: antseal <TAG> <ART> commit:<COMMIT> <timestamp>`, then
`REAL_EXIT=0`. Copy both lines verbatim.
*STOP if* either line differs — the second line naming another version, file
or commit is a STOP even though the first line looks good.

6b — the only form a gate may use: exact equality on the trusted comment, never
an exit status alone (`D71-…:436-446`). The manifest's authenticated comment
supplies the one field you cannot know in advance, the timestamp; every
signature in a release carries the same one (`scripts/sign-release.sh:43-46`).

```sh
got="$(minisign -Q -H -Vm SHA256SUMS -P "$KEY")"; echo "REAL_EXIT=$?"; printf '%s\n' "$got"
prefix="antseal $TAG SHA256SUMS commit:$COMMIT "
case "$got" in "$prefix"*) TS="${got#"$prefix"}" ;; *) TS='' ;; esac
case "$TS" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) echo "TS=$TS" ;; *) echo MANIFEST-COMMENT-MISMATCH ;; esac
gate_check() { # $1 = the file to check, $2 = the artifact name its signature must carry
  got="$(minisign -Q -H -Vm "$1" -P "$KEY")"; rc=$?
  if [ "$rc" -eq 0 ] && [ "$got" = "antseal $TAG $2 commit:$COMMIT $TS" ]; then echo "MATCH $2"; else echo "NO-MATCH $2 rc=$rc got=[$got]"; fi
}
sed -E 's/^[0-9a-f]{64}[ ]{1,2}[*]?//' SHA256SUMS | while IFS= read -r name; do gate_check "$name" "$name"; done
sha256sum -c SHA256SUMS; echo "REAL_EXIT=$?"
```

*Expected:* `REAL_EXIT=0`; the manifest's comment; `TS=<RFC3339 UTC>`; one
`MATCH` per artifact and no `NO-MATCH`; every `sha256sum` line `OK`;
`REAL_EXIT=0`. Do both halves: a good manifest signature says nothing about an
archive nobody checked against it (`verifying-a-release.md:75-84`).
*STOP if* `MANIFEST-COMMENT-MISMATCH`, any `NO-MATCH`, any line not `OK`, or a
non-zero exit. Step 7 re-uses `gate_check` itself, so the check that is shown
able to fail is the check that was run.

**7. Prove the check can fail — on copies, never on what you will install.** A
check that has only ever seen a good artifact has not been shown able to fail;
D71 requires at least a flipped data byte, an edited trusted comment and a
replayed previous release (`D71-…:676-683`). The expected messages below were
measured when this document was written (2026-09-13, minisign 0.11, a throwaway
passphrase-wrapped key in a scratch directory, deleted afterwards — never a
project key).

```sh
rm -rf ~/gate/tamper && mkdir -p ~/gate/tamper/t1 ~/gate/tamper/t2 ~/gate/tamper/t3 ~/gate/tamper/t5
# T1 — one data byte flipped
cd ~/gate/tamper/t1 && cp ~/gate/release/"$ART" ~/gate/release/"$ART".minisig .
printf 'X' | dd of="$ART" bs=1 seek=100 conv=notrunc status=none
cmp -s "$ART" ~/gate/release/"$ART" && echo "PLANT DID NOT CHANGE THE FILE"
minisign -H -Vm "$ART" -P "$KEY"; echo "REAL_EXIT=$?"
gate_check "$ART" "$ART"
# T2 — trusted comment edited
cd ~/gate/tamper/t2 && cp ~/gate/release/"$ART" ~/gate/release/"$ART".minisig .
sed -i "s/^trusted comment: antseal $TAG /trusted comment: antseal ${TAG}-tampered /" "$ART".minisig
grep -c "^trusted comment: antseal ${TAG}-tampered " "$ART".minisig
minisign -H -Vm "$ART" -P "$KEY"; echo "REAL_EXIT=$?"
gate_check "$ART" "$ART"
# T3a (first release) — a genuine signature presented for another artifact
cd ~/gate/tamper/t3 && cp ~/gate/release/SHA256SUMS "$ART" && cp ~/gate/release/SHA256SUMS.minisig "$ART".minisig
minisign -H -Vm "$ART" -P "$KEY"; echo "REAL_EXIT=$?"
gate_check "$ART" "$ART"
# T3b (first release) — this release's genuine signatures, held to another release's expectation
( TAG="${TAG}-other"; cd ~/gate/release && sed -E 's/^[0-9a-f]{64}[ ]{1,2}[*]?//' SHA256SUMS | while IFS= read -r name; do gate_check "$name" "$name"; done )
# T4 — a key that is not antseal's (minisign's own published key, D71-…:252-257)
minisign -H -Vm ~/gate/release/"$ART" -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3; echo "REAL_EXIT=$?"
# T5 — the digest list catches a changed archive
cd ~/gate/tamper/t5 && cp ~/gate/release/SHA256SUMS ~/gate/release/"$ART" .
printf 'X' | dd of="$ART" bs=1 seek=100 conv=notrunc status=none
sha256sum -c --ignore-missing SHA256SUMS; echo "REAL_EXIT=$?"
```

*Expected:*

- **T1** — no `PLANT DID NOT CHANGE THE FILE` line; `Signature verification failed`;
  `REAL_EXIT=1`; `NO-MATCH <ART> rc=1 got=[]`.
- **T2** — `1`; `Comment signature verification failed`; `REAL_EXIT=1`;
  `NO-MATCH <ART> rc=1 got=[]`.
- **T3a** — `Signature and comment signature verified` with a trusted comment
  naming `SHA256SUMS`, and `REAL_EXIT=0`: minisign accepts a genuine signature
  presented in the wrong place. Then `NO-MATCH <ART> rc=0 got=[antseal <TAG> SHA256SUMS commit:<COMMIT> <TS>]`.
  **`rc=0` beside `NO-MATCH` is the observable that matters**: a check reading
  the exit status alone would have accepted, and `gate_check` refused.
- **T3b** — one `NO-MATCH <name> rc=0 got=[antseal <TAG> <name> …]` line per
  artifact and no `MATCH`: every signature is genuine, and the release is still
  refused because it is not the release expected. This is why the expected
  version and commit come from the packet and are never defaulted
  (`scripts/verify-release.sh:245-246`, `:374`).
- **T4** — `Signature key id in … is …` and
  `but the key id in the public key is E7620F1842B4E81F`; `REAL_EXIT=1`.
- **T5** — `<ART>: FAILED` and `WARNING: 1 computed checksum did NOT match`;
  `REAL_EXIT=1`.

**The replay arm D71 names, and the gap on a first release.** A previous
release presented with its own genuine signature is accepted by minisign; only
the trusted-comment equality refuses it (`D71-…:259-289`).

- **On the first release there is no previous release to replay**, so D71's
  third case cannot be run. T3a and T3b are the closest available arms —
  genuine signatures from this release, presented for the wrong artifact or
  against the wrong release's expectation, refused by the same function for the
  same reason a replay is. Record the replay arm as `n/a — first release`
  **and list it under deviations as a gap**, never as a pass.
- **From the second release on**, run the real arm as well. The previous
  release is published, so it is fetched from the documented channel without a
  credential. While this release is still a draft, `releases/latest` names the
  previous one. The archive name is assumed unchanged between releases; if
  the previous release's `SHA256SUMS` names it differently, use that name for
  both files and record the deviation:

  ```sh
  mkdir -p ~/gate/tamper/replay && cd ~/gate/tamper/replay
  curl -sS -o latest.json -w '%{http_code}\n' https://api.github.com/repos/aed900/antseal/releases/latest
  PREV="$(grep -oE '"tag_name": *"[^"]*"' latest.json | sed -E 's/.*"([^"]*)"$/\1/')"; echo "PREV=$PREV"
  for f in "$ART" "$ART.minisig"; do
    curl -fsSL --proto '=https' --proto-redir '=https' -O "https://github.com/aed900/antseal/releases/download/$PREV/$f" || echo "DOWNLOAD FAILED: $f"
  done
  minisign -H -Vm "$ART" -P "$KEY"; echo "REAL_EXIT=$?"
  gate_check "$ART" "$ART"
  ```

  *Expected:* `200`; `PREV=` a tag other than `$TAG`; no `DOWNLOAD FAILED`;
  `REAL_EXIT=0` and a trusted comment naming the previous version; then
  `NO-MATCH <ART> rc=0 got=[antseal <previous tag> …]`. `PREV` equal to `$TAG`
  means this release is already published — step 3's STOP, seen late.

*STOP if* any arm prints `MATCH`, any minisign command expected to fail exits
`0`, or an arm fails with a message other than the one above.

**8. Install the binary.**

```sh
mkdir -p ~/gate/unpack ~/bin && cd ~/gate/unpack
tar -tzf ~/gate/release/"$ART" | tee ~/gate/evidence/archive-listing.txt
grep -cE '^/|(^|/)\.\.(/|$)' ~/gate/evidence/archive-listing.txt
tar -xzf ~/gate/release/"$ART"
install -m 0755 "$(find . -type f -name antseal | head -1)" ~/bin/antseal
sha256sum ~/bin/antseal; ~/bin/antseal --version; echo "REAL_EXIT=$?"
```

*Expected:* a listing you record verbatim; `0` (no absolute or `..` entries);
`antseal <TAG without its leading v>` — the flag prints the binary name and
its crate version (`crates/antseal-cli/src/cli.rs:48-50`), and the release
version is what `--version` reports (`docs/user/versioning.md:28`);
`REAL_EXIT=0`. Compare the machine's glibc (step 1) with the floor the release
notes declare.
*STOP if* the entry check is not `0`, no `antseal` file is found, the version
differs, `--version` fails (a `GLIBC_… not found` loader error means the
machine is below the floor), or the notes declare a floor above the machine's
glibc.

**9. Stage the bundle.** Copy the packet's `.sealproof` into `~/gate/bundle/`.

```sh
cd ~/gate/bundle && ls -l && sha256sum -- *.sealproof
```

*Expected:* one file whose digest equals `$BUNDLE_SHA256`.
*STOP if* the digest differs, or there is more than one bundle.

**10. Verify with the CLI, offline, with the network provably off.** `verify`
opens no vault and never prompts (`crates/antseal-cli/src/commands.rs:922-925`);
without `--online` it collects no network inputs at all (`commands.rs:996-997`);
and because no vault is opened, the post-command anchor-upgrade pass returns
before doing anything (`commands.rs:973`;
`crates/antseal-cli/src/upgrade_hook.rs:323-327`). Detach the network adapter,
then:

```sh
ip -brief link
curl -sS --max-time 10 -o /dev/null https://antseal.org/ ; echo "CONTROL_EXIT=$?"
B="$(ls ~/gate/bundle/*.sealproof)"
~/bin/antseal verify "$B" > ~/gate/evidence/verify-offline.txt; echo "REAL_EXIT=$?"
head -1 ~/gate/evidence/verify-offline.txt
~/bin/antseal verify --json "$B" > ~/gate/evidence/verify-offline.json; echo "REAL_EXIT=$?"
grep -o '"network":"[a-z-]*"' ~/gate/evidence/verify-offline.json
grep -o '"work":{"work_id":"[0-9a-f]\{64\}"' ~/gate/evidence/verify-offline.json
grep -o '"app_version":"[^"]*"' ~/gate/evidence/verify-offline.json
grep -o '"verdict":{[^}]*}' ~/gate/evidence/verify-offline.json
```

*Expected:*

- `CONTROL_EXIT` **non-zero**. Zero means the network is still up.
- `REAL_EXIT=0` on both runs: no verdict rung holds
  (`crates/antseal-cli/src/verify_out.rs:150-165`).
- The first line is the headline, in the one template
  `existed no later than <unix seconds> (tsa, <source>)`
  (`crates/antseal-core/src/verify/wording.rs:165-170`; rendered first,
  `verify_out.rs:175-177`). **The kind inside the parentheses must be `tsa`** —
  the gate's "headline time from a TSA token". Offline, only `proven` and
  `valid-at-stamping-cert-since-expired` are headline-eligible
  (`crates/antseal-core/src/verify/aggregate.rs:48-57`), and an OTS anchor
  reaches `proven` only when confirmed online (`wording.rs:238-243`).
- `"network":"arbitrum-one"`: with no flag and no config file the effective
  network is the built-in default (`crates/antseal-cli/src/lib.rs:151-152`;
  `crates/antseal-cli/src/config.rs:273-278`, `:316`;
  `crates/antseal-net/src/network.rs:214-219`). Record it as the clean
  machine's reading of the released binary's default, which `Q34` also asks
  for.
- Exactly one `work_id`, equal to `$WORK_ID`. The verifier **recomputes** it
  from the manifest body and the comparison with a value obtained independently
  of the bundle is where the evidence is
  (`crates/antseal-core/src/verify/report.rs:231-241`).
- Exactly one `app_version` line, reading
  `"app_version":"antseal/<TAG without its leading v>"`. The CLI writes its own
  crate version into every seal it makes (`crates/antseal-cli/src/commands.rs:413`),
  so this shows the smoke seal was made with the candidate's binary, the
  release under test, and not a development build (D172 §2 R9). The field is
  the sealer's own text, checked against nothing
  (`crates/antseal-core/src/verify/report.rs:211-213`). It catches an honest
  seal made with the wrong build, not a sealer that lies.
- A `verdict` member with `"rung":null`, `"unanchored":false`,
  `"headline_eligible":` at least `1`, and `"exit_code":0`
  (`crates/antseal-core/src/verify/orchestration.rs:940-953`; its shape as
  committed, `crates/antseal-cli/tests/snapshots/json-envelopes.txt:46`).

*STOP if* `CONTROL_EXIT=0`, either `REAL_EXIT` is not `0`, the headline kind is
not `tsa`, the work id differs, the network is not `arbitrum-one`, or the
`app_version` output is not exactly the one line above. Do
**not** run `--live`. If it is run by mistake, record the command, its
`REAL_EXIT` and its whole output verbatim as a deviation. It is not evidence
about the bundle, and what it prints depends on the build:

- **A build with no storage backend compiled in** refuses before verifying
  anything: exit `23`, with a message saying this build has no storage backend
  compiled in (D170 §2 R4).
- **The `ant-backend` build** resolves `arbitrum-one`'s built-in bootstrap
  peers before verifying (D173 §2 R7), verifies the bundle offline, and only
  then tries the network — a contact with the public Autonomi network that
  this procedure's network policy never allows, and that reaches nothing at
  all while the adapter is detached. Whether any built-in peer answers is
  established by nothing in this repository (D173 §2 R16), so no outcome of
  a `--live` run here says anything about the network. With the adapter
  detached, expect this bundle's offline exit code, `0`, beside one of two
  live lines (the wording is
  `crates/antseal-core/tests/snapshots/verdict-wording.txt`'s): a
  `live check: inconclusive — …` line when the client connects and each fetch
  then fails on its own (D170 §2 R2, §2 R6), or a
  `live check: not performed — no connection to the Autonomi network was made, …`
  line when no connection is made at all, with a
  `` note: `verify --live` checked nothing — … `` line on stderr saying why
  (D199). It can take over
  a minute: the connection attempt alone may wait up to 60 seconds
  (`READ_ONLY_CONNECT_TIMEOUT`, `crates/antseal-cli/src/backend.rs`). The live
  check never sets the exit code. A live line saying anything other than
  those two is a finding to record, not a verdict. An exit `23` from this
  build means its async runtime could not start, and its message says so.

**11. Verify with the CLI `--online`.** Re-attach the network adapter.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://antseal.org/
~/bin/antseal verify --online "$B" > ~/gate/evidence/verify-online.txt; echo "REAL_EXIT=$?"
```

What `--online` contacts, and nothing else: for each **upgraded** OTS anchor's
block height, two Bitcoin esplora endpoints, `https://blockstream.info/api` and
`https://mempool.space/api` (`crates/antseal-anchor/src/esplora.rs:85-86`); and
only if the bundle carries a receipt, the Arbitrum One pair
`https://arb1.arbitrum.io/rpc` and `https://arbitrum.drpc.org`
(`crates/antseal-anchor/src/arbitrum/endpoints.rs:22-23`, `:48-54`). The plan
is derived from the bundle alone (`crates/antseal-core/src/verify/plan.rs:132-147`)
and the pairs are the pinned defaults unless a config file overrides them,
which this machine does not have (`crates/antseal-cli/src/verify_host.rs:328-364`).
No Autonomi, no TSA, no OTS calendar and no credential is involved. A bundle
whose OTS anchors are all still pending and which carries no receipt makes
zero requests.

*Expected:* `200`, then `REAL_EXIT=0`. The offline block is followed by the
online advisory lines (`verify_out.rs:209-213`). An unreachable or disagreeing
endpoint cannot change the exit code (`verify_out.rs:34-40`); record it.
*STOP if* any anchor is reported refuted, or the exit code is `41` or `42`.

**12. Open the hosted page and establish its provenance.** **Today: this
would STOP** — see "Why it cannot run today".

In the browser, type `https://antseal.org/` exactly — apex, `https`, trailing
slash, the one canonical URL (`crates/antseal-cli/src/brand.rs:55`). Do not
follow a link or a search result. The address bar must show exactly that URL
with no certificate warning; record the certificate's issuer and expiry from
the page-information dialog. (Measured 2026-09-13: the plain-HTTP form of the
address answers `301` to the canonical URL, and there is no `www` host — it has
no address record.) Then fetch the same bytes in the terminal:

```sh
cd ~/gate/evidence
curl -fsS -H 'Accept-Encoding: identity' -D page.headers -o page.html https://antseal.org/
grep -iE '^(HTTP|content-type|content-length|last-modified|etag|cache-control)' page.headers
sha256sum page.html
grep -o 'id="page-build">[^<]*<code>[0-9a-f]\{64\}</code>' page.html
sed -n 's/.*const ANTSEAL_MODULE_B64 = "\([A-Za-z0-9+/=]*\)";.*/\1/p' page.html | base64 -d | sha256sum
awk '$2=="index.html"{print $1}' ~/gate/release/verifier-web-SHA256SUMS   # use the page manifest's name in this release
sha256sum ~/gate/release/antseal_wasm_bg.wasm                            # likewise the module's
sed -n '/<!-- BEGIN minisign-public-key/,/<!-- END minisign-public-key/p' page.html | grep -cE '(^|[^A-Za-z0-9+/])RW[A-Za-z0-9+/]{54}([^A-Za-z0-9+/]|$)'
sed -n '/<!-- BEGIN minisign-public-key/,/<!-- END minisign-public-key/p' page.html | grep -oE 'RW[A-Za-z0-9+/]{54}' | head -1
```

*Expected — every one an equality you record:*

- **The page carries the module it names.** The footer reads
  `module build <64 hex>` (`verifier-web/index.template.html:150`) and that
  digest equals the SHA-256 of the module decoded out of the page. The footer
  digest is the module's, not the page's — a file cannot contain its own hash
  (`index.template.html:140-149`).
- **You fetched the page the release describes.** `sha256sum page.html` equals
  the `index.html` line of the release's page manifest, which step 6 covered.
  Only the signed release copy is authoritative; a sums file served by the
  page's host carries no authority (`docs/decisions/D63-footer-build-hash-and-artifact-set.md:543-548`).
- **The module is the released one.** The footer digest equals
  `sha256sum antseal_wasm_bg.wasm`.
- **The page was built from the release's commit.** The browser footer's build
  line reads `antseal-core <version> · formats <list> · source <40 hex>`
  (`index.template.html:825-827`); the `source` value equals `$COMMIT`. This
  line is filled in by the page's script, so `page.html` shows it empty — read
  it in the browser (`tasks/R.md`, `### R26 —` Notes).
- **The footer publishes the same key.** The bounded count is `1` and the key
  equals `$KEY` (`index.template.html:151-178`; all four key locations change
  in one act, `maintainer-key-procedure.md:212-213`). Read the key only between
  the markers: the page's embedded module is one long run of the same alphabet
  — measured 2026-09-13, an unbounded key-shaped pattern matches **136** times
  in the live page.

*STOP if* any equality fails. One exception: the host caches for 600 s
(`cache-control: max-age=600`), so a page-digest mismatch within ten minutes of
a redeploy is inconclusive — wait ten minutes and re-fetch once; a second
mismatch is a STOP. **Today** the footer label is `page build`, the module is
stamped with a commit that cannot be fetched, no release manifest exists to
compare against, and the page carries no key markers, so this step fails on
four counts.

**13. Verify on the hosted page, offline.** With the page loaded, detach the
network adapter and re-run step 10's `curl` control (*expected* non-zero).
Drop the bundle onto the page, or pick it with the file chooser.

*Expected:* no "This bundle was refused." heading (`index.template.html:298-307`);
the page's headline line is **identical, character for character**, to the
CLI's first line from step 10 — both are the same rendered headline from the
same verification library (`index.template.html:263-268`;
`crates/antseal-core/src/verify/orchestration.rs:570-583`); the anchor list shows
the same slots and states as the CLI's; `bundle format version 1`
(`index.template.html:289`). The footer's advice line reads
`for high-stakes verification, run antseal verify and compare verdicts`
(`index.template.html:139`) — steps 10 and 13 are that comparison. The page
verifies with no network access: it is one file, fetches nothing to load
(`D129-…:10-12`), and fetches nothing until "confirm online" is pressed
(`index.template.html:862-866`). Take screenshots of the full result and the
footer.
*STOP if* the bundle is refused, the headline differs from the CLI's, or
verification does not complete while offline.

*Optional:* re-attach the network and press "confirm online". Record the
overlay; it is advisory and not a gate condition.

**14. Verdict.** The run passes only if every step 1–13 met its expected
observable, every tamper arm was rejected with its own message, and the
recordings are filed. Stop the `script` session (`exit`) and the screen
recording, fill in the template's verdict, and sign it with the date and your
role.

**15. Dispose of the machine.** Destroy the VM — or, if a snapshot was taken
before step 1 (the template records its name), revert to that snapshot. It now
holds antseal and a bundle, so as it stands it is never a clean machine again.
If the channel witness is to run on this VM, revert it — never merely delete
files from it — and keep the reverted VM, with no credential ever added, until
the witness has run (D172 §2 R6).

## Reading a red

`verify`'s exit codes (`crates/antseal-cli/src/error.rs:420-476`): `0` clean;
`2` usage; `4` the bundle file could not be read; `17` malformed config (a clean
machine has none); `23` network failure (only from `--live`, which this
procedure does not run — a build with no storage backend compiled in refuses
`--live` with it before verifying, D170 §2 R4, and the `ant-backend` build
exits with the offline verdict's code whatever the network does, D170 §2 R2
and §2 R6, returning `23` only if its async runtime cannot start, as its
message then says); `40` bundle rejected; `41` an anchor refuted; `42` headline
anchors disagree by more than 48 h; `43` unanchored. The `--json` document's
`verdict.exit_code` equals the process's exit code by construction
(`verify_out.rs:277-284`).

minisign exits `0` on success, `1` on a failed check and `2` on malformed
input (`scripts/verify-release.sh:86-88`) — never write a check that expects
exactly `1` for every failure.

## Recording the walkthrough

- Accept row 3's "walkthrough recorded" means the recordings **and** the filled
  evidence file. A filled template alone does not discharge it, and neither
  does a recording without the template.
- The terminal record is `~/gate/evidence/session.log` with its timing file;
  the browser half is the screen recording plus step 13's screenshots. Name
  where each is filed in the evidence file.
- Copy `~/gate/evidence/` off the machine **before** step 15.
- Nothing personal in any of it: the account is `user`, the host name is
  generic, the browser profile is fresh, and nobody signs in to anything. The
  public key, digests, versions and commits are not secrets and are recorded in
  full. No passphrase is used anywhere in this procedure; if one is ever asked
  for, that is a finding.

## Evidence

The completed evidence file is this procedure's product. File it with the
`Q34` gate evidence (`tasks/Q.md`, `### Q34 —` Accept row 1). A verification
whose values live only in a terminal scrollback did not happen. The channel
witness below fills its own block of the same template, after publication; its
result never changes this run's verdict.

## After publication: the channel witness (D172 §2 R6)

**A witness, not a gate.** Run this only after two things have happened, in
this order: the gate evidence was committed, and then the maintainer published
the release with express consent given at that moment. The witness checks that
the release served through the documented channel is byte for byte the set this
procedure gated. **It cannot undo anything.** A red here is detection, not
rollback: the release is already public, and the remedy is a new version, never
replacing a published file. Replacing a published asset's bytes in place is
forbidden, because it would void this witness's own premise (D172 §2 R6,
§2 R7). The success metric's `release_date`, and any sentence in the release
notes saying the gate passed, are written only after this witness passes.

**The machine.** A machine with no credential: the gate VM reverted to its
pre-step-1 snapshot (step 15) and never given a credential since, or a fresh
VM built as in "The clean machine" above, with the reason for not using the
gate VM recorded. It needs no antseal, and it installs none. Network:
`api.github.com`, `github.com`, `release-assets.githubusercontent.com`.

**Inputs.** `TAG` and `COMMIT`, exactly as in gate packet Part A (the
committed evidence file's Part A table); and
`courier.sha256` from the **committed** gate evidence, by any file transfer —
never regenerated, and never taken from the release.

**W0. Record, and confirm no credential.** In the terminal:
`mkdir -p ~/witness && script -q -T ~/witness/timing.log ~/witness/session.log`,
start a screen recording, and note the UTC time (`date -u`). Inside the
recorded shell, run step 1's commands.
*Expected:* step 1's credential lines: `No such file or directory` for every
credential path, and `0` token variables.
*STOP if* any credential path exists or a token variable is set.

**W1. The published release, read anonymously.** Put `courier.sha256` in
`~/witness/`, then:

```sh
cd ~/witness
TAG='<release tag, as in gate packet Part A>'
COMMIT='<the 40-hex commit, as in gate packet Part A>'
sha256sum courier.sha256
curl -sS -o release.json -w '%{http_code}\n' "https://api.github.com/repos/aed900/antseal/releases/tags/$TAG"
grep -oE '"(tag_name|draft|prerelease|published_at)": *("[^"]*"|true|false|null)' release.json
curl -sS -o tag-commit.json -w '%{http_code}\n' "https://api.github.com/repos/aed900/antseal/commits/$TAG"
grep -m1 -oE '"sha": *"[0-9a-f]{40}"' tag-commit.json
```

*Expected:* the `courier.sha256` digest, recorded, so a reviewer can compare it
with the committed file; `200`; `"tag_name": "<your TAG>"`; `"draft": false`;
`"prerelease": false`; a `published_at` you record; `200`; `"sha": "<your
COMMIT>"` — the published tag resolves to the gated commit (D172 §2 R2).
*STOP if* either status is not `200`, `draft` or `prerelease` is anything but
`false`, the `tag_name` is not the packet's, or the tag's commit is not
`$COMMIT`.

**W2. Every asset, from the documented channel, equal to what was gated.**

```sh
mkdir -p ~/witness/published && cd ~/witness/published
grep -oE '"browser_download_url": *"[^"]*"' ../release.json | sed -E 's/.*"(https:[^"]*)"$/\1/' > ../asset-urls.txt
while IFS= read -r url; do
  case "$url" in
    "https://github.com/aed900/antseal/releases/download/$TAG/"*)
      curl -fsSL --proto '=https' --proto-redir '=https' -O "$url" || echo "DOWNLOAD FAILED: $url" ;;
    *) echo "REFUSED: $url" ;;
  esac
done < ../asset-urls.txt
sha256sum -- * > ../published.sha256
cd ~/witness
LC_ALL=C sort -k2 courier.sha256 > courier.sorted
LC_ALL=C sort -k2 published.sha256 > published.sorted
diff courier.sorted published.sorted; echo "REAL_EXIT=$?"
awk '{print $1}' courier.sha256 | LC_ALL=C sort > courier-digests.sorted
grep -oE '"digest": *"sha256:[0-9a-f]{64}"' release.json | sed -E 's/.*sha256:([0-9a-f]{64})"$/\1/' | LC_ALL=C sort > api-digests.sorted
diff courier-digests.sorted api-digests.sorted; echo "REAL_EXIT=$?"
```

*Expected:* no `DOWNLOAD FAILED` and no `REFUSED` lines; the first `diff`
prints nothing and `REAL_EXIT=0` — the same names, the same count and the same
SHA-256 for every asset; the second `diff` prints nothing and `REAL_EXIT=0` —
GitHub's own per-asset `digest`, served anonymously, agrees with every one.
*STOP if* either `diff` prints anything or exits non-zero. A missing or extra
asset, a changed byte and an absent `digest` all land here. Record the `diff`
output verbatim; it names the asset.

**W3. The channel names this release as the latest.**

```sh
curl -sS -o latest.json -w '%{http_code}\n' https://api.github.com/repos/aed900/antseal/releases/latest
grep -oE '"tag_name": *"[^"]*"' latest.json
```

*Expected:* `200`; `"tag_name": "<your TAG>"`.
*STOP if* either differs.

**W4. Verdict and filing.** Stop the recordings, fill the template's witness
block, and file it with the gate evidence. A STOP at any W step is a **red
witness**: record it, publish nothing further under this version, and take the
remedy D172 §2 R6 names — a new version — never an in-place replacement.
