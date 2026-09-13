# Clean-machine verification (Q32 Do (b))

**Status: WRITTEN, NEVER EXECUTED — and it CANNOT be executed today.** This
procedure has not been run by anyone. Writing it is the closed half of Q32
Do (b); *executing* it and *recording the walkthrough* is the open half of
Q32 Accept rows 2 and 3, and it belongs to the Q34 gate run. Four of its
preconditions are false as of 2026-09-13 (see "Why it cannot run today"), so
the first honest outcome of following it today is a STOP at step 3. Nothing
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

1. fetch the released binary from the documented channel, GitHub Releases
   (`docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md:506-512`);
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
- anything about persistence on Autonomi, or restore. **`verify --live` and
  `restore` refuse in every build, including the released `ant-backend`
  build**: `restore` returns the backend refusal unconditionally
  (`crates/antseal-cli/src/commands.rs:590-600`) and `verify --live` returns it
  before any verification (`commands.rs:728-733`); in a build with the backend
  compiled in, the message says the command "does not construct one yet"
  (`crates/antseal-cli/src/backend.rs:208-213`), class `network-failure`,
  exit 23 (`crates/antseal-cli/src/error.rs:410`). This procedure never runs
  either. Restore is the disk-loss drill's subject
  ([`vault-restore-drill.md`](vault-restore-drill.md)), once `restore` is wired;
- who wrote the sealed work, or that nobody else held it. A seal proves the
  holder of the sealing key possessed the content by the proven time — not
  authorship, and not exclusive possession
  (`crates/antseal-core/src/verify/wording.rs:181-183`). Nor does it carry any
  legal effect: it is evidence of existence and integrity by a proven time,
  not a notarial act.

## Why it cannot run today (measured 2026-09-13)

| Step | Blocker | Measurement | Owner |
| --- | --- | --- | --- |
| 3–8 | **No release exists.** | `GET repos/aed900/antseal/releases` returned an empty list; the remote's only tag is `format-v1-freeze` (no `v*` tag). The release workflow is `Q31`'s and has not landed. | `Q31`, then `Q34` |
| 5 | **The key's independent pin does not exist.** | `dig +short TXT antseal.org` returned nothing, while the same query for `github.com` returned records (the resolver answers TXT). `dig +short DS antseal.org` returned nothing (not DNSSEC-signed). | maintainer, `docs/signing/maintainer-key-procedure.md` §2 (`Q30`) — an external act at the registrar |
| 12 | **The live page is stale and its stated commit cannot be fetched.** | `https://antseal.org/` serves 2 516 397 B, SHA-256 `ea7e9447584be131443a6948c70ea2f5a624882d6ea7d1f953e6c08d04f43951`, `last-modified: Sat, 15 Aug 2026 08:02:40 GMT`. Its footer reads `page build` with digest `70235b8b6192b983b1d1eb3b926e5e5925257cd806b6763eeb2aff76539403c0`, which does equal the SHA-256 of the module embedded in the page (1 853 031 B). The module carries the source stamp `9317a35b3adaef56b03eaa22a80a2b76e232a7d9`, which `GET repos/aed900/antseal/commits/<that id>` answers with HTTP 422 "No commit found" (the current `main` head resolves). The page carries no `minisign-public-key` marker at all, and its footer label predates the `module build` label the template now has (`verifier-web/index.template.html:150`). The last deploy was run `31873422229` on 2026-08-15 (`tasks/R.md`, `### R26 —` Notes). | a redeploy from the release commit, owed before the gate |
| 9–13 | **No gate bundle exists.** | The mainnet smoke seal has not been performed; it needs a funded wallet (`Q33`) and an `ant-backend` build. | `Q34` |

What that means for a digest comparison **today**: the footer digest is
internally consistent (the page carries the module it names), but the
documented reproduction — build at the deployed commit and compare
(`docs/user/release-checklist.md:106-124`) — cannot be performed as written,
because the deployed commit cannot be fetched. A stamp is supplied rather than
discovered (`crates/antseal-wasm/build.rs:8-14`), so the digest reproduces only
at the commit it was built from and at no other
(`docs/user/versioning.md:145-159`). Treat the live digest as unreproducible
until a redeploy publishes a digest labelled with a commit that exists.

## An ordering this document cannot resolve

The release checklist gates publication on this procedure's evidence
(`docs/user/release-checklist.md:72-75`), and `Q34`'s `Do` runs the
clean-machine verification before "publish the release" (`tasks/Q.md`,
`### Q34 —` Do). But `Q31`'s pipeline publishes a **draft** release
(`tasks/Q.md`, `### Q31 —` Do), and GitHub serves draft releases only to
accounts with push access ("Only users with push access will receive listings
for draft releases" — GitHub REST API documentation, *List releases*, read
2026-09-13). A machine that holds no credential — the property this procedure
exists to test (`tasks/Q.md`, `### Q34 —` Deps) — cannot see a draft. So the
release, or a public pre-release, must be published **before** step 3 can pass,
and publication has no rollback (`docs/user/release-checklist.md:375-377`).

This document does not choose between publishing a GitHub pre-release first,
reordering `Q34`, or another route. It requires only what step 3 checks: a
published, non-draft release reachable without credentials.

## Zero repository resources, concretely

`Q32` Accept row 2: *"Clean-machine procedure uses zero repo-checkout resources
(released artifacts + hosted page only)"*.

**Permitted inputs, and nothing else:**

- the release's assets, downloaded from `https://github.com/aed900/antseal/releases`;
- the release's metadata from GitHub's unauthenticated API;
- the hosted page at `https://antseal.org/`;
- the `TXT` record on `antseal.org`;
- packages from the Debian archive;
- the gate packet below: which release to expect, and the bundle.

**Forbidden, each a STOP:** cloning or fetching the repository; the release
page's auto-generated "Source code" archives (`tarball_url`/`zipball_url` —
they are the repository); any file from the repository, including
`scripts/verify-release.sh` (it needs the antseal source,
`docs/signing/verifying-a-release.md:86-93`) and this document itself; any key,
digest, version, commit or URL taken from the repository rather than from the
release, DNS or the page; the `gh` tool; any GitHub login, token, SSH key or
`.netrc` on the machine or in its browser.

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
  (`v<major>.<minor>.<patch>`, `docs/user/versioning.md:102-118`); the 40-hex
  commit that release names; the bundle's SHA-256; the bundle's work id (64 hex);
  the network it was sealed on (`arbitrum-one` for the smoke seal); whether
  the bundle includes the Arbitrum receipt.
- **Part B — the file**: the `.sealproof` bundle, by any file transfer.

The packet deliberately does **not** contain the public key, a binary, a
script, or any repository file. The key must be obtained through the
documented route (step 5) — that route is under test.

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
| `minisign`, `curl`, `ca-certificates`, `bind9-dnsutils`, `firefox-esr`, plus whatever desktop the operator needs to run the browser | `antseal` (until step 8), `git`, `cargo`, `rustc`, `rustup`, `gh`, any antseal state directory (`$ANTSEAL_DIR`, else `~/.antseal` — `crates/antseal-cli/src/vault/layout.rs:10,16,81-111`), any SSH key, `.netrc` or GitHub credential, any browser profile that has ever signed in to anything |

Everything else the procedure uses — `sha256sum`, `base64`, `dd`, `install`,
`grep`, `sed`, `awk`, `find`, `cmp`, `tar`, `ldd`, `script` — ships in Debian's
essential or required packages, and `ip` in `iproute2`, which every standard
installation carries.

### Network policy

| Phase | Steps | Network | Allowed destinations |
| --- | --- | --- | --- |
| setup | 0–9 | on | `deb.debian.org`; `api.github.com`; `github.com` and `release-assets.githubusercontent.com` (where release downloads redirect — measured 2026-09-13 on a third-party public release); `antseal.org`; DNS |
| offline verify | 10, 13 | **off** — detach the VM's virtual network adapter | none; proven by a control that must fail |
| online | 11 (and 13's optional online check) | on | `blockstream.info`, `mempool.space`, `arb1.arbitrum.io`, `arbitrum.drpc.org` (below) |

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
find / "$HOME" -xdev \( -name MVP-SPEC.md -o -name verify-release.sh -o -name '*.sealproof' \) 2>/dev/null | sort -u | wc -l
```

*Expected:* a Debian release, `x86_64`, a glibc version line; all seven tools
`absent`; `No such file or directory` for every listed path;
`ANTSEAL_DIR=unset`; `0`.
*STOP if* anything else — this machine is not clean.

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

**3. Confirm the release is published and reachable without credentials.**
**Today: STOP here** — no release exists.

```sh
mkdir -p ~/gate/release && cd ~/gate/release
curl -sS -o release.json -w '%{http_code}\n' "https://api.github.com/repos/aed900/antseal/releases/tags/$TAG"
grep -oE '"(tag_name|draft|prerelease|published_at)": *("[^"]*"|true|false|null)' release.json
```

*Expected:* `200`; `"tag_name": "<your TAG>"`; `"draft": false`. Record
`prerelease` and `published_at`.
*STOP if* `404` (no such published release — this endpoint is documented as
"Get a published release with the specified tag", so a draft answers 404 too),
any `draft` other than `false`, or a `tag_name` that is not the packet's.

**4. Download the release assets.** Only the assets listed in the release —
never `tarball_url` or `zipball_url`.

```sh
grep -oE '"browser_download_url": *"[^"]*"' release.json | sed -E 's/.*"(https:[^"]*)"$/\1/' > asset-urls.txt
while IFS= read -r url; do
  case "$url" in
    "https://github.com/aed900/antseal/releases/download/$TAG/"*)
      curl -fsSL --proto '=https' --proto-redir '=https' -O "$url" || echo "DOWNLOAD FAILED: $url" ;;
    *) echo "REFUSED: $url" ;;
  esac
done < asset-urls.txt
ls -l; sha256sum -- * > ~/gate/evidence/downloaded.sha256
```

*Expected:* no `DOWNLOAD FAILED` and no `REFUSED` lines. The set a release
carries: `SHA256SUMS` and `SHA256SUMS.minisig`; every artifact with its own
`.minisig` (`D71-…:380-396`); `minisign.pub` and `minisign.pub.ots`
(`D71-…:480-485`, `:518-523`); the page's manifest, renamed
`verifier-web-SHA256SUMS` in the D71 proposal (`D71-…:398-405`); and the
pre-packaging module `antseal_wasm_bg.wasm` (`docs/decisions/D129-verifier-page-file-shape-and-the-in-artifact-csp.md:12-14`).
`Q31` fixes the real names, so record what is actually there. This document
writes the Linux archive as `antseal-x86_64-unknown-linux-gnu.tar.gz`, the
example name in `D71-…:412-415`.
*STOP if* `SHA256SUMS`, `SHA256SUMS.minisig`, `minisign.pub`, the Linux
archive or the archive's `.minisig` is missing.

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
alone**: it is served by the same account as the binary, so a substituted key
and a substituted binary verify against each other (`D71-…:480-485`). The page
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
- **From the second release on**, run the real arm as well: in
  `~/gate/tamper/replay/`, download the **previous** release's archive and its
  `.minisig` with step 4's `curl` form, run step 6a's command on them
  (*expected* `REAL_EXIT=0` and a trusted comment naming the previous version),
  then `gate_check "$ART" "$ART"` (*expected* `NO-MATCH <ART> rc=0 got=[antseal <previous tag> …]`).

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
its crate version (`crates/antseal-cli/src/cli.rs:44-46`), and the release
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
opens no vault and never prompts (`crates/antseal-cli/src/commands.rs:689-692`);
without `--online` it collects no network inputs at all (`commands.rs:735-736`);
and because no vault is opened, the post-command anchor-upgrade pass returns
before doing anything (`commands.rs:713`;
`crates/antseal-cli/src/upgrade_hook.rs:305-309`). Detach the network adapter,
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
grep -o '"verdict":{[^}]*}' ~/gate/evidence/verify-offline.json
```

*Expected:*

- `CONTROL_EXIT` **non-zero**. Zero means the network is still up.
- `REAL_EXIT=0` on both runs: no verdict rung holds
  (`crates/antseal-cli/src/verify_out.rs:120-135`).
- The first line is the headline, in the one template
  `existed no later than <unix seconds> (tsa, <source>)`
  (`crates/antseal-core/src/verify/wording.rs:165-170`; rendered first,
  `verify_out.rs:145-147`). **The kind inside the parentheses must be `tsa`** —
  the gate's "headline time from a TSA token". Offline, only `proven` and
  `valid-at-stamping-cert-since-expired` are headline-eligible
  (`crates/antseal-core/src/verify/aggregate.rs:48-57`), and an OTS anchor
  reaches `proven` only when confirmed online (`wording.rs:238-243`).
- `"network":"arbitrum-one"`: with no flag and no config file the effective
  network is the built-in default (`crates/antseal-cli/src/lib.rs:151-152`;
  `crates/antseal-cli/src/config.rs:138-143`, `:181`;
  `crates/antseal-net/src/network.rs:214-219`). Record it as the clean
  machine's reading of the released binary's default, which `Q34` also asks
  for.
- Exactly one `work_id`, equal to `$WORK_ID`. The verifier **recomputes** it
  from the manifest body and the comparison with a value obtained independently
  of the bundle is where the evidence is
  (`crates/antseal-core/src/verify/report.rs:231-241`).
- A `verdict` member with `"rung":null`, `"unanchored":false`,
  `"headline_eligible":` at least `1`, and `"exit_code":0`
  (`crates/antseal-core/src/verify/orchestration.rs:902-915`; its shape as
  committed, `crates/antseal-cli/tests/snapshots/json-envelopes.txt:46`).

*STOP if* `CONTROL_EXIT=0`, either `REAL_EXIT` is not `0`, the headline kind is
not `tsa`, the work id differs, or the network is not `arbitrum-one`. Do
**not** run `--live`. If it is run by mistake, record its exit 23 and message
as a deviation; it is not evidence about the bundle.

**11. Verify with the CLI `--online`.** Re-attach the network adapter.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://antseal.org/
~/bin/antseal verify --online "$B" > ~/gate/evidence/verify-online.txt; echo "REAL_EXIT=$?"
```

What `--online` contacts, and nothing else: for each **upgraded** OTS anchor's
block height, two Bitcoin esplora endpoints, `https://blockstream.info/api` and
`https://mempool.space/api` (`crates/antseal-anchor/src/esplora.rs:83-84`); and
only if the bundle carries a receipt, the Arbitrum One pair
`https://arb1.arbitrum.io/rpc` and `https://arbitrum.drpc.org`
(`crates/antseal-anchor/src/arbitrum/endpoints.rs:22-23`, `:48-54`). The plan
is derived from the bundle alone (`crates/antseal-core/src/verify/plan.rs:132-147`)
and the pairs are the pinned defaults unless a config file overrides them,
which this machine does not have (`crates/antseal-cli/src/verify_host.rs:277-305`).
No Autonomi, no TSA, no OTS calendar and no credential is involved. A bundle
whose OTS anchors are all still pending and which carries no receipt makes
zero requests.

*Expected:* `200`, then `REAL_EXIT=0`. The offline block is followed by the
online advisory lines (`verify_out.rs:179-183`). An unreachable or disagreeing
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
`crates/antseal-core/src/verify/orchestration.rs:552-565`); the anchor list shows
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

## Reading a red

`verify`'s exit codes (`crates/antseal-cli/src/error.rs:391-442`): `0` clean;
`2` usage; `4` the bundle file could not be read; `17` malformed config (a clean
machine has none); `23` network failure (only `--live`, which this procedure
does not run); `40` bundle rejected; `41` an anchor refuted; `42` headline
anchors disagree by more than 48 h; `43` unanchored. The `--json` document's
`verdict.exit_code` equals the process's exit code by construction
(`verify_out.rs:247-254`).

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
whose values live only in a terminal scrollback did not happen.
