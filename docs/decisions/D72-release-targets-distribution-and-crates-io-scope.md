# D72 — The release target set, the distribution channel, and what a crates.io publish would oblige

- **Status: RESOLVED. The maintainer's DIRECTION is confirmed on both halves —
  Linux-only binaries, GitHub Releases as the channel — but three of the brief's
  premises are overturned on measurements taken today, and one whole question the
  brief never asked is ruled because another record assigned it here.**
  1. **"crates.io names stay reserved but unpublished" is FACTUALLY WRONG.** All
     five names were **really published on 2026-08-11 by `aed900`** —
     `antseal`, `antseal-core`, `antseal-anchor`, `antseal-net`, `antseal-cli`,
     each at `0.0.0`, each `MIT OR Apache-2.0`, none yanked. `scripts/reserve-crates.sh`
     was run with `--execute`. There is no "reserved but unpublished" state on
     crates.io to choose: **reservation IS publication**, and it already happened.
     The choice left is not *whether to publish* but *what to do about five live
     placeholder crates*.
  2. **"macOS/Windows stay CI-verified build-from-source" overstates the CI by a
     wide margin.** `cross-os-extended.yml`'s two arms run
     `scripts/ci-lanes.sh cross-os`, whose entire body is
     `cargo test -p antseal-core --locked -- corpus_ vector_`. **`-p antseal-core`.**
     No lane in this repository has *ever* compiled `antseal-cli`, `antseal-net`
     or `antseal-anchor` on macOS or Windows. Linux-only is therefore **not** a
     narrowing of code proven portable; the shippable binary's portability to
     those platforms is **unmeasured**, and this record forbids the release notes
     from implying otherwise.
  3. **The libc question does not have the escape hatch the brief assumes.**
     `x86_64-unknown-linux-musl` is **not buildable on this host**: the default
     graph dies at `ring v0.17.14` and the `ant-backend` graph at
     `aws-lc-sys v0.43.0`, both `exit status 1`, both for a missing
     `x86_64-linux-musl-gcc`. Meanwhile the gnu binary that *does* build requires
     **`GLIBC_2.34`** — a floor set by the build host, not by our code, and
     today set implicitly by an unpinned `runs-on: ubuntu-latest`.
  4. **A hard ordering blocker the brief does not mention, and neither does any
     row: the repository is PRIVATE** (`isPrivate: true`, measured today). A
     GitHub Release on a private repository is not publicly downloadable, and
     **M4's gate requires a clean machine to install the released binary from the
     documented channel**. "GitHub Releases only" is therefore inoperative until
     **Q65** resolves. Q65 is promoted from *"M4, alongside Q22/Q28"* to **a
     precondition of Q31 and Q34** (§2 R6).
  5. **D89 §Consequences 6 assigned the release build's FEATURE SET to this
     record** and the brief omitted it. It is ruled at §2 R4: the released
     binary is built `--features ant-backend`, and that is what makes
     `self_encryption` GPL-3.0 a distribution fact rather than a hypothetical.
- **Date: 2026-08-16**
- **Owning task: Q31/Q22.**
- Related: D6 (per-crate licensing and the GPL-3.0 distribution reality — its
  conclusion is confirmed here at the *dependency-graph* level rather than from
  crates.io metadata), D50 (OS-keystore scope; its follow-up is unblocked by this
  record and answered *no* at §3), D35/P15 (the `self_encryption` prohibition,
  which this record shows applies to *declaration*, not to the shipped graph),
  D89 (wallet primitives below the gate; §Consequences 6 hands the feature-set
  question here), D138/Q239 (the cross-OS cadence — this record reads the same
  two arms and finds their *content* much narrower than that record needed to
  care about), Q65 (publish scope + the pre-public scrub — promoted to a
  precondition here), Q30/D71 (signing mechanism, still open), U33 (closed at
  §3), Q34 (the M4 gate whose clean-machine clause forces §2 R2 and §2 R6).

---

## 1. The measurement

Every figure below was produced on this host on **2026-08-16**. Host:
Debian GNU/Linux 12 (bookworm), kernel 6.1.0-51-amd64, `rustc 1.92.0
(ded5c06cf 2025-12-08)` from `rust-toolchain.toml`.

### 1.1 The glibc floor is real, and it is 2.34

```
$ ldd --version
ldd (Debian GLIBC 2.36-9+deb12u14) 2.36
```

A release build of the CLI, in a scratch `CARGO_TARGET_DIR` so no other lane's
`target/` lock was taken:

```
$ CARGO_TARGET_DIR=<scratch>/t-gnu cargo build --release -p antseal-cli --locked
   … 120 crates …
GNU_EXIT=0
$ file <scratch>/t-gnu/release/antseal
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
$ ldd <scratch>/t-gnu/release/antseal
	linux-vdso.so.1
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
	/lib64/ld-linux-x86-64.so.2
$ objdump -T <scratch>/t-gnu/release/antseal | grep -o 'GLIBC_[0-9.]*' | sort | uniq -c
     74 GLIBC_2.2.5      1 GLIBC_2.18       1 GLIBC_2.30
      2 GLIBC_2.3        1 GLIBC_2.25       1 GLIBC_2.32
      1 GLIBC_2.3.4      1 GLIBC_2.28       4 GLIBC_2.33
      3 GLIBC_2.4        1 GLIBC_2.16      12 GLIBC_2.34
      1 GLIBC_2.14       1 GLIBC_2.17
```

**Highest required symbol version: `GLIBC_2.34`, twelve symbols.** The
`for GNU/Linux 3.2.0` string in `file` output is the ELF ABI note and is **not**
the floor — reading it as one is the trap this paragraph exists to close. The
floor is the `objdump -T` maximum.

glibc 2.34 (2021-08) is the release that merged `libpthread`/`libdl` into
`libc`, which is why twelve symbols land exactly there: they are the
unversioned-to-2.34 `pthread_*` re-exports that Rust's `std` picks up **from
whatever glibc the build host has**. Consequences, stated as a property rather
than a distro list to be argued with: **a binary built on host glibc *N* will
generally not run on a target with glibc < *N*, and nothing about our source
code changes that.** Debian 11 (2.31), Ubuntu 20.04 (2.31) and RHEL/CentOS 8
(2.28) are below 2.34 and would refuse this artifact at `execve`.

**The important half of this measurement is not the number — it is that the
number is a property of the BUILD ENVIRONMENT, and the build environment is
currently an unpinned label.** Every job in `ci.yml` and `cross-os-extended.yml`
that could produce an artifact says `runs-on: ubuntu-latest`. `ubuntu-latest` is
a moving alias; GitHub re-points it between images on its own schedule. A
release built there has a glibc floor that **nobody in this repository has ever
measured, that is not recorded anywhere, and that can rise without a commit.**
That is the D138 defect class exactly — a failure whose only symptom is
something not working somewhere nobody is looking.

### 1.2 musl: measured, failed twice, and the failure is not where the brief expects

`rust-toolchain.toml` pins `targets = ["wasm32-unknown-unknown"]`; adding a
target to the pinned toolchain is permitted and worked:

```
$ rustup target add x86_64-unknown-linux-musl --toolchain 1.92.0
info: downloading component rust-std
EXIT=0
$ rustup target list --installed --toolchain 1.92.0
wasm32-unknown-unknown
x86_64-unknown-linux-gnu
x86_64-unknown-linux-musl
```

So the *toolchain* is not the obstacle. The C toolchain is:

```
$ command -v musl-gcc x86_64-linux-musl-gcc
(neither found)
$ cc --version
cc (Debian 12.2.0-14+deb12u1) 12.2.0
```

**Arm A — default features:**

```
$ CARGO_TARGET_DIR=<scratch>/t-musl cargo build --release -p antseal-cli \
      --locked --target x86_64-unknown-linux-musl
error: failed to run custom build command for `ring v0.17.14`
Caused by:
  process didn't exit successfully: … build-script-build (exit status: 1)
  --- stderr
  error occurred in cc-rs: failed to find tool "x86_64-linux-musl-gcc":
  No such file or directory (os error 2)
MUSL_EXIT=101
```

**Arm B — `--features ant-backend`, i.e. the graph a shippable binary has:**

```
error: failed to run custom build command for `aws-lc-sys v0.43.0`
Caused by:
  process didn't exit successfully: … build-script-main (exit status: 1)
  warning: aws-lc-sys@0.43.0: Compiler family detection failed due to error:
  ToolNotFound: failed to find tool "x86_64-linux-musl-gcc"
MUSL_AB_EXIT=101
```

**A correction to my own method, recorded because it is the house defect class
and it nearly went into this record as a green.** Both builds were launched as
backgrounded compound commands ending in `tail`. The harness reported
**"completed (exit code 0)"** for both — the *wrapper's* exit, not the build's.
The real verdicts, `MUSL_EXIT=101` and `MUSL_AB_EXIT=101`, are only visible
because the exit code was echoed into the log and read back from there. Had I
trusted the notification I would have recorded "musl builds clean" and shipped
a false ruling. This is *Verify a failure by its message* in a new suit.

`ring` reaches the **default** graph through the anchor client, which is not
optional and not removable:

```
$ cargo tree -p antseal-cli -e normal -i ring
ring v0.17.14
├── rustls v0.23.43
│   └── ureq v3.3.0
│       └── antseal-anchor v0.0.0
│           └── antseal-cli v0.0.0
└── rustls-webpki v0.103.13
```

**What this does and does not prove.** It does **not** prove musl is impossible
— both failures are a missing cross-compiler, not a source incompatibility, and
installing `musl-tools` would move arm A forward. It **does** prove musl is not
free, that it is unproven for this workspace today, and that arm B's blocker
(`aws-lc-sys`, a CMake/NASM BoringSSL fork) is a materially harder problem than
arm A's. Adopting musl at M4 would mean adopting an unmeasured build, which is
the opposite of what the M4 gate is for.

### 1.3 What the cross-OS arms actually prove — much less than assumed

`.github/workflows/cross-os-extended.yml` runs exactly one command on each of
`macos-latest` and `windows-latest`:

```yaml
- name: Run cross-platform-sensitive suites (corpus_/vector_ filters; allowed-empty)
  run: bash scripts/ci-lanes.sh cross-os
```

and the whole of that lane (`scripts/ci-lanes.sh:935-944`) is:

```sh
lane_cross_os() {
  note "cross-platform-sensitive suites (corpus_ vector_; allowed-empty by design)"
  cargo test -p antseal-core --locked -- corpus_ vector_ || return 1
  …
  if [ "${matched}" -eq 0 ]; then
    printf '::notice title=cross-OS suite set is EMPTY::… vacuously green by design (Q1).\n'
  fi
}
```

Three findings, in ascending order of consequence:

1. **`-p antseal-core` only.** `cross-os-extended.yml` names no crate at all;
   the crate selection is inside the script. `antseal-cli` (the binary),
   `antseal-net` (the Autonomi/EVM boundary) and `antseal-anchor` (the HTTP/TLS
   substrate, and therefore `ring`) **are never compiled on macOS or Windows by
   any lane in this repository.** `ci.yml`'s `test` job is the only
   `cargo test --workspace --locked` and it is `runs-on: ubuntu-latest`.
2. **The filter is a substring filter over test paths**, not a suite. It selects
   the `corpus_`/`vector_` reserved-name tests. As a source-side proxy,
   `grep -rn 'fn [a-z0-9_]*\(corpus_\|vector_\)' crates/antseal-core --include=*.rs`
   returns **106** matches, so the set is no longer the empty one the `::notice::`
   was written for — but it is a deliberately chosen slice of one crate, sized
   for canonicalization and golden-vector stability, not for portability.
3. **Consequence for the wording of this decision, which is the reason it is
   here.** The maintainer's lean describes macOS and Windows as
   "CI-verified build-from-source". They are not. What is CI-verified on those
   two platforms is *one crate's canonicalization and golden-vector determinism*
   — which is a genuinely valuable property, and is precisely what
   `MVP-SPEC.md:170` asks for ("canonicalization idempotent and cross-platform
   stable"), and is **not** a build-from-source claim. §2 R7 fixes the wording.

**This does not contradict D138.** That record priced these arms and moved them
off the push path; their *content* was not its question. It is being read here
for the first time as a portability claim, and it does not support one.

### 1.4 The spec mandates no platform set — verified, not assumed

```
$ grep -n -i 'macos\|windows\|linux\|platform\|musl\|glibc' MVP-SPEC.md
170:- **(M0) UTF-8 corpus**: CRLF, NFD vs NFC, BOM, emoji/ZWJ, mixed scripts —
     canonicalization idempotent and cross-platform stable.
```

**One line, and it is the only one.** `macos`, `windows`, `linux`, `musl` and
`glibc` appear **nowhere** in the spec. The single hit is `cross-platform`, and
its subject is canonicalization determinism — a property of the *code*, which
Linux-only distribution does not touch and which §1.3's arms are exactly the
right instrument for.

**There is therefore no spec clause contradicting Linux-only, and this record
says so on evidence rather than by silence.** The two clauses that *do* bind are
`MVP-SPEC.md:157` — "**binary signing** (sha256sums + minisign/cosign) + documented
distribution channel" — which mandates *a* channel without naming one, and the
M4 gate clause, stated twice: at line 157, "verified end-to-end from a clean
machine using only the released (signature-checked) binary + the hosted page",
and again as the dedicated Verification entry at **`MVP-SPEC.md:175`**,
"**(M4) Gate**: … verified end-to-end from a clean machine using only the
released signed binary + the hosted verifier page; disk-loss restore drill"
(`TODO.md:794` restates it as the Q34 gate). The gate clause is what forces
§2 R2 and §2 R6; it is the sharpest platform-adjacent requirement in the
document and it is about *installability*, not about a platform set.

### 1.5 crates.io: the names are published, and the placeholders now block the real publish

Retrieved **2026-08-16T15:17:05Z–15:17:27Z**, `GET https://crates.io/api/v1/crates/<name>`:

| name | HTTP | version | published | by | license | yanked |
|---|---|---|---|---|---|---|
| `antseal` | **200** | 0.0.0 | 2026-08-11T13:48:44Z | `aed900` | `MIT OR Apache-2.0` | false |
| `antseal-core` | **200** | 0.0.0 | 2026-08-11T13:49:17Z | `aed900` | `MIT OR Apache-2.0` | false |
| `antseal-anchor` | **200** | 0.0.0 | 2026-08-11T13:49:50Z | `aed900` | `MIT OR Apache-2.0` | false |
| `antseal-net` | **200** | 0.0.0 | 2026-08-11T13:50:23Z | `aed900` | `MIT OR Apache-2.0` | false |
| `antseal-cli` | **200** | 0.0.0 | 2026-08-11T13:50:57Z | `aed900` | `MIT OR Apache-2.0` | false |
| `antseal-wasm` | **404** | — | — | — | — | — |

All five carry `description = "Reserved name for the antseal project (pre-M0
placeholder — see repo)"` and `repository = https://github.com/aed900/antseal`,
which is `scripts/reserve-crates.sh`'s generated metadata verbatim, at
33-second intervals matching its `PUBLISH_PAUSE_SECS=30`. **`--execute` was
run.** `antseal-wasm` is 404 because it is `publish = false` and was never in
the script's `CRATES` list.

**Permanence, from the source rather than folklore** — the Cargo Book,
*Publishing on crates.io*: *"Take care when publishing a crate, because a publish
is **permanent**. The version can never be overwritten, and the code cannot be
deleted."* And on yank: *"A yank **does not** delete any code… The semantics of a
yanked version are that no new dependencies can be created against that version,
but all existing dependencies continue to work."* **Yanking frees nothing and
hides nothing.**

**Does a reservation decay? No — and the risk runs the other way.** crates.io has
no inactivity expiry and *"will not transfer ownership of existing crates without
the explicit approval of the current owner"*. But the policy that RFC 3463
installed names as prohibited content anything that *"exists only to reserve a
name for a prolonged period of time (often called 'name squatting') without
having any genuine functionality, purpose, or significant development activity"*,
and states that *"the crates.io team may delete crates from the registry that do
not comply with the policies on this document… in most cases the team will first
give the author the chance to justify the purpose of the crate."*

**So the steady state the lean imagines does not exist.** Five empty `0.0.0`
crates whose own description says "placeholder" are the textbook shape of the
thing the policy prohibits; the protection is not silence but the fact that the
project is real and can be justified on request. *(Retrieval note: `crates.io/policies`
is a client-rendered page that could not be fetched verbatim; the quoted wording
was retrieved from RFC 3463, which is the document that installed it. Re-verify
against the live page before acting on §2 R8's review clause.)*

### 1.6 None of the five crates is publishable today — measured, and the cause is the reservation itself

```
$ cargo publish --dry-run -p antseal-core --allow-dirty
warning: crate antseal-core@0.0.0 already exists on crates.io index
warning: manifest has no description, license, license-file, documentation,
         homepage or repository
   Packaging antseal-core v0.0.0
error: failed to prepare local package for uploading
Caused by:
  failed to select a version for `antseal-core`.
      ... required by package `antseal-core v0.0.0`
  versions that meet the requirements `=0.0.0` are: 0.0.0
  package `antseal-core` depends on `antseal-core` with feature `test-util`
  but `antseal-core` does not have that feature.
PKG_CORE_EXIT=101
```

`cargo package --no-verify` fails identically (`NOVERIFY_EXIT=101`), so this is
the packaging step, not the verification build.

**Three distinct blockers in one output, and the third is the interesting one:**

1. **`0.0.0` is burned.** The next publish of any of the five must be a higher
   version. Expected, and confirmed by cargo itself.
2. **No `license`/`description`/`repository` fields.** Exactly as D6 predicted —
   they land at M4/Q29 — and cargo's own warning is the check.
3. **The house `test-util` pattern is a structural publish blocker, and the
   placeholder is what makes it bite.** `crates/antseal-core/Cargo.toml:133-134`
   declares a self-dev-dependency:
   ```toml
   [target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]
   antseal-core = { workspace = true, features = ["test-util"] }
   ```
   and `Cargo.toml:53` gives that workspace entry
   `{ path = "crates/antseal-core", version = "=0.0.0" }`. At package time cargo
   resolves the dev-dep against the **registry**, finds the published empty
   `0.0.0` placeholder — which has no features at all — and refuses. **The
   reservation artifact is actively blocking the real publish of the crate whose
   name it reserved.** `antseal-net` carries the identical pattern
   (`Cargo.toml:55-59`), and D34's forced sub-finding put the same edge on
   `antseal-cli`, so this is a family property, not one crate's.

   The `version = "=0.0.0"` is not gratuitous: `Cargo.toml:49-52` records that it
   exists so P13's `deny.toml` wildcard ban is satisfied for path deps. **Fixing
   publishability and satisfying the wildcard ban pull in opposite directions**,
   and neither this record nor any row owns that conflict — see §5.

### 1.7 The shipped binary's graph contains GPL-3.0 code, measured at the graph

```
$ cargo tree -p antseal-cli -e normal --prefix none | sort -u | wc -l
182
$ cargo tree -p antseal-cli --features ant-backend -e normal --prefix none | sort -u | wc -l
677
```

C-carrying and licence-carrying members of the **`ant-backend`** graph that are
absent from the default one:

```
aws-lc-rs v1.17.3      lzma-sys v0.1.20        self_encryption v0.36.0
aws-lc-sys v0.43.0     openssl v0.10.81        keyring v3.6.3
bzip2-sys v0.1.13      openssl-sys v0.9.117
```

(`ring v0.17.14` is in **both**.)

**D6's conclusion is confirmed at the dependency-graph level rather than from
crates.io metadata: `self_encryption v0.36.0` is in the shipped binary's normal
graph.** D6 reached this from ant-core's published dependency list; it is now
measured in the resolved tree. D35/P15's prohibition is untouched — it bans
*declaring* the edge from an antseal crate, and no antseal crate does; the
transitive arrival is exactly what D6 said the distribution consequence rests on.

**A finding for D50's follow-up that D50 could not have had: `keyring v3.6.3` is
already in the shipped graph**, transitively through ant-core. D50 argued the
keyfile wrap costs "zero new dependencies" while a keystore wrap would pull a
platform subtree into the audited graph. Half of that premise has moved — the
facade crate is already there. It does not change §3's answer, but it changes the
follow-up's cost arithmetic and must not be re-derived from D50's snapshot.

### 1.8 The repository is private, and there is no release machinery at all

```
$ gh repo view aed900/antseal --json isPrivate,visibility,createdAt
{"createdAt":"2026-07-27T20:59:42Z","isPrivate":true,"visibility":"PRIVATE"}
$ gh api repos/aed900/antseal/releases --jq 'length'
0
$ git tag --list
format-v1-freeze
pre-trailer-strip-949dd9d
$ grep -ln 'tags:\|release:' .github/workflows/*
(no match)
```

Eight workflows, none tag-triggered, no releases, no release workflow. Q31 builds
it from nothing, which is why this record's rulings are constraints on a design
rather than edits to one.

---

## 2. The ruling

### §2 R1 — The release target set is `x86_64-unknown-linux-gnu`, and it is the only one

Confirmed. macOS and Windows are **not** release targets: no binary is built,
signed, published or supported for them at M4.

**What is refused along with them, and why the refusal is on evidence:** the
tempting softener — "we don't ship them but they build fine from source" — is
**not available**, because §1.3 shows no lane has ever compiled the binary crates
on either platform. Adding macOS/Windows to the target set would mean adding
*two entirely unproven builds* to the release, on the same day the M4 gate is
supposed to be the strictest instrument in the project. That is the argument
that survives; "we only have Linux users" is not, because nobody has measured
that either.

### §2 R2 — The glibc floor is a released-artifact property: it is named, pinned, and asserted

Three obligations on Q31, in order of importance:

1. **The release job pins its image. `ubuntu-latest` is forbidden for the
   artifact build.** An unpinned alias means the floor moves without a commit
   (§1.1). Every other job may keep `ubuntu-latest`; the one that produces a
   signed artifact may not.
2. **A floor is chosen, written into the release notes and the Q22 install doc,
   and stated as a minimum glibc version** — not as a distro list, which ages
   badly and invites argument.
3. **The floor is ASSERTED in the release workflow, not assumed.** The check is
   the §1.1 command reduced to one line:
   `objdump -T <artifact> | grep -o 'GLIBC_[0-9.]*' | sort -u -V | tail -1`,
   compared against the declared floor, failing the release on a rise.

Obligation 3 exists because obligations 1 and 2 are otherwise an assertion that
cannot fail: a floor that is only *documented* has no failure mode, and the first
symptom of a silent rise is a user who cannot run the binary and has no way to
say so. **The check must be proven red before it is believed** — plant a floor
one minor version below the measured maximum and require the job to fail.

Today's measurement, for the record and as the starting point: this workspace on
a glibc-2.36 host produces a `GLIBC_2.34` artifact. **That is evidence about this
host, not a declaration of the floor**; the floor is Q31's to choose along with
the image, and choosing an older image is the lever that lowers it.

### §2 R3 — musl is NOT adopted at M4, and this is the record that stops it being re-proposed blind

Refused on the §1.2 measurement, with the failures named so the next proposal
starts from them rather than from optimism:

- default features fail at **`ring v0.17.14`**, `ant-backend` at
  **`aws-lc-sys v0.43.0`**, both for a missing `x86_64-linux-musl-gcc`;
- `ring` is **not removable** — it arrives via `rustls` ← `ureq` ← `antseal-anchor`,
  the anchor client, which is the product;
- the two failures are **not the same difficulty**. `musl-tools` plausibly clears
  `ring`. `aws-lc-sys` is a CMake/NASM BoringSSL fork and is the real work.

**Stated honestly: this is a refusal on unmeasured cost, not on impossibility.**
A static binary genuinely would answer §2 R2 more cleanly than pinning an image
does — one artifact, no floor, no image to age. If the glibc floor becomes a
real user complaint, musl is the right next investigation and §1.2 is its
starting point. It is refused **for M4** because adopting it means shipping a
build nobody has completed, and the M4 gate is the wrong place to debut one.

### §2 R4 — The released binary is built `--features ant-backend`. Its distribution is GPL-3.0.

Ruled here because **D89 §Consequences 6** assigned it here in terms
(*"Release targets and the release build's feature set are not pre-committed by
anything here"*), and the brief did not carry it.

A default-feature build cannot reach Autonomi at all — §1.7 measures the
difference as 182 packages against 677 — so a released `antseal` that cannot
seal is not a release. Therefore:

1. The release artifact is `cargo build --release -p antseal-cli --features ant-backend`.
2. **`self_encryption v0.36.0` (GPL-3.0) is in that artifact's normal graph
   (§1.7). D6's "distribution effectively GPL-3.0" for `antseal-cli` is
   confirmed as a fact about the shipped binary**, not a forecast.
3. **The release notes and the Q22 install doc must state the binary's effective
   licence, and complete-source-offer obligations attach to the distribution.**
   Q29 owns the LICENSE files; this record owns the finding that the obligation
   is live at first release rather than conditional.
4. D35/P15's prohibition is **unaffected** and must not be read as contradicted:
   it bans a *declared* edge from an antseal crate, and there is none. The
   permissive core and the verifier page keep their split — `antseal-core`'s
   default graph and `antseal-wasm` do not contain `self_encryption`.

### §2 R5 — The channel is GitHub Releases, single authoritative source, with signing per D71/Q30

Confirmed, and it satisfies `MVP-SPEC.md:157`'s "documented distribution
channel". No package managers, no third-party mirrors, no `cargo install` path
at M4 (which §2 R8 forecloses anyway). Every artifact ships with `sha256sums`
plus the D71 signature; the release page is the only place the project tells
anyone to get a binary.

### §2 R6 — R5 is INOPERATIVE while the repository is private. Q65 becomes a precondition of Q31 and Q34.

This is the ruling the brief did not ask for and the one most likely to change a
schedule.

Release assets inherit repository visibility: on a private repository they
require an authenticated account with access. **Q34's gate requires a clean
machine to install the released binary from the documented channel and verify
its signature** (`MVP-SPEC.md:175`; `TODO.md:794`; `tasks/Q.md:539` clause (b),
whose Accept row at `tasks/Q.md:542` is stricter still — *"Clean-machine
procedure uses zero repo-checkout resources (released artifacts + hosted page
only)"*). A clean machine cannot authenticate to a
private repository without being handed a credential, at which point it is not
the clean third-party machine the gate is testing.

Therefore **the gate cannot be discharged as specified until the repository is
public**, and going public is precisely what **Q65** owns — including the
`/home/deb/…` path scrub in five tracked files, which Q65 records is *"cheapest
to fix before a visibility change, because afterwards it needs a history
rewrite to undo."*

**Ruling:** Q65 is a **precondition** of Q31's release execution and Q34's gate,
not a parallel M4 row. Q65's own trigger — *"becomes urgent the moment making the
repo public is considered for any reason"* — is **fired by this record**.

Recorded so the alternative is not silently lost: the only ways to keep the
repository private are to host artifacts somewhere public that is not GitHub
Releases, which contradicts R5, or to relax the gate's clean-machine clause,
which contradicts the spec. **Neither is chosen here.** The ordering change is
the cheaper answer and it is the one ruled.

### §2 R7 — What the release notes may say about macOS and Windows

Binding wording rules for Q22 and the release notes, because §1.3 makes the
natural phrasing false:

- **PERMITTED:** "Released binaries are provided for Linux x86_64 only." ·
  "The verifier page runs in any modern browser on any platform." ·
  "`antseal-core`'s canonicalization and golden-vector determinism are tested on
  Linux, macOS and Windows in CI." (True — that is exactly §1.3's arms.)
- **FORBIDDEN:** any claim that antseal *builds*, *runs* or is *supported* on
  macOS or Windows, and any phrasing implying build-from-source works there.
  **No lane has ever compiled the binary on either.**
- **FORBIDDEN:** implying the verifier page's platform reach is the CLI's. The
  page is genuinely cross-platform; the binary is not.

### §2 R8 — crates.io: no real publish at M4. The five placeholders stay, are documented, and get a review date.

**No `antseal*` crate is published to crates.io as part of the M4 release.**
Four independent reasons, each measured, any one sufficient:

1. **It is not currently possible.** §1.6: `PKG_CORE_EXIT=101`, and the cause is
   structural (the self-dev-dep), not a missing metadata field.
2. **A publish is a permanent, irrevocable public source disclosure that routes
   around Q65.** `cargo publish` uploads the crate's source tarball; the Cargo
   Book's *"the code cannot be deleted"* and *"a yank does not delete any code"*
   mean there is no undo. Publishing `antseal-core` while the repository is
   private would make that crate's source public **without the scrub Q65 exists
   to perform**, in a place from which it cannot be withdrawn.
3. **It would put a permanent licence assertion on an immutable index (D6).**
   A real `antseal-cli` carries `self_encryption` (§1.7). Publishing it under a
   bare `MIT OR Apache-2.0` — which is what the placeholders already say, and
   which is *correct for an empty placeholder and wrong for the real crate* —
   would be a licence misstatement that can be superseded but never removed.
4. **The channel is already ruled (R5) and crates.io is not it.** A second source
   of binaries contradicts "single authoritative source"; `cargo install antseal`
   would also be an **unsigned** acquisition path, defeating Q30/D71 for anyone
   who used it.

**Disposition of the five live placeholders — the part the lean's framing had no
room for.** They cannot be un-published, and yanking would achieve nothing (it
hides a version from resolution, frees no name, deletes no code). They stay.
But "reserved and forgotten" is not a stable state (§1.5): they are, on their
face, what crates.io's policy calls name squatting, and their protection is that
the project is real and can be justified if the team asks. Therefore:

- Q31 records the five names, their owner account, their publish date and their
  `0.0.0` status in the release documentation, so the reservation is a **known
  project asset with a stated purpose** rather than five orphans.
- **A review date is set: the first release after M4.** At that point either a
  real version ships (which converts the reservation into ordinary
  development activity and ends the exposure), or the placeholders are
  re-justified deliberately. **What is refused is letting them sit indefinitely
  with nobody owning the question.**
- If a real publish is ever wanted, §1.6's blockers are the entry cost and
  **§5.1's task must be done first**.

### §2 R9 — Nothing here is a portability claim about the code

Recorded because the failure mode of a Linux-only ruling is that it hardens into
a belief that the code is Linux-specific. It is not, and nothing measured today
says it is. `antseal-core` is WASM-safe and passes its determinism suites on
three OSes. **What is Linux-only is the release, for the reasons in R1 and R2 —
absence of evidence about other platforms, not evidence of absence.** A future
decision that adds macOS should start by extending §1.3's lane to compile the
binary crates, and that measurement is cheap.

---

## 3. The cascade: U33 closes, D50's follow-up is answerable and the answer is "no"

### 3.1 U33 — closes on a recorded limitation

`TODO.md:815` / `tasks/U.md:543`. U33's own text is dispositive and this record
takes the branch it names: *"If Windows is not a D72 target, close this task with
a one-line register note."*

**Windows is not a target (R1), so U33 closes.** Its Accept row — *"D72-resolved
branch taken explicitly (implementation OR recorded limitation, never silence)"*
— is satisfied by this section.

Precisely what is and is not affected, since U33's subject is a *code* behaviour
that outlives the decision:

- **No code changes.** `--passphrase-fd 0` works on every platform via
  `std::io::stdin`; non-stdin descriptors work through `/dev/fd/<n>` where it
  exists. The typed `FdReadFailed` behaviour is unchanged and its snapshot
  coverage stays.
- **No inherited-handle plumbing is written**, and the `unsafe`/platform-crate
  decision U33 anticipated does not arise. That is the whole saving.
- **A documentation obligation lands on Q22**, small but real: `--passphrase-fd`
  documentation must describe the `/dev/fd` mechanism as what it is, rather than
  promising portable non-stdin descriptors. The primary scripting shape
  (`printf … | antseal …`, fd 0) is unaffected.
- **Reopening is cheap and the trigger is explicit**: if a later decision adds
  Windows, U33 reopens with its brief intact.

### 3.2 D50's OS-keystore follow-up — unblocked, and answered NO

D50 deferred the keystore wrap's platform scope to *"a follow-up decision AFTER
D72 resolves"*. D72 has resolved, so the follow-up is answerable. **The answer is
that wrap-mode 2 stays unimplemented at M4**, and the reasoning inverts the
expectation the register's phrasing sets up.

**Linux-only does not unblock the keystore — it selects the one platform on which
D50's own evidence says the keystore is worst.** D50 §Evidence records that Linux
has no universally durable keystore: the Secret Service path assumes a desktop
session with an unlocked login keyring, which headless CLI users do not have, and
`linux-keyutils` is a kernel keyring that is *"memory-resident, not persistent
across reboot"* — which D50 calls *"not a wrap, it is a time bomb: first reboot ⇒
vault permanently unopenable."* macOS Keychain and Windows Credential Manager are
the two durable, session-integrated stores in the landscape, and R1 has just
removed both from scope. **A Linux-only release is therefore the release with the
least reason to build a keystore wrap, not the most.**

Two further inputs, one new and measured today:

- **D47's export re-wrap constraint stands unpaid.** A machine-bound factor does
  not travel in a `vault export`, so the M4 disk-loss drill (`tasks/Q.md:539`
  clause (c)) would import a vault whose second factor died with the old machine.
  D50 requires `vault export` to re-wrap to portable factors or refuse before any
  keystore ships. That work does not exist and M4 is not where it should debut.
- **NEW (§1.7): `keyring v3.6.3` is already in the shipped binary's graph**,
  transitively via ant-core. D50's dependency-cost argument was written against
  a workspace with no keyring anywhere. **The follow-up must re-derive its cost
  from this measurement, not from D50's snapshot** — and note the version
  disagreement: D50 surveyed the churn-active `keyring 4.1.6` line, while what is
  actually resolved in this tree is `3.6.3`.

**Is leaving mode 2 unimplemented a permanent format-registry consequence?
No — it is reversible, and this was checked rather than assumed.** The wrap-mode
registry is the vault header's, in `crates/antseal-cli/src/vault/header.rs`
(`WrapModeUnknown { found: u64 }`); `grep -rn -i 'wrap.mode' docs/format/` returns
**no hits**, so the slot is **not** in the Q14 frozen format registry —
confirming D50's own statement that *"nothing here enters the Q14 freeze."* The
`.sealproof` bundle and manifest formats are untouched by it. Mode 2 remains a
reserved id in a CLI-side registry, an M4 binary continues to reject it with the
distinct "wrap mode not supported" error, and implementing it later stays
**additive** exactly as D50 designed. **What D50's residual-risk note requires is
unchanged: the id is honoured or formally retired through the register, never
reused.** This record honours it by leaving it reserved and stating why.

**Register consequence:** D50 §Consequences 5 and §Discovered-work anticipated
*"a new U-task + register decision pair, created when D72 lands."* Given that the
answer is "not at M4 and not on Linux", the follow-up should be minted as a
**parked** row with this section as its brief — not as active M4 work. See §5.

---

## 4. What this record does NOT decide

1. **The signing mechanism and key custody.** minisign vs cosign vs both, and
   the custody procedure, are **D71/Q30** and remain open. R5 assumes signatures
   exist; it does not choose them.
2. **The exact glibc floor number, or which pinned runner image is used.**
   §2 R2 requires that a floor be chosen, pinned, documented and asserted, and
   supplies today's measurement as the starting point. Picking the image is
   Q31's, because it is a trade between reach and toolchain age that wants the
   release workflow in front of it.
3. **The version and tag scheme.** `tasks/Q.md:528` gives Q31 app SemVer tags,
   independent format-version integers, and freeze tags. Untouched here beyond
   noting `0.0.0` is burned on the registry (§1.6).
4. **Whether the repository goes public, and what is scrubbed.** §2 R6 rules that
   Q65 must resolve *before* Q31/Q34, and fires its trigger. **It does not
   pre-empt Q65's answer**, including the answer "stay private indefinitely" —
   which Q65 explicitly permits, and which would force R5/R6 back open with the
   channel question genuinely unsolved.
5. **Whether a future release adds macOS, Windows, ARM64 Linux, or musl.** R1
   and R3 are M4 rulings. R9 states the reopening path; §1.2 is musl's starting
   evidence.
6. **Whether the five placeholder crates are ever superseded by real versions.**
   R8 sets a review date and refuses an indefinite unowned drift; it does not
   decide the review's outcome.
7. **Distribution beyond the first release.** No package manager, distro package,
   container image or `cargo-binstall` manifest is ruled in or out for later.
8. **`antseal-wasm`'s publication.** It is `publish = false` (D18 §5 R1) and the
   page ships as a hosted artifact. Unchanged, and 404 on the registry (§1.5) is
   the expected state.
9. **Whether `ring` should be replaced to ease a future musl build.** §1.2 names
   it as the default-graph blocker; changing the TLS backend of the anchor client
   is a dependency-policy event of its own and no part of this record.

---

## 5. What this ruling owes

1. **`antseal-core` and `antseal-net` cannot be packaged at all while the
   self-dev-dep carries `version = "=0.0.0"` (§1.6), and the fix collides with
   P13's wildcard ban.** Dropping the version makes the dev-dep a bare path dep
   (which cargo strips at package time, unblocking the publish) and trips
   `deny.toml`'s wildcard rejection; keeping it keeps the crate unpublishable.
   **Nobody owns this**, it is invisible to every lane in the tree because
   nothing runs `cargo package`, and it will be discovered at the worst possible
   moment — the first time someone tries to publish. It needs a row (§6).
2. **A pinned-image release job and the `objdump` floor assertion** (§2 R2) are
   Q31's build, including the planted-fault proof that the assertion can go red.
3. **`docs/ci-verification.md`** describes the environment as
   `x86_64-unknown-linux-gnu` (line 15) but records no glibc floor and no
   released-artifact story. It gains both when Q31 lands. Outside this lane's
   write scope.
4. **Q22's install doc** owes: the Linux-only statement in §2 R7's permitted
   wording, the glibc floor, the effective-licence statement from §2 R4(3), and
   the `--passphrase-fd` correction from §3.1.
5. **Q65 must be re-read in the wave that acts on §2 R6**, since this record
   fires its trigger and changes its position in the M4 ordering.
6. **No lane, gate or CI job enforces anything in this record.** Every ruling
   here is prose until Q31 builds the release workflow. That is the honest state,
   and §2 R2's assertion requirement exists because prose is not a check.

---

## 6. Discovered work (described, not registered — the registrar mints these)

1. **Q-domain, M4, blocks any crates.io publish, size S.** *"The `test-util`
   self-dev-dep makes every publishable antseal crate unpackageable, and the fix
   collides with P13's wildcard ban."* Reproducer: `cargo package --no-verify -p
   antseal-core --allow-dirty` → exit 101. Must resolve the conflict between
   `Cargo.toml:49-52`'s stated reason for `version = "=0.0.0"` and cargo's
   packaging behaviour, and should add a `cargo package --no-verify` smoke check
   so the answer cannot silently rot. **Note the second-order question this row
   must settle rather than assume: whether the failure survives a version bump to
   a version that does not yet exist on the registry** — today's failure is
   measured against the *published* `0.0.0`, and whether it generalises to every
   future version was not proven here and must not be assumed either way.
2. **Q-domain, M4, size S.** *"The release artifact's glibc floor is unpinned and
   unasserted."* §2 R2's three obligations, with the planted-fault proof. Rides
   on Q31 if Q31 is not split.
3. **U-domain, PARKED (not M4), size M.** *"OS-keystore wrap (mode 2): platform
   scope + implementation."* D50 §Discovered-work required this pair be minted
   when D72 landed. Mint it **parked**, with §3.2 as its brief: the answer for
   M4 is *no*, the reasons are Linux's durability gap and D47's unpaid export
   re-wrap, and the cost inputs must be re-derived from `keyring v3.6.3`-already-
   in-graph rather than from D50's `4.1.6` snapshot.
4. **Q-domain, ordering change, no new work.** Q65 moves from *"M4 alongside
   Q22/Q28"* to *"precondition of Q31 and Q34"* per §2 R6, and its trigger is
   fired.
5. **Q-domain, size S, quality — the finding with the widest blast radius beyond
   this decision.** *"`cross-os-macos`/`cross-os-windows` compile one crate, and
   their name promises a whole workspace."* §1.3. Two required status contexts
   named `cross-os-*` produce, on a reasonable reading, a cross-OS guarantee the
   project does not have; D50 §Context already read them that way in writing
   (*"CI today runs three OS lanes"*), which is evidence the misreading is
   natural rather than hypothetical. Either widen the lane, or rename the
   contexts, or document the scope where a reader meets it — but the gap between
   the name and the content should not survive unrecorded. **Renaming a landed
   required context is forbidden by `ci.yml`'s own header rule**, so this row is
   more constrained than it first looks.
