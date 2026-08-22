# Versioning

**Your bundle says format v1. Your binary says something else. Which one
matters?**

Both, for different things — and they are deliberately not the same number.

The short version: **the version of the program never decides whether your
bundle verifies.** A `.sealproof` is verified against the *format* it declares,
and the format is a separate integer with a separate promise attached to it.
Upgrading antseal cannot invalidate a bundle you already hold, and downgrading
it cannot either.

This page says which numbers exist, what each one is allowed to change, and
where you can read each one off a real artifact. What forces the *format*
number to move is a different question with its own page — see
`format-stability.md` §8, which this page does not restate.

## 1. There are five numbers, not two

They are five because a build that showed one label for several of them would
hide a real divergence. The page's own build record carries all of these as
separate fields (`crates/antseal-wasm/src/build_info.rs:34-48`, one field per
row below).

| number | what it identifies | where it lives | today |
| --- | --- | --- | --- |
| **release version** | the thing you downloaded: CLI binary and its tag | `antseal --version`; the git tag; the signature's trusted comment | `0.0.0`, and no release has happened |
| **`core_version`** | the verifying library inside that binary | `crates/antseal-core/src/lib.rs:45` | `0.0.0` |
| **`binding_version`** | the WASM boundary crate the page loads | `crates/antseal-wasm/src/build_info.rs:55` | `0.0.0` |
| **format version** | which wire format your bundle is written in | key 0 of the manifest body and of the bundle (registry §7.2, §7.6) | `1` |
| **`report_version`** | the shape of the verdict document a verifier emits | `crates/antseal-core/src/verify/report.rs:103` | `1` |

`core_version` and `binding_version` are split on a recorded reason rather than
by accident: the comment at `crates/antseal-wasm/src/build_info.rs:38-40` says
*"the two can diverge and a footer that showed one label for both would hide
it."*

A sixth field is not a version at all but belongs in the same list, because it
is what actually identifies a build: **`source_commit`**, the 40-character
commit the artifact was compiled from
(`crates/antseal-wasm/src/build_info.rs:26`). Section 5 explains why it, and
not any version number, is what a reproducibility check compares.

## 2. The independence, stated as the format itself states it

The release version **is** written into every bundle you produce. That sounds
like a dependence and is the opposite of one, because of how the frozen format
classifies the field.

The manifest body carries the producing build's version at **key 1**,
`app_version`. The frozen registry describes that key, in its own words, as:

> free-form, informational only (producing build; never verdict-bearing)

— registry §7.2, the manifest-body table, key 1.

*Never verdict-bearing* is the whole statement. A verifier reads the field and
records it; nothing in a verdict may turn on its value. So a bundle sealed by
`antseal 0.1.0` and the same bundle sealed by `antseal 9.9.9` verify
identically, and a verifier that behaved otherwise would be violating the
frozen registry rather than exercising a policy.

The same section records that key 1 is **required but may be empty**, and that
*"no non-empty check may ever be added"* — because adding one would reject a
bundle a released verifier had accepted, which is the illegal direction under
`MVP-SPEC.md` line 123. The independence is therefore permanent in the strong
sense: it cannot be narrowed later without breaking the format-stability
promise.

## 3. The independence is also enforced mechanically, in two places

A policy that only exists in prose is one careless commit from being untrue.
Two mechanisms make this one hold without anyone remembering it.

**The golden vectors do not record the real version.** Every committed test
vector writes a fixed placeholder instead:

```rust
pub const APP_VERSION: &str = "antseal-fixture/1";
```

`crates/antseal-core/src/manifest/fixtures.rs:39-42` states why in its own doc
comment: *"a fixed placeholder, never the real crate version, so a version bump
cannot silently change committed vector bytes."* Because the frozen vectors are
byte-pinned, a release-version bump that leaked into them would turn the vector
freeze red. It cannot leak, so it does not.

**A build declares a set of supported format versions, not one.**

```rust
pub const SUPPORTED_VERSIONS: &[u64] = &[1];
```

`crates/antseal-core/src/format.rs:115` — and its doc comment at `:112-114`
records the direction rule: *"v1 is the sole entry and the only version that
has ever been released. A future release appends; it never edits or removes."*
One build verifying many format versions is what makes the two numbers
independent in practice, and the list shape is what makes appending the only
available move.

## 4. The tag scheme

Two kinds of tag, which never share a namespace.

| tag | shape | what it marks | in this repository today |
| --- | --- | --- | --- |
| release | `v<major>.<minor>.<patch>` | a released binary set | none — no release has happened |
| format freeze | `format-v<n>-freeze` | the moment format `v<n>` became immutable | `format-v1-freeze` exists |

Both were measured with `git tag --list` on 2026-08-22: the tags present are
`format-v1-freeze` and `pre-trailer-strip-949dd9d`, and no `v*` release tag
exists.

**Release tags follow SemVer over the CLI surface**, not over the format. A
major bump means the command surface broke compatibility — a removed flag, a
changed exit code, a renamed subcommand. It does **not** mean the format moved,
and it must never be read as meaning that.

**Freeze tags are annotated and are cut once per format version.** The ceremony
that produces one is `format-stability.md` §9; step 6 of that section is the
tag itself. A freeze tag is never moved and never re-cut.

The release version passed to the signing step is the release tag, and it is
carried inside the signature rather than beside it:

```
antseal <version> <artifact-basename> commit:<40-hex> <RFC3339 UTC timestamp>
```

That string is the trusted comment required by
`docs/decisions/D71-binary-signing-mechanism-and-key-custody.md` §2 R4, built
at `scripts/sign-release.sh:250`. It is covered by the signature, so the
version cannot be altered after signing without the secret key. The
*untrusted* comment is free text that anyone can rewrite while the artifact
still verifies, and D71 §2 R4 forbids this project from putting a version, a
filename or any other meaningful value there.

## 5. What a version number cannot tell you, and what can

The verifier page publishes a build hash so that anyone can rebuild it and
compare. That comparison is **not** made against a version number, and this is
the part most easily got wrong.

The page module stamps the commit it was built from through the build script:
`crates/antseal-wasm/build.rs:22-40` reads `ANTSEAL_SOURCE_COMMIT` and re-emits
it as a compile-time environment value, with
`cargo::rerun-if-env-changed=ANTSEAL_SOURCE_COMMIT` at `:22`. A build without
one stamps `unknown` rather than failing (`:24`).

The consequence, recorded at `docs/ci-verification.md:2641-2647`: two commits
with **identical compile inputs** produce modules of identical size and
**different digests**, because the commit string is itself an input. So:

- **A published page hash reproduces at the commit it was deployed from, and at
  no other commit** — including a later commit that changed nothing.
- The honest claim is *"reproducible at the commit it was deployed from"*, never
  *"reproducible from HEAD"*. `docs/ci-verification.md:2651-2652` states this
  in those words.

If you want to check the live page yourself, build at the deployed commit and
compare bytes — `scripts/pages-publish.sh --verify` does exactly that
comparison at `scripts/pages-publish.sh:132-145`, against the sums a local
`--build` produced. The page is at `https://antseal.org/`, and its footer shows
the module digest.

## 6. What each number is allowed to do to the other

| change | moves the release version? | moves the format version? |
| --- | --- | --- |
| bug fix, new flag, better message | yes | no |
| breaking CLI change | yes, major | no |
| assigning a reserved slot as a new optional field | yes | no — `format-stability.md` §8 lists this as *not* a bump |
| raising a parser cap | yes | no — limits may be raised, never lowered |
| a real format change (`format-stability.md` §8's first table) | yes, whichever SemVer level the CLI surface warrants | yes, and a new freeze tag |

Read the table one way and it says something worth saying plainly: **the format
version moves rarely, the release version moves often, and no row makes an old
bundle stop verifying.** That is obligation 2 of `MVP-SPEC.md` line 123, and
`format-stability.md` §3 is where it is stated and enforced.

## 7. Where you read each number off a real artifact

| number | how to read it |
| --- | --- |
| release version of your binary | `antseal --version` (the flag is declared at `crates/antseal-cli/src/cli.rs:46`) |
| release version recorded in a bundle | the manifest's `app_version`, key 1 of registry §7.2; written at `crates/antseal-cli/src/commands.rs:394` as `antseal/<version>` |
| format version of a bundle | key 0 of the bundle map, registry §7.6 — the first key on the wire, by design |
| format versions your build accepts | `SUPPORTED_VERSIONS`, `crates/antseal-core/src/format.rs:115` |
| the page's build identity | the footer at `https://antseal.org/`, and `build_info()` at `crates/antseal-wasm/src/build_info.rs:52-60` |
| the version a signature attests | the trusted comment, printed by `scripts/verify-release.sh` |

## 8. What this page does not promise

- **It does not promise a release exists.** Measured 2026-08-22: every crate in
  this workspace is `version = "0.0.0"`, and
  `crates/antseal-core/src/lib.rs:54` asserts that value in a test. No `v*` tag
  exists. Every release-side statement here is the scheme a release will
  follow, not a description of one that has shipped.
- **It does not restate what forces a format bump.** That is
  `format-stability.md` §8, and duplicating it would create a second source of
  truth for a frozen policy. Where the two pages appear to disagree,
  `format-stability.md` governs the format and this page governs the release.
- **It does not describe the release procedure.** The gate a release must pass
  before it reaches you is `release-checklist.md`.

## Evidence

| Claim on this page | Where it is enforced |
| --- | --- |
| five distinct version fields, one per struct field | `crates/antseal-wasm/src/build_info.rs:34-48` |
| the two crate versions are split on a recorded reason | `crates/antseal-wasm/src/build_info.rs:38-40` |
| `app_version` is informational and never verdict-bearing | `docs/format/registry-v1.md`, registry §7.2 key 1 |
| no non-empty check on `app_version` may ever be added | registry §7.2, the paragraph following the body table |
| vectors record a placeholder, not the crate version | `crates/antseal-core/src/manifest/fixtures.rs:39-42` |
| a build supports a *set* of format versions | `crates/antseal-core/src/format.rs:115`, doc comment at `:112-114` |
| format v1 is the integer 1 in both registries | `crates/antseal-core/src/manifest/registry.rs:47`; `crates/antseal-core/src/bundle/registry.rs:58` |
| the report document has its own version | `crates/antseal-core/src/verify/report.rs:103` |
| the commit is stamped into the page module | `crates/antseal-wasm/build.rs:22-40` |
| a page hash reproduces only at its deployed commit | `docs/ci-verification.md:2633` section, measured at `:2641-2652` |
| the served bytes are compared against a local build | `scripts/pages-publish.sh:132-145` |
| the signature carries version, basename and commit | `scripts/sign-release.sh:250`; D71 §2 R4 |
| `--version` exists on the CLI | `crates/antseal-cli/src/cli.rs:46` |
| the recorded version in a seal is `antseal/<version>` | `crates/antseal-cli/src/commands.rs:394` |
| the format-stability promise itself | `MVP-SPEC.md` line 123; `format-stability.md` §1 |
