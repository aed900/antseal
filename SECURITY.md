# Security policy

antseal seals content and later proves things about it. Everything it is for
lives inside a verifier that strangers are invited to run, so a flaw in that
verifier is not a defect in a feature — it is a defect in the whole claim.
Reports are wanted. This page says where to send one, when to expect an
answer, and what this project will and will not treat as a security issue.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting.** On this repository:
**Security → Advisories → Report a vulnerability**, or go directly to
<https://github.com/aed900/antseal/security/advisories/new>. That opens a
draft advisory readable only by you and the maintainer.

**If that link does not resolve, private reporting is not available on this
repository right now** — GitHub offers it on a public repository with the
feature switched on, and nowhere else, so it is not something this project can
enable ahead of publication. This policy states that condition rather than a
date, because any sentence about *when* the route opens is wrong on one side of
it. Check the link. If it is dead, take the *"Request a private channel"*
route described below, and not the public tracker.

**Do not open a public issue for a security finding.** The blank-issue route
is switched off and the issue chooser offers the private form first, so the
public tracker should never be the first place a finding lands.

**If you cannot use that form** — no GitHub account, or the advisory route is
not available on this repository — open the *"Request a private channel"*
issue and put **no detail in it at all**: not the component, not the symptom,
not a reproducer, and nothing in the title. That form has no field for detail
on purpose. A maintainer will open a private advisory and invite you into it.

### What to put in the report

- **The commit** you tested. Nothing has been released, so a version number
  will not identify a build; the SHA on `main` will.
- **What you did, what you expected, and what happened.** For a verification
  finding, the useful shape is a bundle that reaches the wrong verdict.
- **A reproducer**, if you have one — a `.sealproof` bundle, a golden vector,
  a script.
- **What you think it buys an attacker.** A verdict that should have been
  refused, evidence that survives a mutation it should not survive, and key
  material that escapes the vault are three different severities.

**Send no real secret material.** This project's own rule is that master
secrets, unit keys, salts and wallet keys never enter the repository, in code
or logs or fixtures, and that applies to the evidence you send as much as to
the code we write. Reproduce with a throwaway vault and a devnet or testnet
wallet. If a finding genuinely cannot be shown without a real key, say so in
the advisory and stop there — do not attach it.

## What to expect

| | |
| --- | --- |
| Acknowledgement that the report arrived | within **7 days** |
| An assessment — in scope or not, and what we think it costs an attacker | within **21 days** |
| Silence past an acknowledgement you were promised | after **14 days**, assume it did not arrive and use the private-channel issue above |

This is a pre-release project with one maintainer. Those windows are what one
person can hold, and they are stated rather than inflated.

**On disclosure.** Nothing has been released, so there is no installed base an
embargo would protect, and this project will not ask you to sit on a finding
indefinitely. The intended path is a GitHub Security Advisory published when a
fix is on `main`, crediting you unless you would rather it did not. If you
plan to publish on your own schedule, say so in the report and we will work to
it rather than around it.

## Supported versions

**No version of antseal has been released.** Every crate in the workspace
carries the placeholder version `0.0.0`, no signed binaries are published, and
the only way to run it is to build from source. The supported version is
therefore **the current commit on `main`**. There is no older release to
back-port a fix to.

**The formats are the part with a long tail, and they are supported
separately.** `format-v1` is frozen: its definitions are permanent, and once a
release exists, a bundle produced under v1 must stay verifiable by every later
release. A flaw in the v1 format, or in the code that verifies it, does not
stop mattering when a later version ships — so report it against the format
rather than against a build, and say so in the advisory.

## Scope

**What antseal claims, so that a report can be measured against it.** A seal
proves that the holder of a key possessed specific content by a specific time.
It does not prove authorship, and it does not prove that nobody else held the
same bytes: an earlier seal by someone who received your work outranks yours,
which is why the advice is to seal before you share. antseal is proof of
existence, integrity and priority; it is not a legal notary. A finding that
antseal fails to deliver one of the three properties it does claim is in
scope. A finding that it fails to deliver a property it never claimed is a
documentation question, and welcome as one.

### In scope

- **Verification.** Anything that makes a bundle verify when it should not, or
  fail when it should not: commitment and Merkle-tree construction, the
  selective-disclosure openings, the signature policy, the structural
  invariants, and the verdict a bundle ends up with.
- **The sealed formats.** The manifest, the `.sealproof` bundle, the domain-tag
  and key-derivation registries, and the strict decoder that rejects
  non-canonical encodings.
- **Parsing untrusted input.** Bundles, DER timestamp tokens and `.ots` files
  arrive from adversaries. A panic, an unbounded allocation, a hang, or a read
  outside a cap is a vulnerability here, not a robustness nit.
- **Anchor verification.** Timestamp-token and calendar-proof handling,
  certificate-chain validation against the pinned roots, expiry semantics, and
  anything that promotes an anchor to a stronger state than its evidence
  supports.
- **Key and vault handling.** Key derivation, AEAD nonce discipline, the vault
  encryption parameters, and any path that puts secret material into a log, an
  error message, a temporary file, or a bundle.
- **The verifier page** served from <https://antseal.org/>: any divergence
  between what the page renders and what the same bundle verifies to natively,
  and any break in the chain that lets you check the page you were served —
  the published digests, the reproducible build, the footer build hash.
- **Redaction and reveal.** Anything that discloses more of an unrevealed unit
  than the design says a reader may learn.

### Not in scope

These are documented properties of the design. Reports about them are read and
answered, but they are not vulnerabilities in this project and they will not
get an advisory.

- **Autonomi's availability, reachability or honesty.** Evidence validity never
  depends on the network: a `.sealproof` bundle is self-contained and verifies
  fully offline, and the network is never trusted for time. Storage permanence
  is a bonus this product offers, not the thing its proof rests on. An outage,
  an unreachable chunk or a network reset costs you retrieval, not evidence.
  *A verifier that consults the network before returning a verdict would be in
  scope, and squarely so.*
- **A host that serves a different verifier page.** A page is JavaScript served
  by a host, and a host that serves something else can render any verdict it
  likes. That threat is structural and no page can close it, which is why an
  independent command-line verify exists and why the build is reproducible with
  published digests. What *is* in scope is a break in those mitigations.
- **A vault holder who is made to open the vault.** Whoever holds the vault and
  its passphrase can be required to use them; destroying the vault is the only,
  irreversible, way out. That is a stated limit of the design, not a flaw in it.
- **Metadata a bundle necessarily exposes.** A redaction view shows the position
  and total size of what it withheld, and unit sizes leak a coarse shape. Both
  are documented. A leak *beyond* what is documented is in scope.
- **Browser memory hygiene.** WebAssembly cannot reliably scrub its own heap,
  and the verifier page is written not to hold anything worth scrubbing. The
  caveat is recorded; a page that holds secret material it should not is a
  different report, and that one is in scope.
- **Third-party timestamp services.** An outage, a rate limit or a change of
  terms at a calendar or a timestamp authority is not a flaw here. A failure to
  *detect* a bad or untrusted token is.
- **The local development network and the test fixtures.** Deliberately
  low-friction, never used to hold anything real.
- **Findings in dependencies**, which belong upstream — though if one is
  reachable through antseal, tell us, because the mitigation may be ours.

## Ordinary bugs

Everything that is not a security finding goes to the public issue tracker
through the bug-report form. The project's own work is tracked in `TODO.md`
rather than in issues, so an issue is a report to the maintainer rather than a
queue position.

## Related documents

- [Threat model](docs/threat-model.md) — what a seal defends against, what it
  does not, and the reasoning behind every scope line above.
- [Security assumptions](docs/security-assumptions.md) — the frozen
  cryptographic assumptions the permanent formats rest on.
- [Contributing](CONTRIBUTING.md) — the checks a change has to pass.
