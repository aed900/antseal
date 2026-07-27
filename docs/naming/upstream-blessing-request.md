# P1 — Upstream blessing request (ready to send)

**Instructions (not part of the issue text):**

- **The maintainer (user) files this manually** at
  <https://github.com/WithAutonomi/ant-client/issues> — Discussions are
  disabled on that repo (verified 2026-07-27), so an issue is the
  on-platform channel. Do not file from automation.
- Before filing, replace **`<REPLY-BY DATE>`** with the planned M0 start
  date (suggested: filing date + 3–4 weeks, aligned with
  [D1's deadline policy](../decisions/D1-product-name.md) — silence past
  that date triggers the non-ant fallback).
- **Deliberately omitted from the public text:** the fallback candidate
  name and any other name deliberations (D1 sensitivity note — availability
  decays; keep candidates private until reservations execute).
- **After upstream replies:** archive the reply (link + full copy) in
  `docs/naming/` (e.g. `upstream-blessing-reply.md`) per P1 acceptance, and
  update D1 to RESOLVED either way.

---

## Title

```
Naming request: is an independent tool named "antseal" (ant- prefix) OK with you?
```

## Body

```markdown
Hi — I'm building an independent, open-source tool on top of Autonomi and
would like your written OK (or objection) for its name before I reserve
anything.

**What it is (one paragraph):** `antseal` is a non-custodial Rust CLI plus
a static WASM verifier page for proof-of-existence with selective
disclosure: it seals files into Autonomi's pay-once permanent encrypted
storage (via the `ant-core` crate), timestamps them against independent
anchors (OpenTimestamps + RFC 3161 TSAs), and later lets the author prove
existence, integrity, and priority of chosen parts without revealing the
rest. All user data is client-side encrypted before upload; the network
only ever stores opaque ciphertext.

**Why I'm asking:** your binaries are `ant`/`antnode`, and an `ant-`
prefixed name could read as official Autonomi tooling. It is **not**: this
is a third-party project, not affiliated with or endorsed by Autonomi, and
its README, docs, and crate descriptions will state that explicitly and
prominently. I'm happy to use any disclaimer wording you prefer.

**The concrete names I'd like your blessing for:**

- crates.io: `antseal`, `antseal-core`, `antseal-anchor`, `antseal-net`,
  `antseal-cli`
- CLI binary: `antseal`
- Domain (static verifier page): `antseal.org`
- GitHub repo: `antseal`

**The ask:** a short reply on this issue saying you're fine with it (or
that you'd rather I didn't use the prefix) is all I need — I'll link it
from the project as the naming provenance record.

**If I don't hear back by <REPLY-BY DATE>:** no problem and no action
needed — I'll conservatively treat the prefix as not blessed and ship under
a non-ant name instead.

Thanks for Autonomi and for `ant-core` — happy to answer anything about the
project here.
```
