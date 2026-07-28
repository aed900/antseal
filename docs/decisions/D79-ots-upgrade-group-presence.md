# D79 — Is the OTS upgrade group tied to `status == attested`, or free-standing?

- **Status: RESOLVED — FREE-STANDING.** The group (`block_height`,
  `block_header`, `fetch_date`; registry §7.8 keys 2–4) is structural:
  all three present or all three absent. The **parse rule never consults
  `status`.**
- **Date: 2026-07-28** (surfaced and ratified the same day, by the D8 bundle
  pass — registry §13 item 9; consumed immediately by F8)
- **Record written: 2026-07-28, M0 wave 7.** Ratified in wave 5 and enforced
  in code ever since, but it had no record file: it existed only as an entry
  in `TODO.md`'s decision register. It is format-permanent and freezes at
  Q14, so it is promoted here, with its code citations verified at `6b6ee17`.

## Context

An `.ots` anchor artifact may carry a Bitcoin attestation. When it does, the
bundle records the block height, the 80-byte block header and the date the
upgrade was captured. The artifact also carries a sealer-written `status`.

The all-or-nothing rule over the three keys was never in question. The
**coupling** was: may the schema require the group to be present exactly when
`status == attested`?

Tying them is superficially attractive — it makes the artifact
self-consistent and gives a crisp early rejection.

## Decision

**Free-standing.** Presence of the group is decided without ever reading
`status`. `status = pending` carrying a header is admitted by the parser and
judged later, by A/R.

## Rationale

1. **`status` is sealer-written, and the design says a verifier must never
   trust it** (registry §6.1). Conditioning a *parse* rule on it would be the
   only place in v1 where a parse outcome depends on a field the design
   explicitly distrusts — which means **a sealer could choose which shapes
   decode**. That is a capability handed to exactly the party the threat
   model treats as an adversary (MVP-SPEC.md's sealer-as-adversary row).
2. **Derived, not declared** — the same principle D28 applies to the
   full-reveal predicate and D8 applies to reveal shape generally. A
   structure is what its *material* says it is, never what a field claims it
   is. The verifier derives the real status from the artifact at M2; the
   parser's job is to admit the artifact so that derivation can happen.
3. **Parse stays ignorant of semantics.** What an upgraded attestation
   proves, whether the header is on the real chain, and how the headline
   verdict is chosen are A-domain judgements with their own evidence
   (A11/A12/A14/A18). Folding a fragment of that judgement into the codec
   would split one rule across two milestones and two error families.

The accepted cost is stated plainly: artifacts like `status = pending` **with**
a header parse successfully. They are not evidence of anything — they are
input to a verdict that has not been computed yet.

## Scope

**The parse rule only.** What the status values mean, which are legal as
*recorded*, and how a verifier derives the real one stay A-domain at M2.
D8 subsequently ruled the recorded-value question the same way and for the
same reason: **all seven `anchor_status` values are legal as recorded, on
both kinds, with no subset ever** — a subset would be this same forbidden
construction one level down, filing a sealer's lie under a `bundle-` code.

## Consequences

- Enforced structurally rather than by check: `OtsUpgrade` holds all three
  fields, so `Option<OtsUpgrade>` **has no "two of three" state**
  (`crates/antseal-core/src/bundle/schema.rs:40`, `:400`, `:527`, `:1872`).
  The partial state is unrepresentable, not rejected at runtime.
- The D79 partial state is therefore only reachable by a byte mutation, which
  is what makes it a tamper row rather than a schema test (**F20**).
- `crates/antseal-core/src/bundle/error.rs:630` carries the ratification
  inline so the error's own docs state the rule.

## Freeze status

Freezes at **Q14** as part of the v1 wire registry (§7.8). The reversible
direction is free-standing → conditioned (strict), never the reverse: bundles
built under the free-standing rule would stop verifying under a conditioned
one, which line 123 forbids.
