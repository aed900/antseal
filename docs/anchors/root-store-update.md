# TSA root-store versioning and update process

> **Owning task: A26** (`tasks/A.md`), milestone **M2**, then `continuous`.
> **Source of truth for scope and admission: [D57](../decisions/D57-tsa-root-store-scope.md)**.
> The store itself is `crates/antseal-core/src/anchor/roots/`; its per-root
> evidence is `crates/antseal-core/src/anchor/roots/PROVENANCE.md`.

Every pinned root is **an organisation that can sign a false, earlier time.**
antseal's whole claim is priority — "existed no later than T" — so
earlier-signing is precisely the capability that matters, and the size of this
store is the size of that exposure. Nothing in this document is
administrative: it exists to make the set grow only deliberately, and to make
each addition auditable years later by someone who was not here.

## 1. What is versioned, and what is not

- `TSA_ROOT_STORE_VERSION: u32` — **monotonic, bumped on any change to the
  root set.** Appears in verdict data (`ChainVerdict::root_store_version`) so
  a rendered verdict says which trust store produced it.
- `TSA_ROOT_STORE_BUILD_DATE: &str` — ISO-8601, the date the contents last
  changed.
- Version **0** is reserved for injected test stores
  (`INJECTED_STORE_VERSION`). It is not a released version and never will be;
  the reservation is what stops a fixture store being mistaken for a shipped
  one in verdict data.

**The root store is not part of the frozen v1 wire format.** MVP-SPEC.md line
123's format-stability guarantee binds *formats*; the store is explicitly
versioned and updatable (spec line 109). This is why an omitted root is a
bounded, repairable problem rather than a permanent one — and it is also why
"we can always add it later" is never a reason to add one now.

## 2. Roots are append-only

Adding a root is an ordinary reviewed change. **Removing one is not.**

A bundle sealed while a root was pinned must keep verifying afterwards, or
aging evidence rots — the failure MVP-SPEC.md lines 109 and 130 forbid by
name. So:

- **Append** — a reviewed change: one `PinnedRoot` block, one version bump,
  one `PROVENANCE.md` section, §4's checklist.
- **Rotate** — an append. The superseded root **stays**. A CA that changes
  hierarchy gets both roots pinned and a compatibility note naming both; the
  old one is not swapped out, because bundles anchored under it exist.
- **Remove** — a deliberate exception requiring an explicit compatibility
  note that states, in the release notes, which previously-verifiable bundles
  will stop reaching `proven` and why the removal is worth that. A key
  compromise is the case this exists for. It is not a cleanup operation.

Expiry is **never** a reason to remove. A9 does not check the trust anchor's
own validity period (D53 §5a): a root that expires while bundles anchored
under it are still being verified must keep anchoring them, and
`an_expired_pinned_root_still_yields_proven` is the test that holds that open.
What expiry requires is that the *successor* be appended in time (§5).

## 3. Admission: no root is compiled in ahead of its provenance

This is D57 §6's rule and it is the one that actually gates the store.

Per root, obtain **C1 (vendor repository), plus at least one of C2 (public
root-programme data) / C3 (Wayback snapshot ≥ 12 months old), plus C4
(operational binding via a live token) always.** C4 is same-operator
corroboration and is **never sufficient alone**.

Record, per root and per channel: subject DN, issuer DN, serial, SHA-256 of
the DER certificate, SHA-256 of the DER `SubjectPublicKeyInfo`, notBefore,
notAfter, key algorithm and size, and for **every** channel its URL, its
retrieval UTC and the fingerprint it yielded. A root enters only when every
recorded fingerprint is identical, **recomputed locally from the retrieved
bytes** — never transcribed from a vendor page.

Two things this procedure has already been wrong about, recorded so they are
not rediscovered:

- **"It must be in a browser root program" is unexecutable.** Mozilla's
  programme covers TLS and S/MIME, so a timestamping-only root will never be
  in it. Only 2 of D57's 5 candidates are in Mozilla NSS at all.
- **The obvious second channel often does not exist.** `crt.sectigo.com`
  serves its root over **plain HTTP only** (TLS handshake failure);
  `www.swisssign.com` returns **403** to every request from a non-browser
  client; the DFN root's C1 URL has **no Wayback capture at any date**. A
  channel that cannot be executed is recorded as not executed, and the root
  waits.

A root whose channels are incomplete is **quarantined**: listed in
`PROVENANCE.md` under `- QUARANTINED: <label>` and absent from the compiled
store. `anchor::roots::tests::the_store_matches_the_provenance_record` reads
those lines and fails in **both** directions — a root compiled in with no
section, and a quarantined root compiled in anyway.

**The cost of a quarantine is real and should be stated in the release
notes.** MVP-SPEC.md line 108 documents alternates that U26 lets a user
select, and A20's gate is "proceed iff ≥1 TSA token passed full core
verification". So a user who configures only quarantined TSAs gets a **hard
pre-payment seal abort**, not a weaker bundle. That is loud and recoverable —
which is the argument for quarantining rather than admitting on thin
evidence, not an argument that it costs nothing.

## 4. The append checklist

1. Execute §3's channels. Recompute every fingerprint locally.
2. Add the DER to `crates/antseal-core/src/anchor/roots/<label>.der`.
   **DER, not PEM** — `include_bytes!` is byte-exact and needs no base64
   decoder in a crate that must stay WASM-safe.
3. Add the `PinnedRoot` block to `ROOTS_V1`, with both fingerprints as
   lowercase hex literals.
4. Bump `TSA_ROOT_STORE_VERSION` and set `TSA_ROOT_STORE_BUILD_DATE`.
5. Add the `### <label>` section to `PROVENANCE.md`; if the root was
   quarantined, remove its `- QUARANTINED:` line in the same commit.
6. Update the count and label list in
   `pinned_store_is_exactly_four_roots_at_version_1` (rename it) and its byte
   total.
7. Run `cargo test -p antseal-core` and the wasm32 build. The store's own
   suite re-derives both fingerprints from the bytes, checks self-signed
   shape, `CA:TRUE`, `keyCertSign`, label uniqueness, and key uniqueness.
8. Confirm no existing anchor verdict changed
   (`appending_a_root_leaves_every_existing_verdict_unchanged`). If one did,
   root-set membership has leaked into a verdict beyond the version field and
   that is a defect in A9, not in the append.
9. State in the release notes: the label, the operator it admits, the
   channels executed, and the new store version.

`.gitattributes` already carries `crates/antseal-core/src/anchor/roots/*.der -text`.
Do not remove it: the Windows CI image sets `core.autocrlf=true` machine-wide
and a CRLF-mangled DER is an unparseable root.
`the_gitattributes_binary_rule_covers_this_directory` fails everywhere if the
rule goes, because the `cross-os` lane can only observe the damage on a
Windows runner.

## 5. Expiry horizon, checked at release

**No pinned root may be within 365 days of its `notAfter` at release time.**

`TsaRootStore::roots_within_expiry_horizon(now_unix, horizon_secs)` implements
it, and it takes `now` as a **parameter** — `antseal-core` reads no clock, so
the function is deterministic and identical on wasm32.

That parameterisation has a consequence worth stating rather than glossing:
**a unit test with a frozen `now` proves the function, not the calendar.** It
cannot detect a real approaching expiry and must not be credited with doing
so. Driving it with the real clock is **A44**'s scheduled, non-gating lane,
and this release-checklist row is the gating half.

Earliest expiry in store v1 is `digicert-trusted-root-g4`, **2038-01-15**.

## 6. Release-checklist rows

Q31 owns the release checklist and it does not exist yet, so these rows are
written here in quotable form for it to adopt. Until it does, the reference is
one-directional and this section is the checklist.

> - [ ] **Root-store expiry horizon.** `roots_within_expiry_horizon(now, 365 d)`
>       is empty for the release build. If not, append the successor root
>       (`docs/anchors/root-store-update.md` §4) — never swap, never drop.
> - [ ] **Root-store provenance.** Every root in `ROOTS_V1` has a
>       `PROVENANCE.md` section whose recorded fingerprints match the
>       compiled bytes, and every `- QUARANTINED:` root is absent from the
>       store. (Mechanised by `the_store_matches_the_provenance_record`;
>       the human half is confirming the *channels* were really executed, not
>       merely written down.)
> - [ ] **Store version in the release notes.** `TSA_ROOT_STORE_VERSION`,
>       `TSA_ROOT_STORE_BUILD_DATE`, the root count, and — if either changed
>       since the last release — which root was appended and which
>       organisation that admits.
> - [ ] **Quarantine disclosure.** Any documented TSA alternate whose root is
>       quarantined is named in the release notes together with the
>       consequence: configuring it produces a pre-payment seal abort, not a
>       weaker bundle.

## 7. Revisit triggers

- Any pinned root within 365 days of `notAfter` → a reviewed append of its
  successor (A44).
- A default or documented-alternate TSA changing hierarchy → D57's closure
  rule fires: the new root enters via §3/§4, the old one stays, and the
  compatibility note names both.
- A quarantined root's missing channel becoming executable → append it, and
  say so in the release notes.
- A new machine-readable root-programme feed appearing → add it to the C2
  menu and record the probe (this is how CCADB's Microsoft feed entered on
  2026-08-03, under D57's own revisit trigger).
- A key compromise at a pinned CA → the only case in which §2's removal
  exception is on the table.
