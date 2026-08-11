# D127 — Q236's disposition of V7.1: rule the exception at the M2 review vs hold the gate for the submit pair

- **Status: RESOLVED — arm (a), rule the exception now, and the lean survives
  ON MEASUREMENT with one honest sharpening: the residue is *bigger* than the
  lean's framing, not smaller. "Same calendar hosts, different route" is
  false for the product's default set — the submit targets are the four
  `DEFAULT_OTS_CALENDARS` *pool aggregator* hosts, which antseal's client has
  never contacted in any mode, while every real-endpoint proof banked so far
  spoke to the *calendar* hosts the attestations name (zero host overlap in
  the wave-16 cycle). The ruling holds anyway, because the residue is
  bounded, enumerable (§2's three items), and closable by exactly one
  consented campaign — and because all three overturn directions die on a
  mechanism or a log: the forbidden "slide past by the bump" is mechanically
  impossible (§1e — a gated `gap` without a register entry is red), the
  entry is bump-atomic by construction (registered early it reds on the
  unused-exemption arm, so entry and bump can only land in ONE change), and
  D118 §5's "stays `{}` absent a recorded ruling" is satisfied, not
  weakened, by an entry whose price is this document: a recorded ruling, a
  named single closure trigger owed to a named actor, and machine-enforced
  removal. M2 ships with its one hole recorded and loud; the whole review is
  not parked on an absent third party while the four covered M2 rows sit
  outside the flagless status gate — D118's exposure class, recreated on the
  milestone that just paid for D118.**
- **Date: 2026-08-11** (wave 17 planning lane, briefed to overturn the
  arm-(a) lean; directions (i)–(iii) taken to measurement below.)
- **Owning task: Q236** (the M2 gate row executes every edit in §6 as part
  of its own named acts; the closure campaign is a maintainer action).
  Builds on D117 (correction discipline), D118 §5/§6 (the constant, the
  refusal this record's moment reverses), D122 (the bump belongs to the gate
  row), Q208 (Q236 exists), Q99/A25 (the script and the consented day-2
  run). **Boundary: D126 owns A25's own rows** — §7 states how this record
  stands under either D126 outcome.

---

## 1. What was measured

**(a) The two route shapes, from the code.** Submit is
`POST <calendar>/digest` — `OTS_SUBMIT_PATH = "digest"`
(`crates/antseal-anchor/src/ots/calendars.rs`), body = the 32 raw digest
bytes, `Content-Type` = `OTS_SUBMIT_CONTENT_TYPE`, `Accept` =
`OTS_ACCEPT_HEADER`, `TlsPolicy::Optional` (the URL comes out of config —
the module documents the deliberate asymmetry with A42's https-required
upgrade URI, which comes out of an attacker-writable artifact), and
`Idempotency::AtMostOnceAfterSend` — the module's own comment calls it "the
one request in this module that may create a server-side effect twice"
(`crates/antseal-anchor/src/ots/submit.rs`, `submit_and_validate`). Upgrade
is `GET <base>/timestamp/<lowercase-hex commitment>` (D54 §6.1's path,
`crates/antseal-anchor/src/ots/upgrade.rs`, `poll_upgrade`), empty body,
`TlsPolicy::RequiredExceptLoopback`, an idempotent read. Different method,
different route, different body semantics, different TLS policy, different
retry class.

**(b) The host asymmetry the lean's framing missed.** The wave-16 cycle's
day-1 submits (2026-08-11T12:46Z,
`testdata/anchors/A25-wave16-cycle/CAPTURE.log`) went to
`a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`,
`a.pool.eternitywall.com`, `ots.btc.catallaxy.com` — the four
`DEFAULT_OTS_CALENDARS` D54 pinned, upstream's POOL endpoints. The day-2
upgrades (17:55Z, `.../upgraded/UPGRADE-CAPTURE.log`) went to
`alice.btc.calendar.opentimestamps.org`,
`bob.btc.calendar.opentimestamps.org`, `btc.calendar.catallaxy.com`,
`finney.calendar.eternitywall.com` — the calendar hosts the pending
attestations name. **Zero host overlap.** So the four endpoints a product
submit would contact have never been contacted by the product's client in
any mode — the residue is not "a second route on proven hosts", it is an
unvisited host set plus an unexercised client path.

**(c) What is banked, precisely.** The loopback selftest proves the submit
mode's request-building and IO path: the mock-observed submit body is the
exact 32 digest bytes with the OTS `Accept` header, 12/12 arms, four
refusal arms proven by message (tasks/A.md A25, 2026-08-11). The client's
*real* branch is proven on three of four modes: A14 upgrade GETs against
real calendar hosts (6 of 8 upgraded; 2 honest `not-yet-confirmed`), A10
TSA POST-with-DER-body against `freetsa.org` (https) and
`timestamp.digicert.com` (plain http) — real POSTs with bodies through the
same `HttpClient` — both `Proven` against the pinned store, and A16/A17
must-agree over real endpoint pairs. The pool hosts themselves accepted
eight hand-issued submits day-1 (all `200`), so the route+method+body shape
is server-accepted — just never as built by antseal. Provenance of "hand":
2026-08-02's bootstrap was curl (its `CAPTURE.log` carries curl's own
resolve error, per D118 §6); 2026-08-11 day-1's log header names no client
and the day-2 consent verbatim reads "Scope excludes fresh calendar
submissions" (tasks/A.md: "day-1 was manual").

**(d) The M2 row set and the queue.** M2 owns five matrix rows: V2.3, V3.5,
V7.2, V7.3 `covered`, V7.1 `gap` (the 34 = 16+6+5+4+3 census, Q208).
Q236's dep line records every other Gate input measured ✅ at registration
(A20/A21/A22/A23, Q17/Q18, U22, U23–U25). The checker's cumulative rule
(`gated_milestones`) gates `M0..=CURRENT_MILESTONE` only, so with the
constant at `M1` all five M2 rows are ungated in the flagless run — and the
M3 tranche (R16–R27, U27–U30) is unconstrained under *either* arm; only
Q237 ("after Q236 + …") stacks behind Q236. Queue order in TODO.md's
wave-17 block is priority, not dependency.

**(e) The checker's four arms, and what they make impossible**
(`scripts/check-traceability.py`, `check_matrix`). (1) A gated row not
`covered` with no `ACCEPTED_NON_COVERED` entry is **red** — so the
"slide past by the bump" Q236's Accept forbids cannot happen silently: bump
first and the flagless run fails on V7.1 by name. (2) An entry whose row
now reads `covered` is **red** ("Drop the entry — a stale exemption is how
a gate decays into a permanent mute"). (3) An entry whose status disagrees
with the row is **red** ("re-decide it"). (4) An entry for a row **not at a
gated milestone** is **red** ("no such row exists at a gated milestone …
Remove it") — measured consequence: registering the V7.1 entry *before*
the M1 → M2 bump is itself red, because V7.1's milestone is not gated under
`M1`. **The entry and the bump are therefore bump-atomic by construction —
they can only land in one change — and closure is likewise one change**
(row → `covered` plus entry removal; either half alone is red). The
sequencing this ruling prescribes is already machine-enforced in both
directions; nothing new is built.

**(f) Arm (b)'s measured cost.** Holding the gate does *not* block the M3
tranche (§1d). What it does: parks the entire M2 review — every clause of
it measured done but this one residue — on a two-consent maintainer-present
campaign of unbounded latency (the maintainer is absent this session;
calendar cadence is unplannable: 13 h 47 m and ~5 h 09 m measured, "still no
interval to plan on"); and leaves the four covered M2 rows outside the
flagless status gate for that whole interval, where a test rename or
fixture deletion is invisible to the ordinary run — exactly the
correct-and-unarmed exposure D118 spent eight stale days documenting.

---

## 2. What a real submit pair proves above everything banked

Three items, and only these three — the bound is the point:

1. **Real pool-host acceptance of the client-built request.** Everything
   the loopback mock does not judge: the exact `Content-Type` value,
   request framing, HTTP version and incidental headers, TLS negotiation
   with the four pool hosts under the `TlsPolicy::Optional` path, and the
   `AtMostOnceAfterSend` classification against real network behavior. Small
   — day-1 proved the hosts accept the shape from curl — but nonzero: real
   servers reject on incidentals mocks accept.
2. **Fresh-response validation in situ.** `submit_and_validate` →
   `assemble` → `parse_ots` over never-before-seen branch bytes per
   calendar, and the `OTS_MIN_DISTINCT_CALENDARS` floor over live outcomes.
   Loopback fed committed capture bytes — real bytes, but replay.
3. **The composed product cycle — the spec bullet's own sentence.** The
   client's *own* merged pending artifact round-trips: `submit_to_calendars`
   stores it, `pending_refs` → `UpgradeTarget` → `poll_upgrade` upgrades it
   against a real calendar serving *that* commitment, no curl anywhere in
   the chain. Every cycle to date is a two-actor composition (hand
   submitted, antseal upgraded); "pending → upgraded next day" (MVP-SPEC.md
   line 173) has never been performed by the product end to end. This item
   is why fresh client submits *alone* do not close the row (§5).

---

## 3. The three overturn directions, taken to measurement

**(i) Does the Gate clause's own text demand the submit leg, and does
D117/D118 forbid arm (a) as scope-narrowing?** The clause — "real-endpoint
smoke incl. two-day OTS pending→upgraded cycle complete (A25)" — read
under the project's own recorded interpretation (the spec heading is
"Anchor smoke tests"; D118 §6: "curl performed it, not antseal"; the V7.1
cell's whole history) has the product's client as its subject, so full
satisfaction *by evidence* requires both legs through the client, and the
submit leg is missing. **Arm (a) does not narrow that reading — it refuses
to.** Q236 records the clause as evidence-plus-ruled-exception, which is
the disjunction Q236's own Accept supplies ("closed by evidence **or
ruled** on the record"). D117's insufficient-sentence precedent (the V7.1
cell's replaced sentence conflated proving the script's real branch with
proving both client paths) constrains the *wording*: state precisely what
each piece of evidence proves. §2 is that statement, and §5 forbids the row
to flip on anything less than the composed pair. Direction (i) constrains
the record's text and dies as an overturn.

**(ii) Is a ruled exception the forbidden slide in different clothes?** The
slide cannot happen silently (§1e arm 1), so the phrase's live danger is
the register used as a lint-silencer — an entry absent a ruling, which is
what D118 §5 forbids. Four structural differences separate arm (a) from
that: the row keeps reading `gap`, so the matrix keeps telling the truth;
the exemption is loud (reason inline in the checker source, interpolated
into every mismatch arm's failure message, cross-referenced from three
homes); removal is machine-enforced (§1e arms 2–4 — the entry can outlive
neither the hole nor the row); and it creates a standing obligation with a
named single trigger owed to a named actor at TODO.md's maintainer-actions
list. A slide leaves no trace and no obligation; arm (a) leaves both.
Direction (ii) dies on the mechanism.

**(iii) Does the register's first entry weaken "stays `{}` absent a
recorded ruling"?** The discipline's operative clause is *absent a recorded
ruling* — not "stays empty forever". D118 §5's refusal was explicitly
time-scoped, in the checker's own comment: "M2 has not shipped, so there is
no known hole to accept yet, and an entry here would silence `V7.1` at the
M2 review — the one moment it exists to speak." That moment is Q236's
review; the row speaks; this document is the answer. The register's
engineering — the reason string, the three staleness arms — exists *for*
the ruled entry; an empty register that stayed empty when a genuine hole
reached its review would resolve holes either by parking ships on absent
third parties or by quietly mis-marking rows `covered`, the exact
corruption the vocabulary exists to prevent. Structurally: the enforced
no-real-network-in-CI policy (V7.3) plus the consent regime *guarantee*
that real-endpoint evidence arrives only through maintainer-present
campaigns, so a gate that can only pass at zero entries collides with
standing policy every time a residue needs one — the register is the
designed junction point. What *would* weaken D118 §5 is an entry without a
decision record, or for work the project can perform itself. **This
precedent does not extend there**: an entry is priced at a recorded ruling
+ a named closure trigger + machine-enforced removal + a residue closable
only by an act standing policy forbids the session to perform. Direction
(iii) inverts — the first entry under full discipline demonstrates the
rule.

---

## 4. The ruling

1. **Q236 disposes of V7.1 by ruled exception — this record.** In the same
   change as the `CURRENT_MILESTONE` `M1` → `M2` bump (one change by
   construction, §1e), `ACCEPTED_NON_COVERED` gains its first entry, §6 E1
   verbatim. The row keeps reading `gap`; M2 ships with the hole recorded
   and loud.
2. **The Gate clause is recorded as evidence-plus-ruled-exception**, not
   declared satisfied by evidence: the cycle is complete with the upgrade
   half through the product (A25 day-2) and the submit half ruled here.
   No sentence anywhere may summarize V7.1 as covered, satisfied, or
   equivalent-to-proven (D117 discipline).
3. **The closure trigger is single and named** (§5): the first consented
   script-driven submit→upgrade pair. On it, the V7.1 cell flips `covered`
   and the register entry is removed in one change — enforced, not
   requested (§1e arms 2–3).
4. **Arm (b) is refused on §1f's measured cost**, stated honestly: it does
   not block the M3 tranche; it parks a review whose every other input is
   measured done on an absent third party, and leaves four covered M2 rows
   unguarded by the flagless run for the duration.
5. **Zero frozen bytes.** No format, vector, or verdict moves; the edits
   are one Python dict + comments, matrix prose, and register prose.

---

## 5. The pair, defined exactly

One campaign through `scripts/anchor-smoke`, two halves, **each under its
own fresh §1 consent naming action and destination** (the day-2 consent's
"Scope excludes fresh calendar submissions" is the precedent for why the
submit half must be named expressly):

- **Day 1 — `anchor-smoke submit`**: A13's `submit_to_calendars` of the
  committed golden-vector digests against the four `DEFAULT_OTS_CALENDARS`,
  pendings stored and logged per runbook §4 through the product's client.
- **Day N — `anchor-smoke upgrade` over those pendings**: A14's
  `pending_refs` → `UpgradeTarget` → `poll_upgrade` of the client-submitted
  commitments.

**Closure predicate**: the submits are accepted through the client (2xx
pending branches stored), **and at least one client-submitted commitment
reaches `outcome=upgraded` through the client**. Not required: all four
calendars upgraded — the consented day-2 run's own standard was 6 of 8 with
two honest `not-yet-confirmed`, and `not-yet-confirmed` is re-pollable
under fresh consent, never failure. Two miscounts this predicate forbids:
fresh submits alone are **not** the pair (§2 item 3 would stay unproven —
the composition is the point), and an all-`not-yet-confirmed` upgrade day
is **not** a dead campaign (re-poll later; the trigger is met when the
first composed upgrade lands). If D126 leaves any A25 re-run obligation
standing, this same campaign may discharge both; the records do not
conflict (§7).

---

## 6. What Q236's implementer does (verbatim)

**E1 — the register entry** (`scripts/check-traceability.py`, in the same
change as `CURRENT_MILESTONE = "M2"`):

```python
ACCEPTED_NON_COVERED: dict[str, tuple[str, str]] = {
    # The register's first entry, ruled by D127 (2026-08-11) at the M2
    # review. Bump-atomic by construction: before the M1 -> M2 bump this
    # entry reds on the unused-exemption arm below, and the bump without it
    # reds on the status arm - one change, both directions (D127 §1e).
    "V7.1": (
        "gap",
        "M2 ships with the submit half owed (D127, 2026-08-11): antseal's "
        "A13 submit path has never spoken to a real calendar - every "
        "committed pending was hand-submitted, and the 2026-08-11 consented "
        "run's scope excluded fresh submissions. Bounded residue: the "
        "loopback selftest pins the request shape and the upgrade/TSA/"
        "must-agree legs proved the client's real branch, but the four "
        "DEFAULT_OTS_CALENDARS pool hosts have never been contacted by the "
        "product in any mode, and the composed cycle (client-submitted "
        "pending -> client-upgraded) has never run. Closes on the first "
        "consented script-driven submit->upgrade pair (maintainer action, "
        "fresh consent per half): the V7.1 cell flips covered and this "
        "entry is removed in the same change.",
    ),
}
```

**E2 — the register's comment block** (replaces the two paragraphs above
the dict; the first paragraph's "Empty, and it should stay that way" and
the second's "Still empty" go false the moment E1 lands):

```python
# Rows allowed to sit at a non-`covered` status inside a gated milestone, as
# `id -> (status, reason)`. An entry here is a milestone shipping with a
# known hole - a decision worth writing down rather than a lint to be
# silenced - so every entry requires a recorded ruling (D118 §5) and carries
# its closure trigger. Stale entries are themselves a failure - see
# `check_matrix` - so this cannot rot into a permanent mute.
#
# It stayed empty through Q165 / D118, deliberately: eleven rows read
# `deferred` at or before M2 and this register was the obvious place to put
# the survivor (`V7.1`, whose real calendar cycle was run by hand with curl
# rather than by antseal). It was the wrong place THEN: M2 had not shipped,
# so there was no known hole to accept yet, and an entry would have silenced
# `V7.1` at the M2 review - the one moment it exists to speak. That moment
# arrived at Q236's review, the row spoke, and D127 (2026-08-11) answered it
# on the record. The entry below is the register's first, at the price D118
# §5 set: a decision document, a named closure trigger, and machine-enforced
# removal. That price is the precedent - an entry for work the project can
# perform itself is not covered by it (D127 §3 iii).
```

**E3 — the V7.1 cell**, dated appendix after "…
`docs/testing/anchor-ci-policy.md`." (one cell, no newlines or pipes):

> **2026-08-11, the M2 review (Q236 / D127): ruled on the record — the
> second arm of exactly the disjunction this cell's last sentence named.**
> The review neither slid past the residue (a gated `gap` without a
> register entry is red — the checker forbids the slide mechanically) nor
> parked on an absent third party: `ACCEPTED_NON_COVERED` gains its first
> entry (reason verbatim from D127 §6 E1) in the same change as the
> M1 → M2 bump, so M2 ships with the hole recorded and loud rather than
> mis-marked `covered`. What a real submit pair still proves above
> everything banked (D127 §2): real pool-host acceptance of the
> client-built `POST /digest` — day-1's eight pendings went to the four
> `DEFAULT_OTS_CALENDARS` pool hosts (`a.pool.opentimestamps.org`,
> `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`,
> `ots.btc.catallaxy.com`) by hand, while the day-2 upgrades spoke to the
> *calendar* hosts the attestations name, so the product's client has
> never contacted the pool set in any mode — fresh-response validation in
> situ, and the composed product cycle (client-submitted pending →
> client-upgraded), which has never run. Closure is unchanged and now
> machine-enforced: on the first consented script-driven submit→upgrade
> pair (D127 §5's predicate: submits accepted through the client AND ≥1
> client-submitted commitment upgraded through the client), this row flips
> `covered` and the register entry is removed **in one change** — the
> checker reds either half alone — with the campaign owed at TODO.md's
> maintainer-actions list.

**E4 — the M2 section preamble** (verification-matrix.md; within Q236's
existing Q230-clause remit — the dated prose copies of the constant move in
the bump's act). Replace the first paragraph ("Checked at the M2 review,
**which has not happened**. …") with:

> Checked at the M2 review, which ran 2026-08-11 (Q236).
> `CURRENT_MILESTONE` is `M2`, so every row here is gated by the ordinary
> flagless run, cumulatively with M0's and M1's. Four rows read `covered`;
> `V7.1` reads `gap` under the register's first `ACCEPTED_NON_COVERED`
> entry (D127) — M2 shipped with that one hole recorded, closure owed as a
> consented submit→upgrade pair (maintainer-actions), the entry's removal
> enforced by the checker's staleness arms.

**E5 — Q236's row, evidence fragment for this clause** (appended when Q236
executes, alongside its per-clause evidence):

> V7.1 dispositioned per **D127** (2026-08-11): ruled exception —
> `ACCEPTED_NON_COVERED` gains its first entry in the same change as the
> M1 → M2 bump (the row stays `gap`; reason verbatim from D127 §6 E1);
> closure = the first consented script-driven submit→upgrade pair against
> the four default pool calendars (D127 §5 predicate), owed at
> maintainer-actions; flagless run green after the move with the exemption
> loud in the checker source.

**E6 — TODO.md maintainer-actions**, new item (6) (registrar; may land
before Q236 runs — a TODO edit has no checker coupling):

> (6) **V7.1 submit pair** (D127) — the one M2 hole shipped by ruling: one
> `scripts/anchor-smoke` campaign, **fresh §1 consent per half, each
> naming action and destination** (day 1: `anchor-smoke submit` — A13
> submits of the committed golden-vector digests to the four
> `DEFAULT_OTS_CALENDARS` pool endpoints; day N: `anchor-smoke upgrade` of
> those pendings — A14 polls). Closes when the submits are accepted through
> the client AND ≥1 client-submitted commitment reaches `upgraded` through
> the client (D127 §5); then the V7.1 cell flips `covered` and the
> checker's `ACCEPTED_NON_COVERED` entry is removed **in the same change**.
> No consent exists today and none carries forward.

**E7 — registrar bookkeeping** (rides the registrar's commit; expect the
transient mid-registration `decision-index` red until the index row lands,
per house pattern): TODO.md D-register row and `docs/decisions/README.md`
index row for D127 — texts supplied in the lane report.

---

## 7. The D126 boundary

D127 rules the *matrix row's* disposition — the `--matrix --milestone M2`
half of Q236's acts. It does not adjudicate A25's rows. If D126 closes A25
on its rows, Q236's `after Q208,A25` dep is satisfied and Q236 executes
with this record in hand; the Gate clause's A25 citation resolves through
D126's record. If D126 holds A25 open, Q236 stays parked on its dep and
this record waits with it, unchanged — it governs what Q236 does when it
runs, not when it runs. Either way the two records cannot conflict: A25's
rows answer task acceptance; V7.1 answers verification-matrix coverage of
spec line 173, a standard D118 §6 established as distinct and D117 forbids
collapsing. If any A25 re-run obligation survives D126, §5's campaign may
discharge both in one consented run.

---

## 8. Residual risk (of the decision taken)

- **The pair may never run.** The maintainer's availability is not owed;
  M2 then ships permanently with the hole. Accepted — that is what "a
  milestone shipping with a known hole" means, and it is loud in four homes
  (checker source, V7.1 cell, maintainer-actions, this record). The refused
  arm bears the same availability risk with the whole review attached.
- **Precedent abuse.** A future wave cites D127 to register an entry for
  convenience. §3 (iii) prices the precedent and states its non-extension:
  no decision record, no named trigger, no third-party-only residue — no
  entry.
- **An all-`not-yet-confirmed` upgrade day.** Fresh-cycle calendar cadence
  is unplannable (13 h 47 m, ~5 h 09 m measured); the campaign's day-N may
  find nothing aggregated yet. §5's predicate keeps that honest in both
  directions: not closure, not failure — re-poll under fresh consent.
- **Reason-string drift.** The checker's reason text could drift from this
  record under later amendment. The entry cites D127 by name; D117's
  dated-correction discipline governs both ends.
- **Consent-scope repetition.** The day-2 precedent shows submit scope is
  excluded unless named; E6's text names it expressly so the campaign's
  consent request cannot inherit the narrower scope by habit.
