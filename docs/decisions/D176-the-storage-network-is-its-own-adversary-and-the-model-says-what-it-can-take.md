# D176 — The threat model gains **§2.11 Storage network as adversary**: what whoever answers the client can take — money, persistence, privacy — and what it cannot — any verdict; **§2.3 is corrected** because a single storing node can count a seal's blobs; the section check **anchors on whole heading lines**; and "no upstream peer cache" is a **pinned code fact**, not a sentence

- **Status: RESOLVED. The placement survived; four of the row's own technical claims fell,
  and the check it asked to extend could not meet its own `Accept` as written.**
  - **Placement — a new §2.11, with a dated §2.3 correction — holds**, for reasons other
    than the row's: §2.9's scope is anchors and time, and this adversary attacks nothing
    §2.9 is about (it attacks availability, money and privacy); §2.3's scope is the receipt
    and the wallet; §2.9 is this adversary's **boundary** and is cited, not re-argued.
  - **Four claims in `Q272`'s Problem fall** when checked against the pinned sources:
    (1) **the one-peer abort** is true of upstream — its sweep stops at the first peer serving
    bad bytes and reports "not found" — but **false as a product claim since `S39`**: antseal
    re-asks every close-group peer and counts bad bytes as a failure, so one hostile peer now
    costs latency and can make a true absence read *inconclusive*; a false absence needs at
    least four queried peers answering not-found unanimously. (2) **§2.3's privacy bound fails
    without any eclipse**: every storing node is handed the payment transaction hash, and that
    transaction carries one non-zero transfer per priced blob, so any single node can count the
    seal's blobs — a claim wrong when written, so a **correction**, not an extension.
    (3) **Non-replication needs less than an eclipse**: antseal's sequential PUT stops at the
    fourth acknowledgement, and an acknowledgement is the peer's word. (4) **The peer cache is
    off** — `Client::connect` passes `peer_cache_path: None` — but nothing pins that, and the
    upstream file antseal **does** write, `client_adaptive.json`, was owned by no row (`S42`).
  - **The section check cannot meet `Accept` row 2 as written**: it is `contains(heading)`
    over the whole file, and each of the ten phrases occurs exactly once today only because no
    cross-reference spells a heading's name. §2.11 will be cross-referenced from §2.3, §2.8,
    §2.9 and §3; one reference spelling *"2.11 Storage network as adversary"* would keep a
    deleted section green.
  - **A defect nobody had found, established by reading and not by running**: one hostile
    quoting peer can steer antseal into the proofs-expired path within the 24-hour window — the
    client does not check quote timestamps, antseal judges expiry by the oldest one, and any
    payment-class PUT rejection then aborts finalize as expired; resume re-quotes, re-consents
    and **pays again**. Honest nodes would not have refused on age. Minted as **`S43`** — the
    section states it only as that row's ruling leaves it.
  - **A citation defect**: `Q272` cites MVP-SPEC.md line 186, which is *Malicious verifier
    host*; the storage-network risk is line **180** (*Autonomi network youth*).
- **Date: 2026-09-15**
- Owner rows: **`Q272`**; **`S43`** (minted with this record); **`S42`** (the adaptive
  snapshot, stated in §2.11); **`S40`**/D173 (the peer precedence rule §2.11 cites and the
  pin §2 R5 shares).
- Related: **D117** (dated corrections), **D139** §2 R7 (copy discipline for class-E
  documents), **D170** §2 R12, **D173**, the frozen security-assumptions block (untouched).

## 0. What was measured against

`HEAD` `3473ab2`. Planning lane P4 checked every claim in `Q272`'s Problem against the pinned
`ant-core` 0.5.0, `ant-protocol` 2.3.0, `saorsa-core` 0.26.2 and `ant-node` 0.15.0 sources and
antseal's adapter and pipelines, read `docs/threat-model.md`'s structure and conventions, the
section check, and every document carrying the section count. No cargo run. The orchestrator
re-read the threat model's headings and the section check's tuples before this record was
written.

## 1. What was measured

- **Eclipse — holds.** Quoting is witnessed by close-group peers the client itself found, so an
  eclipse controls the vote; the price is a forced-price rule over a self-attested key count,
  capped at 1 000 000; the one paid transfer goes to the median quote's rewards address;
  `--yes` has no spend ceiling (`--max-cost` is D36's open candidate).
- **A false *already stored* is caught, and the catch is antseal's**: finalize finds no bytes
  and no payment record for that blob — exit 23, that blob unpaid, the work incomplete.
- **Withholding after `S39`**: silence gives *inconclusive* or the D43 cache fallback;
  unanimous lying from at least four queried peers gives a false *"no longer on the network"* /
  *"the network has no data at this address"*; restore never yields wrong bytes (every byte is
  re-hashed to the manifest address); after a disk loss the cache is gone, because exports never
  carry it.
- **Upstream's client routing is permissive against Sybils in upstream's own words**, and a peer
  id is a hash of a key anyone can generate.
- **Nothing about the network survives a run except its peer source**: a fresh identity per
  run, no peer cache, no close-group cache, upstream's `bootstrap_peers.toml` never read — and
  `client_adaptive.json` (three concurrency caps, no peers) read at start and written on drop in
  upstream's shared data directory.
- **Read-time disclosure is uncovered anywhere**: `restore`, a fetching `reveal` and a third
  party's `verify --live` tell whoever answers that this network address is interested in an
  address. **[Corrected in place before this record landed, 2026-09-15, by the lane writing
  the section]**: as first written this said they tell whoever answers *which work* is being
  checked — one answering peer learns interest in one address; learning the work takes
  answering all of a work's requests, which is the eclipse case.
- **The numbering's knock-ons**: the frozen block names no section count and is untouched; the
  section intro (*"The ten headings are enumerated by … `:272-315`"*), the status header and the
  sign-off table must change; dated records that say *ten* stay as captured; `# 3.`'s row for spec
  line 180 gains §2.11 beside §2.9 (a two-section owner cell has precedent); §2.3's note must not
  begin *"Correction to this section's M0 scope line"*, or the document's count of three such
  corrections goes stale.

## 2. RULING

### §2 R1 — Placement

`## 2.11 Storage network as adversary` after §2.10 and before `# 3. Risk coverage map`; §2.1–§2.10
keep their numbers and headings byte for byte.

### §2 R2 — A scope paragraph written with its body

§2.11 opens with a `*Scope.*` paragraph, as every section does, stating in one sentence that scope
and body were written together by `Q272` on its date, so it is not read as an M0 contract.

### §2 R3 — The boundary is cited, never repeated

One statement that offline verdicts are unaffected, citing §2.9's *"Autonomi is never trusted for
time, and evidence never depends on it"* and the frozen block's *not assumed* bullet **by marker**,
never by line.

### §2 R4 — Each property in what the user observes, with pinned-source provenance

(a) **Peer sources ranked by trust** — a user-supplied list is the cheapest eclipse (a hostile
snippet), the vendored list needs a build or release compromise, run-time peers carry no
provenance — with **precedence cited to D173 §2 R6, never restated**, and the tension stated:
precedence is not trust. (b) **Withholding**, per §1, including restore's disk-loss case. (c) **The
upstream one-peer abort** described as upstream behaviour that antseal's absence confirmation
neutralises, with its two residuals. (d) **Payment misdirection**, per §1, and that the exact
allowance bounds loss to the consented total; the proofs-expired path only as `S43` leaves it.
(e) **Non-replication** — four acknowledging targets suffice, undetectable from the same vantage;
`verify --live` from a **different vantage** can see it; a false *already stored* fails at
finalize. (f) **What the network learns** — the §2.3 correction's facts, and what an eclipse adds:
every chunk, the bucketed size vector, the exact manifest length, the uploading address and payer
**joined to the whole work** (a single storing node the client reaches directly already holds the
upload's network address beside the transaction hash — corrected in place by the implementing lane),
and **read-time interest, including a third party's `verify --live`**. (g) **Cross-run
state** — §2 R5. Plus what antseal does not do: no cover traffic, no multi-vantage check, no peer
diversity enforcement, no spend ceiling; UPnP gateway discovery on every connect (D173 §1.4).

### §2 R5 — "No upstream peer cache" is pinned in the same commit

D173 §2 R15's source-text test — code lines only, failing on `from_node_with_peer_cache`,
`save_peer_cache`, `load_bootstrap_peers`, `close_group_cache_dir`, `client_peer_cache` or the
literal `bootstrap_peers.toml` under `crates/*/src`, baseline zero hits — lands with the section.
Its planted cases are built into the test over a temporary directory (a code line must red, a
comment must stay green), so no plant touches a source file another lane may hold. The section
states plainly that every dropped client **does** write `client_adaptive.json` into upstream's data
directory, and cites `S42`.

### §2 R6 — §2.3 is corrected in place, dated

In *"What the storing nodes learn, receipt or no receipt"*: the clause `or the unit structure` is
struck in place with a dated marker, and a paragraph headed **Correction — a storing node can count
the seal's blobs, and an eclipse learns more (2026-09-15, Q272)** quotes the struck clause, states
the measured fact (one non-zero transfer per priced blob in the transaction the node is handed),
says what survives (the work-id half and the per-work signing keys) and points to §2.8's grouping
routes and §2.11. It must not begin *"Correction to this section's M0 scope line"*. The implementing
lane re-measures the fact itself before writing it.

### §2 R7 — The check anchors on whole heading lines, and gains §2.11

`crates/antseal-core/tests/security_assumptions_drift.rs`'s required sections gain
`("2.11 Storage network as adversary", "eclipse, withholding, payment misdirection,
non-replication")`; the predicate becomes **exactly one whole line equal to `## <phrase>`** (after
trimming trailing whitespace) for all eleven; its message becomes owner-neutral; the test keeps its
name `every_m4_threat_section_is_enumerated`, which three documents cite.

### §2 R8 — Cross-references cite `§2.11` bare

Never the heading phrase, so the heading phrase occurs exactly once.

### §2 R9 — Currency edits in the same commit

The section intro (eleven headings, the test cited by name, no line range), the status header, the
sign-off table (a row for §2.11: written by `Q272`, not frozen), `# 3.`'s row for spec line 180, and
`## Related records` (D170, D173). Dated records stay as captured.

### §2 R10 — `Q272`'s spec anchor is corrected

From line 186 to line 180, with a dated marker, by the registrar.

### §2 R11 — The proofs-expired defect is a row before the section describes it

`S43` is minted with this record. §2.11 names the row and the chain as a **known open defect**,
never as accepted behaviour.

### §2 R12 — One commit

The section, the §2.3 correction, the check's extension and the §2 R5 pin land together, so the check
never names a missing section and the section never lands unpinned. The peer-trust subsection is
written against D173 as ruled.

### §2 R13 — No new user page is required

§2.11 ends with a **Delegated** paragraph naming what users are owed and when: the persistence advice
(check from a second vantage with `verify --live`; a disk-loss restore has no cache) and the warning
that a peer list is a trust decision — owed to a user page once `S40` makes the default network
reachable. Optional and lint-safe: one clause in `docs/user/wallet-hygiene.md` §4 that a node keeping
the transaction hash also learns how many blobs that payment covered.

### §2 R14 — Copy discipline by hand

`docs/threat-model.md` is class E and not linted, but D139 §2 R7 applies: no *notary*, no unqualified
*priority*, no authorship claim without its disclaimer in the same sentence.

## 3. Fault plants

Baseline green first (the check's target, test count read from the log). Doc-text plants, restored
from a saved copy and compared with `cmp` — never `git checkout --`, which would discard the lane's own
uncommitted section: delete the §2.11 heading line (red, *found 0*); delete the whole section (red);
delete the heading **and** add a cross-reference spelling its phrase — run once against the old
`contains` predicate to prove it is **green** there, then red under the anchored predicate; demote the
heading to `###` (old green, anchored red); duplicate the heading inside `# 3.` (red, *found 2*); delete
§2.10's heading (red naming §2.10 with the new message). The pin's cases per §2 R5, plus the unmodified
tree green. **[Corrected in place before this record landed, by the implementing lane]**: the blindness
proof cannot be run against the old test file *verbatim* for §2.11, which that file does not list — it is
run with the old `contains` predicate plus the §2.11 entry, and with the verbatim old file against the same
plant shape applied to §2.10.

## 4. What this record does NOT decide

- The Sybil cost of becoming a published address's close group at `saorsa-core` 0.26.2, and whether
  honest nodes shed records to closer newcomers — **not established**, and not written as fact.
- The fix for `S43`, and confining `client_adaptive.json` (`S42`).
- The absolute ANT price bound.
- D173 §2 R16's §2.9 wording for `Q34`'s stage 0 — the maintainer's.

## 5. Edit list — per write scope, with the lane named before this record was written

### RT (the threat-model lane)
- `docs/threat-model.md` per §2 R1–R4, R6, R8, R9, R13, R14 (nothing between the frozen block's
  markers; no existing `## 2.N` heading line).
- `crates/antseal-core/tests/security_assumptions_drift.rs` per §2 R7.
- A new source-text test under `crates/antseal-net/tests/` per §2 R5 / D173 §2 R15.
- Optionally `docs/user/wallet-hygiene.md` §4 per §2 R13.

### Registrar
- Mint `S43`; `Q272` Notes and its spec anchor (§2 R10); index row and register row.

## Closing — this record is not consent

It changes documents and tests only.
