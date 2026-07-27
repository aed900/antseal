# P1 — Name propagation checklist

Every name-bearing identifier the D1 product-name decision propagates into,
with its owning domain (per tasks/P.md P1: **C** context string, **F**
format strings, **U** vault dir/binary, **P** crates/domain/repo, **Q**
docs) and its freeze point. When D1 finalizes (blessing, or fallback per
the deadline policy in
[`docs/decisions/D1-product-name.md`](../decisions/D1-product-name.md)),
the final name + this checklist go to each owning domain **before the M0
Definitions freeze**.

Verified against MVP-SPEC.md (Revision 2, 2026-07-27); spec line numbers
cited.

| # | Identifier | Current value | Owning domain | Freeze point |
| --- | --- | --- | --- | --- |
| 1 | **Signature context string** (spec line 97) | `"antseal-manifest-v1"` | **C** (C12) | **M0 — PERMANENT.** Bound into every signature pre-image (ML-DSA-65 `ctx`; Ed25519 `ctx ‖ 0x00 ‖ body`); after M0 the name is baked into an immutable format forever. This row is the reason D1 must land pre-M0. |
| 2 | HKDF labels (spec lines 91–98) | `"unit-key"`, `"unit-salt"`, `"path-salt"`, `"file-salt"`, `"fine-seed"`, `"sig-ed25519"`, `"sig-mldsa65"`, `"manifest-key"` | C/F | Frozen at M0, but **NOT name-bearing** (verified — none embeds the product name) → rename-immune; listed to record the check, not as a propagation target. |
| 3 | Hash domain tags (spec line 79) | single bytes `0x00`–`0x06` | C/F | Frozen at M0; **not name-bearing** → rename-immune. |
| 4 | Future format/domain identifier strings minted by F at M0 (CBOR profile ids, bundle format ids, …) | none exist yet | **F** (F4) | **Standing rule:** any new string that embeds the product name must take the D1-final name *before* the M0 Definitions freeze; prefer name-free strings where possible so formats stay rename-immune. |
| 5 | crates.io crate names (spec lines 45–56) | `antseal`, `antseal-core`, `antseal-anchor`, `antseal-net`, `antseal-cli` (workspace dirs `crates/antseal-*` follow) | **P** (P2; D5 covers the bare-name question) | Renameable until first crates.io publish; **each publish permanently claims the name** (yank hides, never releases). P2 executes only on D1-final. |
| 6 | GitHub repo / org | `aed900/antseal` (user+org `antseal` free as of 2026-07-27) | **P** | Renameable-later (GitHub renames leave redirects); settle before the repo goes public (M4). |
| 7 | Verifier domain → canonical URL substrate (spec line 139) | planned: `antseal.org` primary + `antseal.dev` defensive (P3, not yet registered) | **P** registers (P3); **R** consumes (R26/D62, M3) | Domain swappable until the **M3 canonical-URL freeze**; after M3 the URL is a trust point — losing or changing it is a provenance incident. |
| 8 | CLI binary name (spec lines 34–38, 55) | `antseal` | **U** (U1) | Renameable until first release (M4); afterwards a UX/docs cost only — the binary name never enters any format bytes. |
| 9 | Vault dir + config paths (spec line 143) | `~/.antseal/` | **U** (U1) | Renameable-later with a local migration shim; local-only, never format-relevant. Set at M0–M1 when U1 lands. |
| 10 | **`.sealproof` bundle extension** (spec lines 36, 38, 112) | `.sealproof` | **F** (format convention) / **R** (page + docs) | **Not name-coupled to the ant- prefix** — it contains "seal" only, and every shortlisted fallback name retains "seal", so **the extension stays `.sealproof` regardless of any D1 outcome** (spec uses it verbatim). It is a filename convention, not format bytes; it hardens into a recognition convention when bundles ship (M2/M3). |
| 11 | README / docs product mentions, one-liners, positioning lines | "antseal" throughout README stub + docs/ | **Q** | Renameable any time; on rename, a repo-wide sweep task (grep for the old name) — no freeze. |
| 12 | crates.io metadata (descriptions, `repository` fields) incl. P2 placeholders | "Reserved name for the antseal project …", repo URL | P/Q | Per-publish; placeholders are superseded by real publishes. |

## Handoff protocol (P1 acceptance)

1. D1 finalizes → update `docs/decisions/D1-product-name.md` with the
   outcome + archived upstream reply (or fallback record + trademark-search
   result).
2. Notify owning domains with the final name against this table: **C**
   freezes the row-1 context string at M0; **F** applies rows 4/10; **U**
   applies rows 8/9; **P** executes P2 (row 5) and P3 (row 7); **Q** sweeps
   row 11.
3. On fallback (`sealstone` per current policy): rows 1, 4–9, 11, 12 take
   the new name (row 1 becomes `"sealstone-manifest-v1"` or as C decides
   the versioned pattern); rows 2, 3, 10 are unchanged by construction.
