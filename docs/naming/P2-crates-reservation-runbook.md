# P2 — crates.io name reservation runbook

> **EXECUTION BLOCKED** on two things:
> 1. **D1-final** — the product name is still provisional
>    ([`docs/decisions/D1-product-name.md`](../decisions/D1-product-name.md):
>    upstream blessing pending; fallback `sealstone` on silence by M0 start).
> 2. **crates.io login** — the real publish must run under the
>    **maintainer's** account: `cargo login` (token from
>    <https://crates.io/settings/tokens>, needs `publish-new` scope) done by
>    the user before `--execute`.
>
> Until both hold, only the safe default (dry-run) mode of
> [`scripts/reserve-crates.sh`](../../scripts/reserve-crates.sh) may run.

## Permanence warning (P2 acceptance requires this note)

**crates.io publishes are forever.** There is no reservation mechanism
other than publishing, no un-publish, and **yank only hides a version — the
name stays claimed** by the publishing account permanently. Consequences:

- Publishing the placeholders **is** the point-of-no-return for the name:
  do it only after D1 is final.
- A wrong-account publish is unfixable without crates.io support
  intervention — verify `cargo login` identity first.
- If the chosen name is squatted between now and execution, that is a
  **forced P1 re-decision** (P2 accept), not something to work around.

## Availability evidence (research memo, retrieved 2026-07-27T13:44:34Z–13:44:39Z)

| crate | HTTP | verdict |
| --- | --- | --- |
| `antseal` | 404 | FREE |
| `antseal-core` | 404 | FREE |
| `antseal-anchor` | 404 | FREE |
| `antseal-net` | 404 | FREE |
| `antseal-cli` | 404 | FREE |
| `seal-core` (context) | 200 | TAKEN — unrelated event-sourcing/SCM project (user `bobisme`, 0.27.1, 2026-04-25) — confirms the spec's reason for the `antseal-*` prefix |
| `seal-cli` (context) | 200 | TAKEN — same project |

Re-confirmed live by the script's own availability pre-check on 2026-07-27
(dry-run test below): all five still FREE.

## Re-verify commands (run any time; the script does this automatically)

```sh
# 404 = free, 200 = taken. Always send a real User-Agent (crates.io policy).
for c in antseal antseal-core antseal-anchor antseal-net antseal-cli; do
  printf '%s: ' "$c"
  curl -sS -o /dev/null -w '%{http_code}\n' \
    -A 'antseal-setup (contact: 129773515+aed900@users.noreply.github.com)' \
    "https://crates.io/api/v1/crates/$c"
done
```

## What gets published

Five standalone 0.0.0 placeholder crates, generated in a temp dir by the
script (never part of the workspace):

- **Version**: `0.0.0`
- **Contents**: minimal `src/lib.rs` (doc comment only)
- **Description**: `Reserved name for the antseal project (pre-M0
  placeholder — see repo)`
- **License** (per [D6](../decisions/D6-license.md)): `MIT OR Apache-2.0`
  for **all five** — the license field describes the crate's own code, the
  placeholders contain only our empty lib and no ant-core dependency, so
  the GPL-3.0 distribution effect on net/cli does not attach to them. The
  net/cli distribution note attaches at first *real* publish (M4/Q29).
- **Repository**: `https://github.com/aed900/antseal` (relocated 2026-07-27; never publish crates pointing at the deprecated aed900 repo)
- **Edition**: 2021 (standalone crates outside the workspace, buildable on
  any ambient toolchain; superseded by real publishes — D4 note)

## Publish order

1. `antseal` — bare product name first: highest squat value, and D5
   reserves it explicitly alongside the spec-normative `antseal-cli`
2. `antseal-core`
3. `antseal-anchor`
4. `antseal-net`
5. `antseal-cli`

The script pauses 30 s between real publishes (crates.io rate-limits
new-crate publishes) and re-checks availability immediately before each
one.

## Procedure

1. Confirm D1 final (decision file updated; blessing archived or fallback
   recorded — on fallback, edit the `CRATES` list in the script first and
   re-run the availability screen for the new family).
2. Dry-run (safe, no login): `./scripts/reserve-crates.sh` — must end
   `RESULT: all names free; all dry-runs green`.
3. Maintainer: `cargo login` with the intended account.
4. `./scripts/reserve-crates.sh --execute` — re-verifies availability per
   crate, then requires typing `publish-forever` at the prompt before any
   upload.
5. Record here: publish date, versions, and the crates.io owner shown for
   each crate (P2 accept: maintainer account is owner on all five).
6. If any name shows TAKEN and the owner is not the maintainer: STOP —
   P1 forced re-decision.

## Dry-run test record

**2026-07-27** — `./scripts/reserve-crates.sh` (default dry-run mode)
executed end-to-end on the dev machine, toolchain cargo 1.92.0:

- Availability pre-check: all five names **FREE (HTTP 404)** — live
  re-confirmation of the 13:44Z memo findings.
- `cargo publish --dry-run`: **green for all five** placeholder crates
  (packaged 4 files ≈1.5 KiB each, verify-build passed, upload aborted with
  the expected `warning: aborting upload due to dry run`).
- Script exit code 0; summary: `antseal / antseal-core / antseal-anchor /
  antseal-net / antseal-cli: FREE, dry-run OK`.
- Argument handling verified: `--help` exits 0; unknown flags exit 2
  without doing anything.

## Post-execution record (fill at real publish)

- Date: _(pending)_
- Published versions: _(pending — expected 0.0.0 ×5)_
- crates.io owner verified on all five: _(pending)_
- Fed back into TODO/P2 acceptance: _(pending)_
