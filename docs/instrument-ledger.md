# Instrument-finding ledger

**Authority**: `TODO.md` protocol rule 8 (**D125**, ruled 2026-08-11). Append-only — a correction is a new entry naming the entry it corrects, never an edit.

**What belongs here**: any finding whose *subject is the verification apparatus itself* — checker/self-test defects, decision-document prose or arithmetic, stale locators, tracker-count drift, gate-instrument honesty. It takes **no task ID and no `TODO.md` row**.

**What does NOT belong here**: a *product* defect found *by* an instrument — the Q112 class (shipped code that fails to compile under a feature gate, a policy violated in code, a wrong byte on the wire). Those mint a row immediately, per protocol rule 2, exactly as before D125.

**The line to draw when unsure**: does fixing it change what a *user's* seal/verify does? Row. Does it change only what a *checker* says or how a document reads? Ledger.

**Promotion**: an entry becomes a task (protocol rule 2 — the registrar assigns the next free ID; lanes never self-number) only when it **blocks an acceptance on the ship path**, which is the Current-focus queue in `TODO.md`. Record the promotion as a new ledger entry pointing at the minted ID.

**Pre-D125 rows**: open instrument-class rows minted before 2026-08-11 stay in `TODO.md`, frozen as a class — they are NOT migrated here and NOT struck. This ledger starts empty and covers findings from wave 16 onward.

**Entry format** (one line each):

    - YYYY-MM-DD · <finder: lane / instrument / session> · <one-line finding> · <pointer: file / section / run id>

---

## Entries

*(none yet)*
