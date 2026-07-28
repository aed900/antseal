# fine-tree/ — fine-tree range-proof fixtures (G15)

**G15's golden vectors landed in the Q4 envelope, not here.** They are

    ../vectors/v1/fine-tree/fine-tree.json     (kind `fine-tree`)
    ../vectors/v1/fine-tree/README.md          (what it pins, case by case)
    ../vectors/v1/fine-tree/gen_vectors.py     (independent reference generator)

and they discharge Q6's must-exist obligation `fine-tree-unbalanced-n6`.

## Why there

The vectors are golden vectors: a fixed `s_root`, a content vector, and the
byte-exact artifacts an implementation must reproduce. Q2's layout decision
makes `vectors/<format-version>/` the home of *all* committed vectors
(`../README.md`, contribution rule 5), Q6's freeze registry already carried
the obligation under that slug, and `../vectors/README.md` had reserved the
kind name `fine-tree` for exactly this task. Landing them in the envelope
inherits — for free, with no new harness — the discovery contract, the
NON-SECRET enforcement, the misfiled-version check, the three `cross-os-*`
lanes, the per-version freeze, and the WASM-safe execution path the Q5
native↔WASM bit-match lane byte-compares. `sig-reject` (C15) and the four
crypto kinds (C16) made the same move for the same reasons; this file's
earlier text already anticipated it ("… may additionally land as `fine-tree`
kind vector files under `../vectors/<format-version>/`").

## What this directory is still for

Fine-tree fixtures that are **not** Q4 vectors — anything the envelope's
"recompute every expectation" contract does not fit, such as bulk streaming
corpora for the G18 perf/memory budget tests. Nothing lands here without a
reason the envelope cannot serve; if it can, it belongs in `../vectors/`.

NON-SECRET fixtures only (see `../README.md`): every `s_root`/GGM seed used
anywhere in the fine-tree fixtures derives from the documented fixed test
seed.
