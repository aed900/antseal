# fine-tree/ — fine-tree range-proof fixtures (G15)

Selective-disclosure range-proof fixtures for the GGM fine tree: leaf/node
domain separation (`0x00`/`0x01` tags), boundary-path openings, leaf-exact
GGM covers, and the must-exist **unbalanced n=6 MSB-first** vector that
pins the GGM indexing (MVP-SPEC.md lines 153/169; enforced at freeze time
by Q6's must-exist list). Populated by **G (G15)**; end-to-end range-proof
vectors that verify against `fine_root` may additionally land as
`fine-tree` kind vector files under `../vectors/<format-version>/` (schema:
`../vectors/README.md`).

NON-SECRET fixtures only (see `../README.md`): every `s_root`/GGM seed here
derives from the documented fixed test seed.
