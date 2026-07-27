# tamper/ — tamper-matrix fixtures (Q7/Q8)

Pre-mutated fixtures for the tamper-matrix harness (MVP-SPEC.md line 168:
**every mutation fails with a distinct error**; no row may panic). The Q7
harness defines the row shape `{row-id, base fixture, mutation, expected
outcome}`; rows are contributed by **F, C, G, A, R** (each owning its
format's mutation families); Q8's machine-readable completeness registry
(`MATRIX.toml`, mapping the spec's M0/M2 mutation enumeration 1:1 onto
implemented rows) lands here beside the fixtures.

Fuzz regression cases from crash triage (Q9) are also added here when a
crash reduces to a deterministic malformed input.

NON-SECRET fixtures only (see `../README.md`): mutations are applied to
fixtures derived from the documented fixed test seed — a tampered fixture
is still committed material and follows the same convention.
