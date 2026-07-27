# fuzz-seeds/ — committed fuzz seed corpora (Q9)

Committed, minimized seed corpora for the cargo-fuzz targets, one
subdirectory per target (`<target-name>/`), e.g. the F17 manifest/bundle
CBOR parsers at M0 and A23's DER/`.ots` parsers at M2 (Q17). Q9's fuzz
workspace (`fuzz/`) reads its initial corpus from here; nightly-run corpus
growth is minimized and folded back per the Q9 cadence doc. Seeds start
from golden vectors (`../vectors/`) and tamper fixtures (`../tamper/`).

Crash triage (Q9): a crash is release-blocking; its reduced reproducer is
committed either here (as a seed) or as a `../tamper/` regression row.

NON-SECRET fixtures only (see `../README.md`). Seed bytes are exact —
covered by the `testdata/** -text` checkout guard like everything else
here.
