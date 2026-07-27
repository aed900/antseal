# utf8-corpus/ — UTF-8 canonicalization corpus (G3)

Input/expected-output pairs for canonicalization v1 (UTF-8, NFC under the
descriptor-recorded Unicode version, LF, no BOM — MVP-SPEC.md line 83):
CRLF, NFD-vs-NFC, BOM, emoji/ZWJ, mixed scripts, invalid UTF-8, idempotence
cases (line 170). Owned by **G (G3)**; executed by
`crates/antseal-core/tests/utf8_corpus.rs`, whose test names carry the
reserved `corpus_` name marker so the three-OS CI lane proves cross-platform
byte stability (CONTRIBUTING.md).

NON-SECRET fixtures only (see `../README.md`, secret-material convention).
Corpus bytes are exact — `.gitattributes` (`testdata/** -text`) keeps them
checkout-stable; never re-encode or "fix" line endings in these files.

## Layout

- `input/<name>` — exact input bytes (several are deliberately invalid UTF-8).
- `expected/<name>` — the exact canonical bytes that input must produce.
- `gen_corpus.py` — the independent reference implementation that produced
  every golden (Python stdlib `unicodedata` only, a different NFC table
  lineage from the pinned Rust crate). `python3 gen_corpus.py --check`
  verifies the committed bytes; running it without `--check` regenerates and
  is a deliberate act (Q6 freeze: a byte change here is a format event).

Fixture names carry no extension on purpose: these are exact-byte fixtures,
not text files, and a `.txt` suffix invites tooling to "fix" them.

Names are discovered by walking the directories — adding a pair needs no
test change. Two conventions carry meaning:

- `pair-<base>-nfd` / `pair-<base>-nfc` — an NFD/NFC convergence pair. Both
  halves must exist, their inputs must differ, and they must canonicalize to
  identical bytes (that shared golden *is* the convergence assertion).
- The suite's `REQUIRED_PINS` list names corner fixtures whose deletion fails
  the run, because each pins a frozen decision (D20/D21).

## What the goldens are evidence of

The goldens are derived independently of the implementation under test, so a
green run is **cross-implementation agreement**, not self-consistency:

- **NFC** — the generator's Unicode table is typically 14.0.0 while the crate
  pins 17.0.0 (D25). Every NFC-sensitive fixture uses only characters
  assigned in Unicode ≤ 6.0, where the Unicode Normalization Stability Policy
  guarantees the NFC form can never change in a later version; that makes the
  older table an exact oracle for these inputs. Characters assigned after the
  oracle's version would break the argument — see `NFC_SAFE_FLOOR` in the
  generator.
- **Lossy decode (D20)** — every invalid-UTF-8 golden is an executed check
  that CPython's UTF-8 `replace` handler and Rust's `String::from_utf8_lossy`
  agree on Unicode §3.9 maximal subparts across all the failure classes
  below. They agreed on every fixture at first run (2026-07-27).

## Frozen behavior each fixture class pins

| Class | Fixtures | Pins |
|---|---|---|
| Degenerate | `empty`, `already-canonical`, `no-trailing-newline` | fixed-point/identity cases; no newline is invented |
| Whitespace | `whitespace-only-lines` | canonicalization never trims (blankness is G6/D22's rule, not the pipeline's) |
| Controls | `nul-and-controls` | NUL/VT/FF/DEL are ordinary content; detection is UTF-8 validity alone; only CR/CRLF fold |
| EOL (D21) | `crlf`, `lone-cr`, `cr-cr-lf`, `eol-mixed`, `lf-then-cr` | CRLF → LF, lone CR → LF, one pass (CR CR LF → LF LF) |
| BOM (D21) | `bom-leading`, `bom-double`, `bom-triple`, `bom-only`, `bom-interior`, `bom-after-lf`, `bom-interior-blocks-composition`, `bom-run-then-crlf-nfd` | strip the whole contiguous **leading** run; interior U+FEFF is content and blocks composition; BOM-only file → empty |
| Invalid UTF-8 (D20) | `invalid-lone-continuation`, `invalid-overlong-c0-af`, `invalid-surrogate-ed-a0-80`, `invalid-truncated-4byte`, `invalid-truncated-bom`, `invalid-bom-then-truncated-bom`, `invalid-maximal-subparts`, `invalid-then-crlf-and-nfd` | one U+FFFD per maximal subpart; a truncated BOM yields a **leading** U+FFFD that is never stripped |
| NFC | `pair-latin-*`, `pair-hangul-*`, `pair-vietnamese-*`, `pair-hebrew-reorder-*` | composition, algorithmic Hangul composition, canonical **reordering** by combining class (Vietnamese, Hebrew points) |
| Breadth | `emoji-zwj`, `mixed-scripts`, `mixed-everything` | ZWJ/skin-tone/flag/VS16 sequences survive byte-exact; RTL + CJK + Devanagari; every class combined |

## Cross-platform evidence status

The suite runs on linux, macOS, and Windows in the `cross-os-*` CI lane (Q1).
Local runs prove byte stability on linux only; the three-OS evidence lands
with the next remote CI run (pushing is a maintainer action).
