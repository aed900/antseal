# utf8-corpus/ — UTF-8 canonicalization corpus (G3)

Input/expected-output pairs for canonicalization v1 (UTF-8, NFC under the
descriptor-recorded Unicode version, LF, no BOM — MVP-SPEC.md line 83):
CRLF, NFD-vs-NFC, BOM, emoji/ZWJ, mixed scripts, idempotence cases
(line 170). Populated by **G (G3)**; consumed by tests carrying the
reserved `corpus_` name marker so the three-OS CI lane proves
cross-platform byte stability (CONTRIBUTING.md).

NON-SECRET fixtures only (see `../README.md`, secret-material convention).
Corpus bytes are exact — `.gitattributes` (`testdata/** -text`) keeps them
checkout-stable; never re-encode or "fix" line endings in these files.
