#!/usr/bin/env bash
# Q30 / D71 — sign a set of built release artifacts with the project's
# long-lived Ed25519 key, locally, on the maintainer's machine.
#
#   ./scripts/sign-release.sh --version v0.1.0 --commit <40-hex> --dir dist/
#   ./scripts/sign-release.sh --help
#
# It produces, per D71 §2 R2:
#   SHA256SUMS              one `sha256sum` line per artifact, excluding
#                           itself and excluding every `*.minisig`
#   SHA256SUMS.minisig      a signature over that manifest
#   <artifact>.minisig      a signature over each artifact individually
#
# ── Why both, and not one of them ─────────────────────────────────────────
#
# D71 §2 R2 refuses each half on its own. Signing only the manifest makes the
# binary's integrity depend on the user remembering a SECOND command: someone
# who checks `SHA256SUMS.minisig` and then runs the binary without
# `sha256sum -c` has verified nothing about the binary and nothing tells them
# so. Signing only the artifacts leaves `MVP-SPEC.md:157`'s mandated manifest
# unauthenticated, which is a trap for anyone who treats it as their integrity
# source. Both costs milliseconds and ~320 bytes per artifact.
#
# ── The trusted comment is the load-bearing field ─────────────────────────
#
# D71 §1.3 row 6 MEASURED the defect this closes: a PREVIOUS release presented
# with its own genuine signature under the same key produces a complete ACCEPT.
# A content signature structurally cannot see replay or downgrade. The only
# thing that distinguishes the two is the trusted comment, which minisign
# covers with `ed25519(<signature> || <trusted_comment>)` and therefore
# authenticates.
#
# So every signature this script emits carries an explicit `-t` in D71 §2 R4's
# structured form:
#
#   antseal <version> <artifact-basename> commit:<40-hex> <RFC3339 UTC>
#
# The basename and version defeat cross-artifact and downgrade presentation;
# the commit ties the release to a tree; the timestamp is the maintainer's
# claim and NOT an anchor — D71 §2 R4 forbids the documentation presenting it
# as one, and `docs/signing/verifying-a-release.md` does not.
#
# ONE timestamp is used for the whole run, deliberately. It is what lets
# `scripts/verify-release.sh` bootstrap the expected comment for every artifact
# from the single authenticated manifest signature and then compare by exact
# string equality, which is the only form D71 §2 R3 permits a gate to use.
#
# The untrusted comment is left at minisign's default and carries nothing.
# D71 §1.3 row 4 measured that rewriting it leaves the artifact fully
# verifying, so anything meaningful placed there would be attacker-editable
# provenance.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m::warning::sign-release: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m::error::sign-release: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
sign-release.sh — produce SHA256SUMS + minisign signatures for a release (D71 §2 R2)

  scripts/sign-release.sh --version <v> --commit <40-hex> --dir <dir> [options]

Required:
  --version <v>        release version, e.g. v0.1.0
  --commit <40-hex>    the full 40-character commit sha the release is built from
  --dir <dir>          directory holding the built artifacts

Options:
  --timestamp <ts>     RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ). Defaults to now.
                       Pass it explicitly to re-produce a previous run's bytes:
                       minisign's Ed25519 signatures are deterministic, so an
                       unchanged artifact under an unchanged trusted comment
                       re-signs to the same bytes (D71 §2 R1).
  --seckey <path>      secret-key file. Default: minisign's own default,
                       ~/.minisign/minisign.key (D71 §2 R7.2).
  --pubkey <token|path>  the matching public key, used ONLY to read every
                       signature back after writing it. Default:
                       ~/.minisign/minisign.pub.
  --minisign <path>    the minisign binary. Default: whatever is on PATH.
  --help

The passphrase is read by minisign itself, interactively. This script never
reads it, never accepts it as a flag or an environment variable, and never
passes it on a command line — a passphrase on argv is visible in ps(1) and in
shell history. Run this from a terminal.

EXPECT ONE PASSPHRASE PROMPT PER ARTIFACT, PLUS ONE FOR THE MANIFEST. That is
not a defect in this script and it cannot be batched away: minisign signs many
files in one invocation only when they share a single `-t`, and D71 §2 R4
requires each trusted comment to carry ITS OWN artifact's basename. The
per-artifact comment is what defeats cross-artifact presentation, so the prompt
count is the price of the property.

The secret key is never on a CI runner, in a GitHub secret, in a KMS, or in
this checkout (D71 §2 R1, §2 R7). Signing is a local act.
EOF
}

# ── D71 §2 R7.1 — a `-W` (unencrypted) key is REFUSED ─────────────────────
#
# The check reads the KDF field out of the key struct instead of matching a
# header string, for a reason D71 §B R3 states in terms: the untrusted comment
# is free text, `-c` replaces it outright, and D71 §1.3 row 4 measured that
# rewriting it changes nothing about validity. Any rule keyed on that line is a
# convenience, not a check.
#
# The struct's first six bytes are the type tag — `sig_alg` "Ed", `kdf_alg`,
# `chk_alg` "B2" — at offset 0. Field order is upstream's `SeckeyStruct`
# (minisign `src/minisign.h`), which rust-minisign's `SecretKey::to_bytes()`
# agrees with byte for byte, so this reads the same field for a key produced by
# either tool. `kdf_alg`:
#
#   0x00 0x00   KDFNONE — the key is NOT passphrase-wrapped. This is `-W`.
#   0x53 0x63   "Sc", scrypt — the required form.
#
# Deliberately NOT written as a base64 prefix comparison: the base64 images of
# those two structs are exactly what `secret-guard` pattern (4c) hunts for
# across this checkout (`scripts/ci-lanes.sh`), and a script carrying either
# literal would red the tree it lives in. Reading the decoded bytes tests the
# same field and leaves no needle behind.
key_kdf_class() {
  local body hex
  body="$(grep -v '^untrusted comment:' -- "$1" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$body" ] || { printf 'unparseable'; return; }
  hex="$(printf '%s' "$body" | base64 -d 2>/dev/null | head -c 6 | od -An -tx1 | tr -d '[:space:]')"
  case "$hex" in
    4564????4232) : ;;
    *) printf 'unparseable'; return ;;
  esac
  case "${hex:4:4}" in
    0000) printf 'unencrypted' ;;
    5363) printf 'encrypted' ;;
    *)    printf 'unknown-kdf' ;;
  esac
}

version=""; commit=""; dir=""; stamp=""; seckey=""; pubkey=""; minisign_bin=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   version="${2:-}"; shift 2 || die "--version needs a value" ;;
    --commit)    commit="${2:-}"; shift 2 || die "--commit needs a value" ;;
    --dir)       dir="${2:-}"; shift 2 || die "--dir needs a value" ;;
    --timestamp) stamp="${2:-}"; shift 2 || die "--timestamp needs a value" ;;
    --seckey)    seckey="${2:-}"; shift 2 || die "--seckey needs a value" ;;
    --pubkey)    pubkey="${2:-}"; shift 2 || die "--pubkey needs a value" ;;
    --minisign)  minisign_bin="${2:-}"; shift 2 || die "--minisign needs a value" ;;
    --help|-h)   usage; exit 0 ;;
    *)           usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$version" ] || { usage >&2; die "--version is required"; }
[ -n "$commit" ]  || { usage >&2; die "--commit is required"; }
[ -n "$dir" ]     || { usage >&2; die "--dir is required"; }

case "$commit" in
  *[!0-9a-f]* | "") die "--commit must be the full 40-character lowercase hex sha (got: $commit)" ;;
esac
[ "${#commit}" -eq 40 ] || die "--commit must be 40 hex characters, got ${#commit} (D71 §2 R4)"

[ -d "$dir" ] || die "--dir is not a directory: $dir"

if [ -z "$stamp" ]; then
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
case "$stamp" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) : ;;
  *) die "--timestamp must be RFC3339 UTC, e.g. 2026-08-18T12:00:00Z (got: $stamp)" ;;
esac

# ── the tool ──────────────────────────────────────────────────────────────
if [ -z "$minisign_bin" ]; then
  minisign_bin="$(command -v minisign 2>/dev/null || true)"
fi
[ -n "$minisign_bin" ] && [ -x "$minisign_bin" ] || die \
  "no minisign binary found. Install it from an archive independent of this project's own
    hosting — \`apt install minisign\` on Debian/Ubuntu, \`brew install minisign\` on macOS —
    or pass --minisign <path>. See docs/signing/maintainer-key-procedure.md."

# ── the key, and the R7.1 refusal ─────────────────────────────────────────
if [ -z "$seckey" ]; then
  seckey="${HOME}/.minisign/minisign.key"
fi
[ -f "$seckey" ] || die "no key file at $seckey — generate one per docs/signing/maintainer-key-procedure.md"

case "$(key_kdf_class "$seckey")" in
  encrypted)
    : ;;
  unencrypted)
    die "REFUSED: $seckey is not passphrase-protected (its KDF field is KDFNONE — a \`-W\` key).
    D71 §2 R7.1 forbids it, and the prohibition is untouched by D71 §B: an unencrypted key is a
    plaintext Ed25519 secret at rest on this machine and in every offline backup of it, and this
    key can never be revoked (D71 §2 R9), so a single read of the file is unbounded in time.
    Generate a passphrase-protected key, or re-wrap this one with \`minisign -C\`." ;;
  unknown-kdf)
    die "REFUSED: $seckey has a KDF field this script does not recognise. It is neither the
    scrypt-wrapped form D71 §2 R7.1 requires nor a recognised unencrypted one; refusing rather
    than guessing." ;;
  *)
    die "REFUSED: $seckey does not parse as a key file (expected a base64 body whose first six
    bytes are the \"Ed\" / KDF / \"B2\" type tag). Refusing rather than handing an unknown file
    to the signer." ;;
esac

# ── the artifact set ──────────────────────────────────────────────────────
# Everything in --dir except the manifest itself and every signature, which is
# exactly D71 §2 R2's rule. `.ots` proofs and `verifier-web-SHA256SUMS` are
# artifacts and are covered like any other.
artifacts=()
while IFS= read -r f; do
  artifacts+=("$f")
done < <(cd "$dir" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS' ! -name '*.minisig' \
           | sed 's|^\./||' | LC_ALL=C sort)

[ "${#artifacts[@]}" -gt 0 ] || die "no artifacts in $dir (after excluding SHA256SUMS and *.minisig)"

# The public key is used ONLY for the read-back below. It is resolved BEFORE
# any signing so a missing one fails immediately rather than after the
# maintainer has typed the passphrase N times.
if [ -z "$pubkey" ]; then
  pubkey="${HOME}/.minisign/minisign.pub"
fi
if [ -f "$pubkey" ]; then
  pubkey="$(sed -n '2p' -- "$pubkey" | tr -d '[:space:]')"
fi
case "${#pubkey}" in
  56) : ;;
  *)  die "--pubkey is neither a readable key file nor a 56-character public key token
    (got ${#pubkey} characters). The read-back below is what proves this run actually signed
    what it claims, so it is not skippable." ;;
esac

note "minisign:  $minisign_bin ($("$minisign_bin" -v 2>&1 | head -1))"
note "key:       $seckey (passphrase-protected)"
note "release:   $version  commit:$commit  $stamp"
note "artifacts: ${#artifacts[@]} in $dir"

# ── 1. the manifest ───────────────────────────────────────────────────────
( cd "$dir" && sha256sum -- "${artifacts[@]}" > SHA256SUMS ) || die "sha256sum failed"
note "wrote $dir/SHA256SUMS (${#artifacts[@]} lines)"

# ── 2. one signature per artifact, then the manifest's ────────────────────
# Signed in a `for` loop over an array rather than a `while read` over a pipe,
# so this script never holds stdin: minisign's passphrase prompt needs it.
sign_one() {
  local name="$1" tc
  tc="antseal ${version} ${name} commit:${commit} ${stamp}"
  "$minisign_bin" -S -s "$seckey" -m "${dir}/${name}" -x "${dir}/${name}.minisig" -t "$tc" \
    || die "signing ${name} failed"
  printf '    %s\n' "${name}.minisig  <-  ${tc}"
}

note "signing ${#artifacts[@]} artifact(s) + the manifest"
for a in "${artifacts[@]}"; do sign_one "$a"; done
sign_one SHA256SUMS

# ── 3. prove the run, here, rather than trusting it ───────────────────────
# A signing script that does not verify its own output is a step whose failure
# nothing could show. Every signature is read back with the same `-Q -H` string
# equality the gate uses (D71 §2 R3).
rc=0
for a in "${artifacts[@]}" SHA256SUMS; do
  want="antseal ${version} ${a} commit:${commit} ${stamp}"
  got="$("$minisign_bin" -Q -H -Vm "${dir}/${a}" -x "${dir}/${a}.minisig" -P "$pubkey" 2>/dev/null)"
  if [ "$got" != "$want" ]; then
    warn "read-back MISMATCH for ${a}: got [${got}] want [${want}]"
    rc=1
  fi
done
[ "$rc" -eq 0 ] || die "at least one signature did not read back under the supplied public key —
    do not publish this directory. Either --pubkey does not match --seckey, or a signature is
    not what this run intended to write."

note "read-back OK: ${#artifacts[@]} artifact signature(s) + the manifest signature"
cat <<EOF

Next:
  1. Publish every file in ${dir}, including SHA256SUMS and every *.minisig.
  2. Verify the directory as a stranger would, from a clean machine:
       scripts/verify-release.sh --version ${version} --commit ${commit} \\
         --dir ${dir} --key <the 56-character public key>
  3. The release notes carry the expected trusted comments printed above.
     docs/signing/verifying-a-release.md is the page a user follows.
EOF
