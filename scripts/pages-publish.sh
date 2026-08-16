#!/usr/bin/env bash
# R26 — build the verifier page for publication to the ONE canonical URL.
#
#   ./scripts/pages-publish.sh --build     provision, build, check, stage
#   ./scripts/pages-publish.sh --verify URL  check what a host actually serves
#   ./scripts/pages-publish.sh --help
#
# The canonical URL is `https://antseal.org/` (D62 §3 R1) — apex, https,
# trailing slash, no www, no subdomain, no path. It is ONE constant and this
# script is the only place in the deploy path that spells it.
#
# ── Why this is a script and not a `run:` block ────────────────────────────
#
# Q43: logic that lives only in YAML is logic nobody runs before a push. Every
# step below is runnable locally, which is the only reason the workflow that
# calls it can be trusted without spending a metered CI minute to find out.
#
# ── What is served is ONE FILE ─────────────────────────────────────────────
#
# D129 §5 R1: the closure is `index.html` and nothing else, so `SHA256SUMS` has
# one line and the set-equality check below compares a set of one. Two riders
# from D131 §5 R4 and D129 §7:
#
#   * the artifact is built to `target/verifier-web/`, never committed and
#     never written into `verifier-web/` — Pages publishes what this run built,
#     so there is no hand-copied artifact between the bytes that were hashed
#     and the bytes that are served (D62 §3 R2's named hazard);
#   * a browser's automatic `GET /favicon.ico` is NOT a served artifact. It
#     404s, and set equality is asserted over served RESPONSES, never over
#     requests — a request-based check goes red on a correct deploy. R23
#     declaring no icon removes the request entirely, but this must be right
#     without that.
#
# ── THE DEPLOY IS WHERE REPRODUCIBILITY IS ENFORCED (R86/D135 §3 R1) ───────
#
# `cmd_build` below runs `scripts/reproducible-build.sh --compare` between
# build A and the packaging step, and `pages.yml` calls `--build` BEFORE
# `actions/configure-pages`, `upload-pages-artifact` and `deploy-pages`. So a
# red there ends the job with nothing staged: *a deploy cannot publish a digest
# two builds disagree on* is a property of the committed files, not a promise.
#
# The tier is DEPLOY-GATED and RAISE-ONLY BY DECISION; the price, the refused
# arms and the pre-priced promotion arm are at the top of that script. What the
# gate does NOT cover, stated here so no reader assumes it: nothing between
# deploys — a commit that breaks reproducibility is caught at the next deploy,
# not at the push that broke it, and this repository's whole history contains
# two deploys.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

CANONICAL_URL="https://antseal.org/"
OUT="target/verifier-web"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31m::error::pages-publish: %s\033[0m\n' "$*" >&2; exit 1; }

cmd_build() {
  # The pins are READ from where they are declared and the two `cargo install`
  # lines live in ONE place, because `verifier-page.yml` needs the same two
  # tools and a second copy of the derivation would agree today and drift
  # afterwards (D136 §2 R5, §3's refused shape; Q130).
  note "provision the pinned wasm tools"
  ./scripts/wasm-tools-provision.sh || return 1

  note "build and check the module (R22)"
  ./scripts/wasm-pack-build.sh --check || return 1

  # AFTER build A and BEFORE packaging (D135 §5 R4): the comparison must not
  # write into `~/.cargo` or `./target`, or the post-job rust-cache save would
  # store a tree contaminated by the second environment and the next deploy
  # would restore it. Build B gets its own checkout path and its own
  # $CARGO_HOME, which is the axis and also the reason it cannot reach this
  # job's cache (D135 §5 R1).
  note "two ENVIRONMENTS, one commit: is the digest this deploy publishes reproducible? (R86)"
  ./scripts/reproducible-build.sh --compare || return 1

  note "package and check the page (R25)"
  ./scripts/verifier-page-build.sh --check || return 1

  [ -f "${OUT}/index.html" ]  || die "${OUT}/index.html was not produced"
  [ -f "${OUT}/SHA256SUMS" ] || die "${OUT}/SHA256SUMS was not produced"

  # The served closure is what SHA256SUMS lists, and nothing else may be in the
  # directory that gets uploaded — D63 §5 R4's "the sums list IS the deploy
  # list", asserted here rather than trusted.
  local listed staged
  listed="$(awk '{print $2}' "${OUT}/SHA256SUMS" | sort)"
  staged="$(cd "$OUT" && ls -A | grep -v '^SHA256SUMS$' | sort)"
  if [ "$listed" != "$staged" ]; then
    printf '::error::the deploy directory and SHA256SUMS disagree\n  listed: %s\n  staged: %s\n' \
      "$(printf '%s' "$listed" | tr '\n' ' ')" "$(printf '%s' "$staged" | tr '\n' ' ')" >&2
    return 1
  fi
  note "staged for ${CANONICAL_URL} — $(wc -c <"${OUT}/index.html") bytes, $(wc -l <"${OUT}/SHA256SUMS") artifact"
}

# ── what a host actually serves ────────────────────────────────────────────
#
# Run AFTER a deploy, against the real URL. This is the half that cannot be
# proven by building: D62 §3 R3's set equality, the Content-Type, and the
# two-encoding tripwire that matters MORE under D129's single file, since one
# 2.47 MB text artifact is exactly what a transform-happy intermediary
# rewrites and the whole payload is inside it.
cmd_verify() {
  local url="${1:-$CANONICAL_URL}" tmp rc=0
  command -v curl >/dev/null || die "curl is not available"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  note "fetch ${url} identity-encoded"
  curl -fsSL --compressed-no -H 'Accept-Encoding: identity' -o "${tmp}/identity" \
       -D "${tmp}/headers" "$url" 2>/dev/null ||
    curl -fsSL -H 'Accept-Encoding: identity' -o "${tmp}/identity" -D "${tmp}/headers" "$url" ||
    die "the canonical URL did not serve a page — a deploy that fails closed is correct, a parking page is not"

  local ctype
  ctype="$(grep -i '^content-type:' "${tmp}/headers" | tail -1 | tr -d '\r')"
  case "$ctype" in
    *text/html*) printf '  content-type: %s\n' "${ctype#*: }" ;;
    *) printf '::error::the page is served as %s, not text/html\n' "${ctype:-<absent>}" >&2; rc=1 ;;
  esac

  note "fetch the same URL gzip-encoded — the two must decode to the SAME bytes"
  curl -fsSL --compressed -o "${tmp}/encoded" "$url" || { printf '::error::the compressed fetch failed\n' >&2; rc=1; }
  if [ -f "${tmp}/encoded" ] && ! cmp -s "${tmp}/identity" "${tmp}/encoded"; then
    printf '::error::the host serves DIFFERENT bytes under two content-codings — it is rewriting the body, which disqualifies it (D63 §10 (iii))\n' >&2
    rc=1
  fi

  if [ -f "${OUT}/SHA256SUMS" ]; then
    note "compare the served bytes against the sums this build produced"
    local want got
    want="$(awk '{print $1}' "${OUT}/SHA256SUMS")"
    got="$(sha256sum "${tmp}/identity" | awk '{print $1}')"
    if [ "$want" = "$got" ]; then
      printf '  served bytes match the built artifact: %s\n' "$got"
    else
      printf '::error::the served bytes are NOT the built artifact\n  built:  %s\n  served: %s\n' "$want" "$got" >&2
      rc=1
    fi
  else
    printf '  (no local SHA256SUMS — run --build first to compare bytes)\n'
  fi

  return $rc
}

case "${1:---build}" in
  --build | "") cmd_build ;;
  --verify)     shift; cmd_verify "${1:-$CANONICAL_URL}" ;;
  --help | -h)  sed -n '3,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "usage: scripts/pages-publish.sh [--build | --verify [url] | --help]" ;;
esac
