#!/usr/bin/env bash
# Q30 / D71 §2 R3 — verify a downloaded antseal release directory.
#
#   ./scripts/verify-release.sh --version v0.1.0 --commit <40-hex> \
#       --dir ./download --key RW<...56 characters...>
#   ./scripts/verify-release.sh --self-test
#   ./scripts/verify-release.sh --help
#
# This is the MACHINE form. The human form — one command, one artifact, no
# second step to forget — is `docs/signing/verifying-a-release.md`, and this
# script runs the same check over a whole directory.
#
# ── Why this compares a STRING and not an exit status ─────────────────────
#
# D71 §1.3 row 6 is the finding this whole script is shaped around. A previous
# release, presented with its OWN genuine signature under the SAME key,
# produces a complete ACCEPT — exit 0, "Signature and comment signature
# verified". A content signature structurally cannot see replay or downgrade.
#
# So a gate that asserts `minisign ... ; test $? -eq 0` is green against the
# one attack the mechanism cannot see: it is an assertion that cannot fail,
# which is this project's dominant defect class (docs/instrument-ledger.md).
#
# D71 §2 R3 therefore mandates exactly one form for a gate:
#
#   test "$(minisign -Q -H -Vm "$art" -P "$KEY")" = "$EXPECTED_TRUSTED_COMMENT"
#
# `-Q` prints ONLY the trusted comment, which turns "a human should also read
# line 2" into a string equality that can go red. `-H` is mandatory: without
# it minisign accepts a legacy non-prehashed signature, a variant nothing in
# this project will ever produce (measured: a legacy signature verifies clean
# without `-H` and is refused with it).
#
# ── Where the expected comment comes from ─────────────────────────────────
#
# The trusted comment is `antseal <version> <basename> commit:<40-hex> <ts>`
# (D71 §2 R4). The caller supplies version and commit — they are what defeats
# a whole-release replay, and defaulting them would hand back the assertion
# that cannot fail. The timestamp is the one field a stranger cannot know in
# advance, so it is taken from the ONE signature that authenticates it: the
# manifest's. `SHA256SUMS.minisig` is checked first, its trusted comment is
# authenticated by `ed25519(<signature> || <trusted_comment>)`, and the
# timestamp read out of it then pins EXACT equality for every other artifact.
# Pass --timestamp to pin the manifest's too, when it is known out of band.
#
# ── What a green run does and does not mean ───────────────────────────────
#
# It means: the holder of this key released these bytes, under this version and
# this commit. It does not mean the software is safe, correct, or current, and
# it says nothing about whether the bytes match the published source — that is
# a reproducible build, which is a different check the CLI does not yet support
# (D71 §2 R10). See docs/signing/verifying-a-release.md.
set -uo pipefail

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m  FAIL[%s]\033[0m %s\n' "$1" "$2" >&2; }
die()  { printf '\033[31m::error::verify-release: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
verify-release.sh — check an antseal release directory (D71 §2 R3)

  scripts/verify-release.sh --version <v> --commit <40-hex> --dir <dir> --key <k>

Required:
  --version <v>       the release version you believe you downloaded
  --commit <40-hex>   the commit that release names
  --dir <dir>         the downloaded directory (artifacts + SHA256SUMS + *.minisig)
  --key <k>           the 56-character public key, or a path to minisign.pub

Options:
  --timestamp <ts>    pin the manifest's RFC3339 UTC timestamp too, when it is
                      known out of band. Without it the timestamp is taken from
                      the manifest's own authenticated trusted comment.
  --minisign <path>   the minisign binary. Default: whatever is on PATH.
  --self-test         plant every mutation D71 §1.3 measured and assert each is
                      caught BY ITS OWN distinct failure. Needs no network and
                      no project key; it generates a throwaway one in a temp
                      directory and deletes it.
  --help

Exit status is 0 only when every artifact verified, every trusted comment
matched exactly, and `sha256sum -c` passed.

NOTE on minisign's own exit codes: they are 0 on success, 1 on a failed
signature check, and 2 on malformed input (measured on 0.11 — a truncated
signature file exits 2). Do not write a check that asserts 1.
EOF
}

# Map minisign's own diagnostic to a distinct failure class. Each class is a
# DIFFERENT reachable failure, which is what makes the self-test below a tamper
# matrix rather than a smoke test.
classify() {
  case "$1" in
    *"Comment signature verification failed"*) printf 'trusted-comment' ;;
    *"Signature verification failed"*)         printf 'signature' ;;
    *"Legacy (non-prehashed) signature found"*) printf 'legacy' ;;
    *"key id in"*)                             printf 'key-id' ;;
    *"No such file or directory"*)             printf 'missing-sig' ;;
    *"base64 conversion failed"*)              printf 'bad-public-key' ;;
    *)                                         printf 'malformed' ;;
  esac
}

# One artifact. Returns 0 on a full match; on failure prints the class and the
# tool's own words. `-Q` suppresses minisign's diagnostics, so a failed check is
# re-run WITHOUT it purely to obtain the message — the verdict still comes from
# the quiet form's string equality.
verify_one() {
  local art="$1" want="$2" got rc msg
  got="$("$MINISIGN" -Q -H -Vm "$art" -P "$KEY" 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    msg="$("$MINISIGN" -H -Vm "$art" -P "$KEY" 2>&1)"
    bad "$(classify "$msg")" "$(basename -- "$art"): ${msg}"
    return 1
  fi
  if [ "$got" != "$want" ]; then
    # minisign said yes. This is D71 §1.3 row 6 — a replayed or cross-presented
    # artifact carrying a genuine signature — and the string equality is the
    # only thing standing here.
    bad "comment-mismatch" "$(basename -- "$art"): trusted comment is not this release's
        got:  ${got}
        want: ${want}"
    return 1
  fi
  ok "$(basename -- "$art")"
  return 0
}

# ---------------------------------------------------------------------------
# self-test — D71 §6.2's planted mutations
# ---------------------------------------------------------------------------
self_test() {
  local tmp rc=0 out cls
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local pw='selftest-throwaway-passphrase'
  # A THROWAWAY key, passphrase-protected — the form D71 §2 R7.1 requires, not
  # the `-W` form it forbids — generated inside mktemp -d and deleted on
  # return. It is never the project key and never leaves this directory.
  printf '%s\n%s\n' "$pw" "$pw" \
    | "$MINISIGN" -G -f -p "$tmp/st.pub" -s "$tmp/st.key" >/dev/null 2>&1 \
    || { printf 'self-test: could not generate a throwaway key pair\n' >&2; return 1; }
  local key; key="$(sed -n '2p' "$tmp/st.key" | tr -d '[:space:]')"
  # Prove the generated key is the encrypted form, so the fixture cannot
  # silently become the thing R7.1 forbids.
  local hex
  hex="$(printf '%s' "$key" | base64 -d 2>/dev/null | head -c 6 | od -An -tx1 | tr -d '[:space:]')"
  [ "${hex:4:4}" = "5363" ] \
    || { printf 'self-test: the throwaway key is not passphrase-wrapped (kdf=%s)\n' "${hex:4:4}" >&2; return 1; }
  KEY="$(sed -n '2p' "$tmp/st.pub" | tr -d '[:space:]')"

  local V=v0.2.0 C=2222222222222222222222222222222222222222 TS=2026-08-18T01:00:00Z
  local OV=v0.1.0 OC=1111111111111111111111111111111111111111 OTS=2026-08-18T00:00:00Z

  mkdir -p "$tmp/rel" "$tmp/old"
  printf 'antseal release v0.2.0 payload\n' > "$tmp/rel/antseal-x86_64-unknown-linux-gnu.tar.gz"
  printf 'antseal release v0.1.0 payload\n' > "$tmp/old/antseal-x86_64-unknown-linux-gnu.tar.gz"

  sign_fixture() { # dir version commit ts
    local d="$1" v="$2" c="$3" t="$4" f
    ( cd "$d" && sha256sum -- antseal-x86_64-unknown-linux-gnu.tar.gz > SHA256SUMS )
    for f in antseal-x86_64-unknown-linux-gnu.tar.gz SHA256SUMS; do
      printf '%s\n' "$pw" | "$MINISIGN" -S -s "$tmp/st.key" -m "$d/$f" -x "$d/$f.minisig" \
        -t "antseal $v $f commit:$c $t" >/dev/null 2>&1 || return 1
    done
  }
  sign_fixture "$tmp/rel" "$V" "$C" "$TS" || { printf 'self-test: fixture signing failed\n' >&2; return 1; }
  sign_fixture "$tmp/old" "$OV" "$OC" "$OTS" || { printf 'self-test: fixture signing failed\n' >&2; return 1; }

  # Every arm: a mutation, the class it MUST be caught by, and a description.
  # A `want` of `-` means the arm must PASS. Each arm runs a full verify over a
  # private copy of the release, so one arm cannot mask another.
  run_arm() { # name expected-class mutate-fn
    local name="$1" want="$2" fn="$3" d out got rc
    d="$tmp/arm"; rm -rf "$d"; cp -r "$tmp/rel" "$d"
    "$fn" "$d"
    out="$(verify_dir "$d" "$V" "$C" "" 2>&1)"; rc=$?
    if [ "$want" = "-" ]; then
      if [ "$rc" -eq 0 ]; then ok "self-test: $name -> ACCEPT (as required)"; return 0; fi
      bad "self-test" "$name: expected ACCEPT, got exit $rc
$out"; return 1
    fi
    if [ "$rc" -eq 0 ]; then
      bad "self-test" "$name: expected REJECT[$want], but the check PASSED — this arm is asleep"
      return 1
    fi
    got="$(printf '%s\n' "$out" | sed -n 's/.*FAIL\[\([a-z-]*\)\].*/\1/p' | head -1)"
    if [ "$got" != "$want" ]; then
      bad "self-test" "$name: expected REJECT[$want], got REJECT[${got:-<none>}]
$out"
      return 1
    fi
    ok "self-test: $name -> REJECT[$want] (as required)"
    return 0
  }

  m_none()    { :; }
  m_flip()    { printf 'X' | dd of="$1/antseal-x86_64-unknown-linux-gnu.tar.gz" bs=1 seek=3 conv=notrunc status=none; }
  m_comment() { sed -i 's/v0\.2\.0/v0.9.9/' "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig"; }
  m_replay()  { cp "$tmp/old/antseal-x86_64-unknown-linux-gnu.tar.gz" "$1/"; \
                cp "$tmp/old/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig" "$1/"; }
  m_nosig()   { rm -f "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig"; }
  m_trunc()   { head -c 40 "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig" > "$1/t" \
                && mv "$1/t" "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig"; }
  m_legacy()  { printf '%s\n' "$pw" | "$MINISIGN" -S -l -s "$tmp/st.key" \
                  -m "$1/antseal-x86_64-unknown-linux-gnu.tar.gz" \
                  -x "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig" \
                  -t "antseal $V antseal-x86_64-unknown-linux-gnu.tar.gz commit:$C $TS" >/dev/null 2>&1; }
  # The manifest still lists the ORIGINAL digest while the artifact and its
  # signature are both legitimately re-signed — only `sha256sum -c` can see it.
  m_sums()    { printf 'tampered payload\n' > "$1/antseal-x86_64-unknown-linux-gnu.tar.gz"
                printf '%s\n' "$pw" | "$MINISIGN" -S -s "$tmp/st.key" \
                  -m "$1/antseal-x86_64-unknown-linux-gnu.tar.gz" \
                  -x "$1/antseal-x86_64-unknown-linux-gnu.tar.gz.minisig" \
                  -t "antseal $V antseal-x86_64-unknown-linux-gnu.tar.gz commit:$C $TS" >/dev/null 2>&1; }

  note "self-test: 8 arms, each asserted by its OWN failure class"
  run_arm "clean release"              "-"               m_none    || rc=1
  run_arm "one data byte flipped"      "signature"       m_flip    || rc=1
  run_arm "trusted comment edited"     "trusted-comment" m_comment || rc=1
  run_arm "previous release replayed"  "comment-mismatch" m_replay || rc=1
  run_arm "signature file removed"     "missing-sig"     m_nosig   || rc=1
  run_arm "signature file truncated"   "malformed"       m_trunc   || rc=1
  run_arm "legacy non-prehashed sig"   "legacy"          m_legacy  || rc=1
  run_arm "manifest digest stale"      "sums"            m_sums    || rc=1

  # The substituted-key arm needs a DIFFERENT key, so it does not fit run_arm's
  # single-key shape. A second throwaway pair, and the release checked under it.
  printf '%s\n%s\n' "$pw" "$pw" \
    | "$MINISIGN" -G -f -p "$tmp/other.pub" -s "$tmp/other.key" >/dev/null 2>&1
  local savedkey="$KEY"
  KEY="$(sed -n '2p' "$tmp/other.pub" | tr -d '[:space:]')"
  out="$(verify_dir "$tmp/rel" "$V" "$C" "" 2>&1)"
  cls="$(printf '%s\n' "$out" | sed -n 's/.*FAIL\[\([a-z-]*\)\].*/\1/p' | head -1)"
  if [ "$cls" = "key-id" ]; then ok "self-test: attacker's key substituted -> REJECT[key-id] (as required)"
  else bad "self-test" "attacker's key substituted: expected REJECT[key-id], got REJECT[${cls:-<none>}]
$out"; rc=1; fi
  KEY="$savedkey"

  # A wrong --version must be caught even though every signature is genuine:
  # this is the whole-release replay, and it is why --version has no default.
  out="$(verify_dir "$tmp/rel" v9.9.9 "$C" "" 2>&1)"
  cls="$(printf '%s\n' "$out" | sed -n 's/.*FAIL\[\([a-z-]*\)\].*/\1/p' | head -1)"
  if [ "$cls" = "manifest-comment" ]; then
    ok "self-test: wrong --version -> REJECT[manifest-comment] (as required)"
  else
    bad "self-test" "wrong --version: expected REJECT[manifest-comment], got REJECT[${cls:-<none>}]
$out"; rc=1
  fi

  if [ "$rc" -eq 0 ]; then
    note "self-test: PASS — 10 arms, 9 distinct rejections and 1 required accept"
  else
    printf '\033[31m::error::verify-release: self-test FAILED\033[0m\n' >&2
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# the check itself
# ---------------------------------------------------------------------------
verify_dir() { # dir version commit timestamp-or-empty
  local dir="$1" version="$2" commit="$3" stamp="$4" rc=0
  local sums="$dir/SHA256SUMS" got msg ts want

  [ -f "$sums" ] || { bad "missing-manifest" "$dir has no SHA256SUMS"; return 1; }
  [ -f "$sums.minisig" ] || { bad "missing-sig" "$dir has no SHA256SUMS.minisig"; return 1; }

  # 1. The manifest's signature is checked FIRST: it is what authenticates the
  #    timestamp every other expected comment is built from.
  local mrc
  got="$("$MINISIGN" -Q -H -Vm "$sums" -P "$KEY" 2>/dev/null)"; mrc=$?
  if [ "$mrc" -ne 0 ]; then
    msg="$("$MINISIGN" -H -Vm "$sums" -P "$KEY" 2>&1)"
    bad "$(classify "$msg")" "SHA256SUMS: ${msg}"
    return 1
  fi

  if [ -n "$stamp" ]; then
    want="antseal ${version} SHA256SUMS commit:${commit} ${stamp}"
    if [ "$got" != "$want" ]; then
      bad "manifest-comment" "SHA256SUMS: trusted comment is not this release's
        got:  ${got}
        want: ${want}"
      return 1
    fi
    ts="$stamp"
  else
    # Everything except the timestamp is pinned by the caller; the timestamp is
    # then read out of the authenticated comment and required to be well-formed.
    local prefix="antseal ${version} SHA256SUMS commit:${commit} "
    case "$got" in
      "$prefix"*) ts="${got#"$prefix"}" ;;
      *) bad "manifest-comment" "SHA256SUMS: trusted comment is not this release's
        got:    ${got}
        want:   ${prefix}<RFC3339 UTC>"
         return 1 ;;
    esac
    case "$ts" in
      [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) : ;;
      *) bad "manifest-comment" "SHA256SUMS: the authenticated timestamp is not RFC3339 UTC: [${ts}]"
         return 1 ;;
    esac
  fi
  ok "SHA256SUMS (release timestamp ${ts}, signed)"

  # 2. Every artifact the manifest lists, by EXACT trusted-comment equality.
  local line name n=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name="$(printf '%s' "$line" | sed -E 's/^[0-9a-fA-F]{64}[ ]{1,2}[ *]?//')"
    [ -n "$name" ] || { bad "manifest-parse" "unparseable SHA256SUMS line: ${line}"; rc=1; continue; }
    if [ ! -f "$dir/$name" ]; then
      bad "missing-artifact" "$name is listed in SHA256SUMS but is not in $dir"; rc=1; continue
    fi
    verify_one "$dir/$name" "antseal ${version} ${name} commit:${commit} ${ts}" || rc=1
    n=$((n + 1))
  done < "$sums"
  [ "$n" -gt 0 ] || { bad "manifest-parse" "SHA256SUMS lists no artifacts"; return 1; }

  # 3. The bulk digest check (D71 §2 R3). It is the arm that catches an
  #    artifact whose signature is genuine but whose bytes no longer match the
  #    manifest the maintainer signed.
  local sr60
  msg="$(cd "$dir" && sha256sum -c --quiet SHA256SUMS 2>&1)"; sr60=$?
  if [ "$sr60" -ne 0 ] || [ -n "$msg" ]; then
    bad "sums" "sha256sum -c SHA256SUMS: ${msg:-mismatch}"
    rc=1
  else
    ok "sha256sum -c SHA256SUMS (${n} artifact(s))"
  fi

  return "$rc"
}

# ---------------------------------------------------------------------------
version=""; commit=""; dir=""; keyarg=""; stamp=""; MINISIGN=""; selftest=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   version="${2:-}"; shift 2 || die "--version needs a value" ;;
    --commit)    commit="${2:-}"; shift 2 || die "--commit needs a value" ;;
    --dir)       dir="${2:-}"; shift 2 || die "--dir needs a value" ;;
    --key)       keyarg="${2:-}"; shift 2 || die "--key needs a value" ;;
    --timestamp) stamp="${2:-}"; shift 2 || die "--timestamp needs a value" ;;
    --minisign)  MINISIGN="${2:-}"; shift 2 || die "--minisign needs a value" ;;
    --self-test) selftest=1; shift ;;
    --help|-h)   usage; exit 0 ;;
    *)           usage >&2; die "unknown argument: $1" ;;
  esac
done

if [ -z "$MINISIGN" ]; then
  MINISIGN="$(command -v minisign 2>/dev/null || true)"
fi
[ -n "$MINISIGN" ] && [ -x "$MINISIGN" ] || die \
  "no minisign binary found. Get it from an archive independent of this project's own hosting:
    Debian/Ubuntu  apt install minisign
    macOS          brew install minisign
    Windows        scoop install minisign
  or pass --minisign <path>. Obtaining the TOOL from somewhere other than this project is the
  point — see docs/signing/verifying-a-release.md."

if [ "$selftest" -eq 1 ]; then
  KEY=""
  self_test
  exit $?
fi

[ -n "$version" ] || { usage >&2; die "--version is required — a default would make a whole-release replay invisible"; }
[ -n "$commit" ]  || { usage >&2; die "--commit is required"; }
[ -n "$dir" ]     || { usage >&2; die "--dir is required"; }
[ -n "$keyarg" ]  || { usage >&2; die "--key is required"; }
[ -d "$dir" ]     || die "--dir is not a directory: $dir"

if [ -f "$keyarg" ]; then
  KEY="$(sed -n '2p' -- "$keyarg" | tr -d '[:space:]')"
else
  KEY="$(printf '%s' "$keyarg" | tr -d '[:space:]')"
fi
[ "${#KEY}" -eq 56 ] || die \
  "--key is not a 56-character public key (got ${#KEY} characters). A minisign public key is 42
  bytes -> exactly 56 base64 characters and begins RW."
case "$KEY" in RW*) : ;; *) die "--key does not begin with RW — that is not a minisign public key" ;; esac

if [ -n "$stamp" ]; then
  case "$stamp" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) : ;;
    *) die "--timestamp must be RFC3339 UTC, e.g. 2026-08-18T12:00:00Z (got: $stamp)" ;;
  esac
fi

note "minisign: $MINISIGN ($("$MINISIGN" -v 2>&1 | head -1))"
note "checking $dir against ${version} commit:${commit}"
if verify_dir "$dir" "$version" "$commit" "$stamp"; then
  printf '\033[32m==> VERIFIED\033[0m %s: every artifact carries a signature by the key you supplied,\n' "$dir"
  printf '    under version %s and commit %s.\n' "$version" "$commit"
  printf '    That is what a signature attests, and it is all it attests. It is not a statement\n'
  printf '    that the software is safe, correct or current, and it does not show that these bytes\n'
  printf '    match the published source. See docs/signing/verifying-a-release.md.\n'
  exit 0
fi
die "verification FAILED for $dir — do not run these artifacts"
