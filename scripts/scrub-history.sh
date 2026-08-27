#!/usr/bin/env bash
# A REPEATABLE credential scan over every object this repository has ever
# held — because the only history scrub on file is a document with a date on
# it, and a dated document rots the moment the next commit lands.
#
# WHY THIS EXISTS, AND WHY A SCRIPT RATHER THAN A SECOND DOCUMENT
# ---------------------------------------------------------------
# Making the repository public publishes GIT HISTORY, not a worktree. That is
# D161's measured finding, and it is the whole reason this file is about the
# object store rather than the checkout.
#
# The one history-wide scrub this project has ever run,
# `docs/reviews/pre-public-scrub-history.md`, was measured on 2026-08-16 over
# 7935 objects (3450 blob / 3670 tree / 813 commit / 2 tag). Nothing re-runs
# it. By the time this script was written the store held 8439 — +504 objects
# and +299 blobs that no scan had ever looked at, across three waves of work.
# A second dated document would only move the date; the gap reopens on the
# next commit either way.
#
# Nor does the existing guard close it. `secret-guard` (`lane_secret_guard()`
# in `scripts/ci-lanes.sh`) is a WORKTREE scan and says so in its own flags:
# it passes `--exclude-dir=.git`, so a blob that was committed and later
# deleted is not in its subject at all. It is also not wired into
# `scripts/local-gate.sh`. The two checks are complements, not duplicates —
# the guard stops a secret being committed TODAY, this stops one that was
# committed and forgotten being PUBLISHED.
#
# WHAT IT SCANS: THE SUPERSET, AND THE PROOF THAT IT IS ONE
# ----------------------------------------------------------
# `git cat-file --batch-all-objects` enumerates the object store itself, so
# it reaches unreachable and dangling objects — the ones `git log` cannot
# show you and a worktree scan cannot see. That claim is not taken on trust:
# every run ASSERTS the reachability arithmetic
#
#     total objects - reachable objects == `git fsck` unreachable count
#
# and refuses to report a verdict if it does not balance. `--self-test`
# additionally plants a fixture in a DANGLING blob that is never committed,
# and requires it to come back — so "the superset really is a superset" is a
# measurement in every self-test run rather than a property of a flag name.
#
# READ-ONLY, IN TERMS
# -------------------
# This script NEVER rewrites history, moves a ref, deletes an object, runs a
# gc, or changes any git setting. It runs `cat-file`, `rev-list`, `fsck`,
# `for-each-ref` and `rev-parse` against the repository, and `hash-object -w`
# / `commit` only inside a throwaway repository under `mktemp -d` during
# `--self-test`. It never revokes, rotates or tests a credential. It REPORTS.
# Remediating a finding is a maintainer act and deliberately not automated:
# the answer to "there is a key in history" is a decision, not a command.
#
# THE `*.md` EXCLUSION IS DELIBERATELY NOT INHERITED
# --------------------------------------------------
# `secret-guard`'s `ex()` passes `--exclude='*.md'`. The 2026-08-16 scrub
# measured that hole rather than assuming it — Markdown is 1053 of the 3367
# reachable blob paths, ~31% of everything ever committed, and it is where
# secret-shaped strings already cluster. D161 records the exclusion as "a
# measured blind spot this record inherits rather than closes". History is
# exactly where it matters, so NOTHING is excluded here: not `*.md`, not
# `ci-lanes.sh`, not the one `export.rs` path the guard exempts. The cost is
# that a handful of known-benign documentary hits come back on every run;
# they are resolved by name in the review record rather than hidden by a
# filter, because a filter that hides a known hit also hides an unknown one.
#
# WHY THIS FILE CONTAINS NO SECRET-SHAPED LITERAL
# -----------------------------------------------
# Every self-test fixture is ASSEMBLED AT RUN TIME from pieces, so no string
# in this file matches any rule in this file. That is not decoration. Two
# things depend on it:
#
#   1. `secret-guard` scans the worktree and exempts exactly one basename,
#      `ci-lanes.sh`. A literal fake key here would red that lane, and the
#      only fix inside this file's write scope would be to weaken the fixture.
#   2. Committing a literal fake key poisons EVERY FUTURE RUN OF THIS SCRIPT,
#      permanently, because history is append-only. The 2026-08-16 scrub kept
#      its detector and its 44 fakes in uncommitted scratch space for exactly
#      this reason, and the review document that quotes them as evidence is
#      itself a standing hit today.
#
# The self-test asserts the property instead of trusting this paragraph: a
# copy of this script is planted as a NEGATIVE control, and the run fails if
# the scanner reports its own source.
#
# DETECTION CLASSES
# -----------------
# R1..R5 mirror `lane_secret_guard()`'s `scan()` rule for rule, in its order,
# with its patterns. E1..E4 are ADDITIONS, marked as such wherever they
# appear, drawn from the gaps the 2026-08-16 scrub measured and named:
#
#   E1  PGP private-key blocks. `secret-guard`'s R1 pattern requires the
#       closing dashes immediately after `PRIVATE KEY`, so a PGP block header
#       does not match it. Measured as Gap 1 by that scrub and still open.
#   E2  Forge tokens (GitHub personal / OAuth / server / fine-grained).
#   E3  AWS access key ids.
#   E4  Slack tokens.
#
# E2-E4 were measured at ZERO occurrences across all 3450 blobs on
# 2026-08-16, so they add coverage without adding resolution burden; they are
# the classes a pasted credential most often takes, and history is where a
# paste survives a `git rm`. Nothing from `secret-guard` was DROPPED.
#
# WHAT THIS DOES NOT DO. It is signature-based over plaintext: a secret
# inside a base64 blob, an archive or an encrypted file will not match, and
# there is no entropy heuristic and no BIP39 wordlist check. It reads git
# only — GitHub-side artifacts (issues, Actions logs, gists, releases) are
# outside the object store and outside this script.
#
# Usage:
#   scripts/scrub-history.sh                 scan every object in the store
#   scripts/scrub-history.sh --since <rev>   scan only what <rev> did not have
#   scripts/scrub-history.sh --self-test     prove every rule can fire
#   scripts/scrub-history.sh --help
#
# `--since <rev>` scans the object store MINUS everything reachable from
# <rev>. That is a SUPERSET of "introduced after <rev>": it also re-includes
# objects that already existed at <rev> on other branches or as unreachable
# junk. The superset is the safe direction for a scrub and is stated in the
# record rather than tuned away.
#
# Exit: 0 clean · 1 finding, malformed input, or a failed invariant. Prints
# one machine-readable `SCRUB_HISTORY ...` summary line as its last line in
# every mode. No network.
set -euo pipefail

# ── The rule register ──────────────────────────────────────────────────────
#
# Declared ONCE, here, and cross-checked against the live body of
# `rules_scan` below. `--self-test` counts the `hits+=` lines in that
# function off `declare -f` and refuses to run if the number differs from
# `${#RULE_IDS[@]}`, then refuses again if any id in this list has no
# fixture. That is the pair of assertions this project learned to write the
# hard way: a rule nobody wrote a fixture for is never exercised, and every
# total still balances (see the Q245 note in `scripts/ci-lanes.sh`).
#
# Ids are the paper trail into `secret-guard`: R1-R5 and R4a/R4b/R4c are that
# lane's own numbering, kept identical so a reader can diff the two rule sets
# by eye. E1-E4 are additions and their ids say so.
RULE_IDS=(R1 R2 R3 R4a R4b R4c R5 E1 E2 E3 E4)
rule_desc() {
  case "$1" in
    R1)  printf 'PEM private-key block (RSA/EC/plain/OPENSSH/ENCRYPTED)\n' ;;
    R2)  printf 'EVM keystore JSON — both web3-secret-storage keys in one object\n' ;;
    R3)  printf 'reserved antseal vault-export magic\n' ;;
    R4a) printf 'age secret-key marker\n' ;;
    R4b) printf 'minisign/rsign secret-key header comment\n' ;;
    R4c) printf 'minisign/rsign secret-key BODY type tag (both kdf_alg arms)\n' ;;
    R5)  printf 'devnet wallet-key export line with a 64-hex value\n' ;;
    E1)  printf '[ADDED] PGP private-key block — the flavour R1 cannot match\n' ;;
    E2)  printf '[ADDED] forge token (personal / OAuth / server / fine-grained)\n' ;;
    E3)  printf '[ADDED] AWS access key id\n' ;;
    E4)  printf '[ADDED] Slack token\n' ;;
    *)   printf 'UNREGISTERED RULE ID\n' ;;
  esac
}

# Apply every rule to a materialised corpus directory. Emits one
# `<rule-id><TAB><object-name>` line per (rule, object) hit, sorted and
# deduplicated. Never exits non-zero: the caller decides what a hit means.
#
# The `ex()` helper is `lane_secret_guard()`'s, minus every `--exclude`. The
# corpus is one file per object NAMED BY ITS OBJECT ID, so `grep -rl` already
# attributes each hit to an object and no exclusion could apply to a filename
# anyway. `-a` is what makes a binary blob scannable rather than skipped.
#
# Each pattern below is written with a character class in the position that
# would otherwise make this file match itself — `[-]{5}` for the PEM dashes,
# `[t]` inside `ciphertext`, `[y]` at the end of the base64 type tags, and so
# on. That is `secret-guard`'s own idiom and it is load-bearing here for the
# reason the header gives: this file gets committed, and a self-matching
# scanner reports itself for the rest of the repository's life.
rules_scan() {
  local root="${1%/}" hits="" a b
  ex() { grep -rlaE -e "$1" "$root" || true; }
  tg() {
    local id="$1" f
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      printf '%s\t%s\n' "$id" "${f#"$root/"}"
    done
  }
  # (R1) PEM private-key blocks, any flavour whose label ends at the dashes.
  hits+="$(ex '[-]{5}BEGIN[ A-Z0-9]*PRIVATE KEY[-]{5}' | tg R1)"$'\n'
  # (R2) EVM keystore JSON: a conjunction, so both signature keys must appear
  #      in the SAME object. `comm` needs sorted inputs and empty lists are
  #      normal, so both sides are emptied of blank lines first.
  a="$(ex '"cipher[t]ext"' | grep -v '^[[:space:]]*$' | sort -u || true)"
  b="$(ex '"kdf[p]arams"'  | grep -v '^[[:space:]]*$' | sort -u || true)"
  hits+="$(comm -12 <(printf '%s\n' "$a" | grep -v '^[[:space:]]*$' || true) \
                    <(printf '%s\n' "$b" | grep -v '^[[:space:]]*$' || true) | tg R2)"$'\n'
  # (R3) The reserved vault-export magic. `secret-guard` exempts the one
  #      source file that DEFINES the constant, by exact path; there is no
  #      path here and the exemption is not reproduced — see the header.
  hits+="$(ex 'ANTSEAL[ ]VAULT[ ]EXPORT' | tg R3)"$'\n'
  # (R4a) age secret-key marker.
  hits+="$(ex 'AGE[-]SECRET[-]KEY[-]1' | tg R4a)"$'\n'
  # (R4b) minisign/rsign secret-key header comment, anchored to the comment
  #       PREFIX so that a signature — which carries `signature from …` in the
  #       same field — is not reported as key material.
  hits+="$(ex 'untrusted[ ]comment:[ ](minisign|rsign)([ ]encrypted)?[ ]secret[ ]key' | tg R4b)"$'\n'
  # (R4c) minisign/rsign secret-key BODY: the first six bytes of the key
  #       struct, which land on exactly eight base64 characters. Both kdf_alg
  #       arms — unencrypted (`00 00`) and passphrase-wrapped (`Sc`).
  hits+="$(ex 'RWQAAEI[y]|RWRTY0I[y]' | tg R4c)"$'\n'
  # (R5) A committed devnet environment export: the key NAME followed by an
  #      actual 64-hex value, so prose naming the variable stays green.
  hits+="$(ex "ANTSEAL[_]DEVNET[_]WALLET[_]PRIVATE[_]KEY[[:space:]]*=[[:space:]]*'?(0x)?[0-9a-fA-F]{64}" | tg R5)"$'\n'
  # (E1) ADDED. The PGP flavour, and disjoint from R1 by construction: it
  #      REQUIRES at least one more label character after `PRIVATE KEY`, which
  #      is precisely the position R1's trailing `[-]{5}` forbids. Written
  #      that way so a hit can only be a block R1 missed, never a duplicate.
  hits+="$(ex '[-]{5}BEGIN[ A-Z0-9]*PRIVATE KEY[ A-Z0-9]+[-]{5}' | tg E1)"$'\n'
  # (E2) ADDED. Forge tokens. Classic tokens are a 3-letter kind, an
  #      underscore and 36 base62; fine-grained ones carry a longer body.
  hits+="$(ex '(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30}' | tg E2)"$'\n'
  # (E3) ADDED. AWS access key ids: long-term (AKIA) and temporary (ASIA).
  hits+="$(ex '(AKIA|ASIA)[0-9A-Z]{16}' | tg E3)"$'\n'
  # (E4) ADDED. Slack bot/user/app/refresh/legacy tokens.
  hits+="$(ex 'xox[baprs][-][0-9A-Za-z]{8,}' | tg E4)"$'\n'
  printf '%s\n' "$hits" | grep -v '^[[:space:]]*$' | sort -u || true
}

# ── Read-only git plumbing ─────────────────────────────────────────────────
err()  { printf '::error::scrub-history: %s\n' "$*" >&2; }
note() { printf '%s\n' "$*"; }

# Globals the scan driver fills in, read back by the summary line. Declared
# here so `set -u` catches a path that forgets to set one.
SC_TOTAL=0 SC_BLOB=0 SC_TREE=0 SC_COMMIT=0 SC_TAG=0
SC_REACHABLE=0 SC_UNREACHABLE=0
SC_SCANNED=0 SC_BYTES=0 SC_FINDINGS=0

# The invariant that makes "superset" a measurement instead of a claim.
# ASSERTED, not printed: a scan whose corpus is not provably the whole store
# is a scan whose clean verdict means nothing, so it must not be able to
# report one. Returns 1 and names both numbers when it does not balance.
assert_reachability() {
  local repo="$1" inv="$2" tmp="$3" delta
  SC_TOTAL="$(grep -c . "$inv" || true)"
  SC_BLOB="$(awk '$2=="blob"'   "$inv" | grep -c . || true)"
  SC_TREE="$(awk '$2=="tree"'   "$inv" | grep -c . || true)"
  SC_COMMIT="$(awk '$2=="commit"' "$inv" | grep -c . || true)"
  SC_TAG="$(awk '$2=="tag"'     "$inv" | grep -c . || true)"
  # `--reflog` matters: an object kept alive only by a reflog entry is
  # reachable to git and would otherwise land on the wrong side of the
  # subtraction. Deduplicated because one blob appears once per path.
  git -C "$repo" rev-list --all --reflog --objects 2>/dev/null \
    | awk '{print $1}' | sort -u > "$tmp/reachable.txt" || true
  SC_REACHABLE="$(grep -c . "$tmp/reachable.txt" || true)"
  git -C "$repo" fsck --unreachable --dangling --no-progress \
    > "$tmp/fsck.txt" 2>/dev/null || true
  SC_UNREACHABLE="$(grep -c '^unreachable ' "$tmp/fsck.txt" || true)"
  delta=$(( SC_TOTAL - SC_REACHABLE ))
  if [ "$delta" -ne "$SC_UNREACHABLE" ]; then
    err "reachability arithmetic does not balance: ${SC_TOTAL} objects in the store" \
        "minus ${SC_REACHABLE} reachable is ${delta}, but git fsck reports ${SC_UNREACHABLE}" \
        "unreachable. Until those agree there is no evidence that the corpus below is the" \
        "whole object store, so no clean verdict can be trusted. Do not paper over this by" \
        "widening the corpus — find out which enumeration is wrong."
    return 1
  fi
  return 0
}

# One file per object, named by object id, under a 0700 temp directory.
#
# WHY MATERIALISE AT ALL. It buys exact per-object attribution from a plain
# `grep -rl`, so the rules above are byte-for-byte the shape `secret-guard`
# runs and a reader can compare them without holding a stream parser in their
# head. Trees are skipped: they carry no free text, and the filenames they
# hold reach this corpus anyway as part of every commit that names them.
#
# The cost is honest and worth stating: on a hit, secret material is written
# to the temp directory. `mktemp -d` is 0700 and the RETURN trap removes it.
materialise() {
  local repo="$1" inv="$2" corpus="$3" sha type size
  SC_SCANNED=0 SC_BYTES=0
  while read -r sha type size; do
    case "$type" in
      blob|commit|tag) ;;
      *) continue ;;
    esac
    git -C "$repo" cat-file "$type" "$sha" > "$corpus/$sha" 2>/dev/null || : > "$corpus/$sha"
    SC_SCANNED=$(( SC_SCANNED + 1 ))
    SC_BYTES=$(( SC_BYTES + size ))
  done < "$inv"
}

# Every path an object has ever been stored at, or a marker when it has none.
# An unreachable blob genuinely has no path — saying so is the finding, not a
# gap in it.
object_paths() {
  local sha="$1" map="$2" out
  out="$(awk -v s="$sha" '$1==s && NF>1 {sub(/^[^ ]+ /,""); print}' "$map" | sort -u | paste -sd'|' -)"
  printf '%s' "${out:-(no path — unreachable or tree-less object)}"
}

# ── The scan driver ────────────────────────────────────────────────────────
#
# `scan_repo <repo> <mode> [<since-rev>]`, where mode is `full` or `since`.
# Fills the SC_* globals, prints the per-object findings and the per-rule
# tally, and returns 1 if anything was found. The summary line is the
# caller's, so that every mode — including `--self-test` — emits exactly one.
scan_repo() {
  local repo="$1" mode="$2" since="${3:-}"
  local tmp corpus inv rule sha type paths n
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  corpus="$tmp/corpus"
  mkdir -p "$corpus"
  inv="$tmp/all.tsv"

  git -C "$repo" cat-file --batch-all-objects \
      --batch-check='%(objectname) %(objecttype) %(objectsize)' > "$inv"
  assert_reachability "$repo" "$inv" "$tmp" || return 1

  if [ "$mode" = since ]; then
    if ! git -C "$repo" rev-parse --verify --quiet "$since^{commit}" >/dev/null; then
      err "--since: \`$since\` does not resolve to a commit in this repository."
      return 1
    fi
    git -C "$repo" rev-list --objects "$since" | awk '{print $1}' | sort -u > "$tmp/base.txt"
    sort -k1,1 "$inv" > "$tmp/all.sorted"
    join -v1 -1 1 -2 1 "$tmp/all.sorted" "$tmp/base.txt" > "$tmp/corpus.tsv"
    note "mode: --since $(git -C "$repo" rev-parse --short "$since") — the object store MINUS everything reachable from that commit."
    note "     (a SUPERSET of \"introduced since\": objects that already existed elsewhere at that point are re-scanned, which is the safe direction.)"
  else
    cp "$inv" "$tmp/corpus.tsv"
    note "mode: full — every object in the store, reachable or not."
  fi

  materialise "$repo" "$tmp/corpus.tsv" "$corpus"
  note "store:  ${SC_TOTAL} objects (${SC_BLOB} blob / ${SC_TREE} tree / ${SC_COMMIT} commit / ${SC_TAG} tag)"
  note "        ${SC_REACHABLE} reachable + ${SC_UNREACHABLE} unreachable — arithmetic asserted, not printed on trust."
  note "corpus: ${SC_SCANNED} objects, ${SC_BYTES} bytes, ${#RULE_IDS[@]} rules, no exclusions (not \`*.md\`, not \`.git\`, not this script)."

  rules_scan "$corpus" > "$tmp/hits.tsv" || true
  SC_FINDINGS="$(grep -c . "$tmp/hits.tsv" || true)"
  if [ "$SC_FINDINGS" -eq 0 ]; then
    note "FINDINGS: none."
    return 0
  fi

  git -C "$repo" rev-list --all --reflog --objects > "$tmp/paths.txt" 2>/dev/null || : > "$tmp/paths.txt"
  note "FINDINGS: ${SC_FINDINGS} (rule, object, type, every path the object was ever stored at)"
  while IFS=$'\t' read -r rule sha; do
    [ -n "${sha:-}" ] || continue
    type="$(awk -v s="$sha" '$1==s{print $2}' "$inv")"
    paths="$(object_paths "$sha" "$tmp/paths.txt")"
    printf 'HIT\t%s\t%s\t%s\t%s\n' "$rule" "$sha" "${type:-?}" "$paths"
  done < "$tmp/hits.tsv"
  note "per-rule tally:"
  for rule in "${RULE_IDS[@]}"; do
    n="$(awk -F'\t' -v r="$rule" '$1==r' "$tmp/hits.tsv" | grep -c . || true)"
    printf '  %-4s %5s  %s\n' "$rule" "$n" "$(rule_desc "$rule")"
  done
  return 1
}

# ── --self-test ────────────────────────────────────────────────────────────
#
# A detection rule with no fixture is never exercised, and every total still
# balances without it. That is this project's dominant defect class, and it
# has already happened once inside `secret-guard` itself, where one rule arm
# went unexercised for the guard's entire life because a neighbouring
# fixture filled its slot in the arithmetic. So this self-test:
#
#   * builds a REAL throwaway git repository under `mktemp -d` and drives the
#     same `scan_repo` the verdict comes from — not a stub, not a re-implementation;
#   * plants ONE fixture per registered rule id and requires each to come
#     back UNDER ITS OWN ID, so one rule cannot cover for another;
#   * plants one fixture as a DANGLING blob that is never committed, so
#     "the corpus reaches unreachable objects" is measured every run;
#   * plants NEGATIVE controls, including a verbatim copy of this script,
#     and fails if any of them is reported;
#   * asserts the rule COUNT off the live function body against the
#     registered id list, so a rule cannot be added without a fixture;
#   * exercises `--since` in both directions — once where the delta must
#     contain every fixture, once where it must contain only the dangling
#     blob — because a delta mode that silently scanned everything, or
#     nothing, would pass every other assertion here.
#
# NO FIXTURE IS A LITERAL. Each is assembled from pieces at run time, for the
# reason the header gives: this file is committed, and history is forever.
# The negative control that is a copy of this script is what turns that from
# a promise into an assertion.
self_test() {
  local tmp repo A B out rules i n fail=0
  local d5='-----' sp=' ' dh='-' a64 a36 a16
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  repo="$tmp/repo"
  mkdir -p "$repo"
  git -c init.defaultBranch=main init -q "$repo"

  # ---- negative controls, committed first so they are reachable from A ----
  # Prose that names every tool without carrying a marker. `secret-guard`'s
  # own history shows why this control exists: an unanchored pattern reported
  # every sentence that merely mentioned a secret key.
  printf '%s\n' \
    'The maintainer holds the release signing key offline; it never enters the checkout.' \
    'No age, minisign or rsign secret key is committed to this repository.' \
    'The devnet wallet key lives in a gitignored .devnet/env and nowhere else.' > "$repo/control-prose.txt"
  # The two near misses that would otherwise be found in production: a
  # minisign PUBLIC key whose all-zero keynum shares five leading base64
  # characters with the unencrypted secret-key type tag, and a SIGNATURE
  # header line. Both are safe to write as literals here, and that is itself
  # the point — R4b is anchored to the comment PREFIX, and `signature from`
  # is not a tool name, so neither string can match a rule in this file.
  printf '%s\n' \
    'untrusted comment: minisign public key 0000000000000000' \
    'RWQAAAAAAAAAAO7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u' \
    'untrusted comment: signature from minisign secret key' \
    'untrusted comment: signature from rsign secret key' > "$repo/control-near-miss.txt"
  # THE control: this scanner's own source. If any pattern in this file
  # matches any literal in this file, the scanner reports itself on every run
  # over this repository from the day it is committed, forever. This is the
  # assertion that stops that shipping.
  cp "${BASH_SOURCE[0]}" "$repo/control-scrubber.sh"
  git -C "$repo" add -A
  git -C "$repo" -c user.name=fixture -c user.email=fixture@example.invalid \
      -c commit.gpgsign=false commit -q -m 'self-test commit A: negative controls only'
  A="$(git -C "$repo" rev-parse HEAD)"

  # ---- one fixture per registered rule id, all assembled at run time ----
  a64="$(printf 'a%.0s' $(seq 64))"
  a36="$(printf 'A%.0s' $(seq 36))"
  a16='ABCDEFGHIJKLMNOP'
  local -a fix_rule=() fix_file=()
  add_fixture() { fix_rule+=("$1"); fix_file+=("$2"); }

  printf '%sBEGIN EC PRIVATE KEY%s\nAAAA\n%sEND EC PRIVATE KEY%s\n' "$d5" "$d5" "$d5" "$d5" \
    > "$repo/fx-pem.txt"                     ; add_fixture R1  fx-pem.txt
  printf '{"version":3,"crypto":{"cipher%sext":"00","kdf%sarams":{"n":1},"mac":"00"}}\n' 't' 'p' \
    > "$repo/fx-keystore.json"               ; add_fixture R2  fx-keystore.json
  printf 'ANTSEAL%sVAULT%sEXPORT v0 scrub-history self-test\n' "$sp" "$sp" \
    > "$repo/fx-vault-export.bin"            ; add_fixture R3  fx-vault-export.bin
  printf 'AGE%sSECRET%sKEY%s1SELFTESTSELFTESTSELFTEST\n' "$dh" "$dh" "$dh" \
    > "$repo/fx-age.key"                     ; add_fixture R4a fx-age.key
  printf 'untrusted comment: minisign%sencrypted secret key\n(body elided: this fixture exercises the header arm only)\n' "$sp" \
    > "$repo/fx-minisign-header.key"         ; add_fixture R4b fx-minisign-header.key
  printf 'untrusted comment: antseal release signing key\nRWQAAEI%s%s\n' 'y' "$a36" \
    > "$repo/fx-minisign-body.key"           ; add_fixture R4c fx-minisign-body.key
  printf 'ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=%s\n' "$a64" \
    > "$repo/fx-devnet-env"                  ; add_fixture R5  fx-devnet-env
  printf '%sBEGIN PGP PRIVATE KEY BLOCK%s\nAAAA\n' "$d5" "$d5" \
    > "$repo/fx-pgp.asc"                     ; add_fixture E1  fx-pgp.asc
  printf 'token: ghp%s%s\n' '_' "$a36" \
    > "$repo/fx-forge-token.txt"             ; add_fixture E2  fx-forge-token.txt
  printf 'aws_access_key_id = AKIA%s\n' "$a16" \
    > "$repo/fx-aws.txt"                     ; add_fixture E3  fx-aws.txt
  printf 'slack: xox%s%s%s\n' 'b' '-' '111111111111-ABCDEFGHIJKLMNOPQRSTUVWX' \
    > "$repo/fx-slack.txt"                   ; add_fixture E4  fx-slack.txt

  # ---- the coupling assertions, BEFORE any scan is trusted ----
  rules="$(declare -f rules_scan | grep -c 'hits[+]=')" || true
  if [ "$rules" -ne "${#RULE_IDS[@]}" ]; then
    err "self-test FAILED: rules_scan carries ${rules} detection rules, but RULE_IDS registers" \
        "${#RULE_IDS[@]}. A rule with no registered id gets no fixture, is never exercised, and" \
        "every total still balances — add the id AND its fixture in the same act."
    return 1
  fi
  # WHY HERE-STRINGS AND NOT `printf ... | grep -q`. This self-test's FIRST run
  # failed here, intermittently, on a rule whose fixture was plainly present.
  # `grep -q` exits the instant it matches; the `printf` upstream of it then
  # takes SIGPIPE, and under `set -o pipefail` the pipeline's status is that
  # signal, not grep's zero — so a SUCCESSFUL lookup takes the `||` branch and
  # reports a missing fixture. It is a race, so it passes most of the time,
  # which is the worst possible shape for an assertion. A here-string is a
  # file: nothing to signal, nothing to race.
  local ids fixids
  ids="$(printf '%s\n' "${RULE_IDS[@]}")"
  fixids="$(printf '%s\n' "${fix_rule[@]}")"
  for i in "${RULE_IDS[@]}"; do
    grep -qxF "$i" <<<"$fixids" || {
      err "self-test FAILED: rule id ${i} is registered but has no fixture, so nothing ever" \
          "proves it can fire. Plant one."
      fail=1
    }
  done
  for i in "${fix_rule[@]}"; do
    grep -qxF "$i" <<<"$ids" || {
      err "self-test FAILED: fixture claims rule id ${i}, which RULE_IDS does not register."
      fail=1
    }
  done
  [ "$fail" -eq 0 ] || return 1

  git -C "$repo" add -A
  git -C "$repo" -c user.name=fixture -c user.email=fixture@example.invalid \
      -c commit.gpgsign=false commit -q -m 'self-test commit B: one planted fixture per rule'
  B="$(git -C "$repo" rev-parse HEAD)"

  # The dangling fixture: written into the object store and never referenced
  # by any tree, commit or ref. `git log` cannot reach it; a worktree scan
  # cannot see it; `--batch-all-objects` must.
  local dangling
  dangling="$(printf 'ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=%s\n' "$(printf 'b%.0s' $(seq 64))" \
              | git -C "$repo" hash-object -w --stdin)"

  # ---- the three arms ----
  # `expect_hits <label> <expected-count> <"rule:sha" ...>` runs a scan,
  # requires EVERY named pair to be present AND the total to match, so a
  # scan that reported everything would fail just as loudly as one that
  # reported nothing.
  local arm_fail=0
  expect_hits() {
    local label="$1" want="$2"; shift 2
    local got want_list pair missing="" extra=""
    got="$(awk -F'\t' '$1=="HIT"{print $2":"$3}' <<<"$OUT" | sort -u)"
    want_list="$(printf '%s\n' "$@")"
    # Here-strings throughout, for the SIGPIPE-under-pipefail reason recorded
    # at the coupling assertions above.
    for pair in "$@"; do
      grep -qxF "$pair" <<<"$got" || missing+=" $pair"
    done
    while IFS= read -r pair; do
      [ -n "$pair" ] || continue
      grep -qxF "$pair" <<<"$want_list" || extra+=" $pair"
    done <<<"$got"
    local n; n="$(grep -c . <<<"$got" || true)"
    if [ -n "$missing" ] || [ -n "$extra" ] || [ "$n" -ne "$want" ]; then
      err "self-test arm [${label}] FAILED: expected ${want} hits, got ${n}." \
          "Rule/object pairs that did NOT fire:${missing:- (none)}." \
          "Objects reported that are not fixtures:${extra:- (none)}." \
          "A missing pair is a rule that cannot detect its own planted secret;" \
          "an extra one is a false positive, and if it is control-scrubber.sh then" \
          "this script now matches itself and will do so in history forever."
      sed 's/^/    | /' <<<"$OUT"
      arm_fail=1
      return 1
    fi
    note "arm [${label}] OK: ${n}/${want} expected hits, every rule fired under its own id, no control reported."
    return 0
  }

  # The full expected set: one object per rule, plus the dangling blob under
  # R5. The dangling blob is the ONE case where two fixtures share a rule id,
  # and it is named here rather than folded into the count so that losing it
  # is a distinguishable failure rather than an off-by-one.
  local -a want_full=()
  for i in "${!fix_rule[@]}"; do
    want_full+=("${fix_rule[$i]}:$(git -C "$repo" hash-object "$repo/${fix_file[$i]}")")
  done
  want_full+=("R5:$dangling")

  OUT="$(scan_repo "$repo" full 2>&1)" || true
  expect_hits 'full scan' "${#want_full[@]}" "${want_full[@]}" || true

  OUT="$(scan_repo "$repo" since "$A" 2>&1)" || true
  expect_hits "--since A (every fixture is newer than A)" "${#want_full[@]}" "${want_full[@]}" || true

  # The arm that proves `--since` actually filters. Everything reachable from
  # B is excluded, which is every fixture; the dangling blob is reachable
  # from nothing, so it must survive. A delta mode that quietly scanned the
  # whole store would report 12 here, and one that dropped unreachable
  # objects would report 0. Both are failures, and only this arm sees them.
  OUT="$(scan_repo "$repo" since "$B" 2>&1)" || true
  expect_hits '--since B (only the dangling blob is outside B)' 1 "R5:$dangling" || true

  # The reachability invariant, asserted on a repo whose numbers are known by
  # construction: three objects were written outside any commit.
  if ! grep -q 'arithmetic asserted' <<<"$OUT"; then
    err "self-test FAILED: no scan reported the reachability assertion, so the invariant" \
        "that makes the corpus a superset was never evaluated."
    arm_fail=1
  fi

  if [ "$arm_fail" -ne 0 ]; then
    err "self-test FAILED — do not trust a clean verdict from this script until it passes."
    return 1
  fi
  note "self-test OK: ${#RULE_IDS[@]} rules, ${#fix_rule[@]} committed fixtures + 1 dangling fixture, 3 negative controls (including this script's own source), 3 arms."
  printf 'SCRUB_HISTORY mode=self-test rules=%s fixtures=%s arms=3 findings=0 verdict=PASS\n' \
    "${#RULE_IDS[@]}" "$(( ${#fix_rule[@]} + 1 ))"
  return 0
}

# ── Entry point ────────────────────────────────────────────────────────────
OUT=""
usage() {
  sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  local mode=full since="" repo rc=0 verdict
  case "${1:-}" in
    -h|--help)   usage; exit 0 ;;
    --self-test) self_test; exit $? ;;
    --since)
      if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
        err "--since needs a commit-ish, e.g. \`--since main~20\` or \`--since <sha>\`."
        exit 1
      fi
      mode=since; since="$2" ;;
    "") ;;
    *) err "unknown argument \`$1\`. Try --help."; exit 1 ;;
  esac

  if ! repo="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    err "not inside a git work tree, and the object store is the entire subject of this scan."
    exit 1
  fi

  note "scrub-history: READ-ONLY scan of every object in the store at $(git -C "$repo" rev-parse --short HEAD)."
  note "               Nothing here rewrites history, moves a ref, or changes a setting."
  scan_repo "$repo" "$mode" "$since" || rc=$?

  if [ "$rc" -eq 0 ]; then
    verdict=CLEAN
  elif [ "$SC_FINDINGS" -gt 0 ]; then
    verdict=FINDINGS
    note ""
    note "Every HIT above needs resolving BY NAME in a review record before this repository"
    note "is made public. A hit is not automatically a leak — the known-benign classes are"
    note "documentation quoting a marker, the guard's own self-test literals, and published"
    note "test vectors — but \"probably benign\" is not a resolution, and nothing in this"
    note "script may be narrowed to make a hit go away."
  else
    verdict=INVARIANT-FAILED
  fi
  printf 'SCRUB_HISTORY mode=%s objects=%s blob=%s tree=%s commit=%s tag=%s reachable=%s unreachable=%s scanned=%s bytes=%s rules=%s findings=%s verdict=%s\n' \
    "$mode${since:+:$since}" "$SC_TOTAL" "$SC_BLOB" "$SC_TREE" "$SC_COMMIT" "$SC_TAG" \
    "$SC_REACHABLE" "$SC_UNREACHABLE" "$SC_SCANNED" "$SC_BYTES" "${#RULE_IDS[@]}" \
    "$SC_FINDINGS" "$verdict"
  exit "$rc"
}

main "$@"
