#!/usr/bin/env bash
# Q32 / D177 R10 / D173 §2 R16 — stage 0 of the M4 gate, and its ONE predicate.
#
# Stage 0 is `seal --dry-run --json` on the smoke file on arbitrum-one, run
# immediately before the M4 smoke seal: the same released binary, the same
# machine, the same smoke file, in one sitting, its output kept as gate
# evidence. The maintainer ruled it inside docs/threat-model.md §2.9's one
# accepted mainnet exposure on 2026-10-15 (D173's addendum). Anything but a
# PASS stops the gate, and no seal is attempted in that sitting.
#
# ── The predicate, and why it is strict ───────────────────────────────────
#
# D173 §2 R16 wrote "exit 0 with \"dry_run\": true and at least one priced
# blob". Read literally — exit 0 and dry_run — it PASSES the resume-plan
# document: a dry run over any resumable work (paid or not) returns BEFORE
# any backend call (seal_run.rs), so it proves no route and no quote, and still
# prints {"ok":true,"result":{"dry_run":true,"quoted":false,"resume":true…}}
# (crates/antseal-cli/tests/snapshots/json-envelopes.txt). So the predicate
# is the conjunction below, every conjunct named, and --self-test proves each
# one load-bearing by deleting it and watching a fixture flip:
#
#   exit      the process exited 0
#   onedoc    stdout is exactly one JSON object (D51: one document, nothing else)
#   v         the envelope schema is v1 — the one this predicate was written against
#   command   it is a `seal` envelope
#   ok        "ok": true
#   network   the top-level "network" is the one the gate expects
#   dry_run   "result.dry_run": true
#   resume    "result.resume": false — present, and false
#   quoted    "result.quoted" is not false (absent or true)
#   blobs     "result.blob_count" is an integer >= 1
#   cost      "result.storage_cost_atto" is a decimal string > 0
#
# `v` and `command` go beyond D177 R10's list; they can only turn a PASS into
# a STOP on an envelope that is not the one this predicate was written for.
#
# ── Usage ─────────────────────────────────────────────────────────────────
#
#   scripts/stage0.sh --plan
#       what each mode does; nothing executed. Prints PLAN, never PASS.
#   scripts/stage0.sh --self-test
#       the predicate over the committed seal envelopes and their mutations,
#       the naive reading against the strict one, every conjunct proven
#       load-bearing, and the refusals of --rehearse and --gate — in memory
#       and a temp directory, with a stub binary. Prints SELF-TEST.
#   scripts/stage0.sh --judge --network NET --exit N --stdout FILE
#       apply the predicate to one recorded invocation (runs nothing).
#   scripts/stage0.sh --rehearse --bin ANTSEAL --export FILE --workdir DIR [--timeout SECS]
#       the loopback rehearsal Q32 owes (D173 §2 R16), three time-boxed arms:
#       dead RPC -> STOP (exit 23), live RPC + dead nodes -> STOP, live -> PASS.
#       Only inside an isolated network namespace; scripts/s41-interop.sh
#       runs it inside its own, against each fleet it boots.
#   scripts/stage0.sh --gate --bin ANTSEAL --smoke-file FILE --passphrase-file FILE --evidence-dir DIR
#       THE REAL MODE, on arbitrum-one. WRITTEN, NEVER RUN: it contacts the
#       public network, so it runs only at the M4 gate, on the maintainer's
#       express consent typed at an interactive terminal in that sitting.
#
# Exit: 0 = PASS (the gate may proceed to the smoke seal; PLAN / SELF-TEST ok
# in those modes; every rehearsal arm as expected) · 1 = STOP, or a rehearsal
# arm that did not behave as expected, or a broken self-test · 3 = REFUSED
# before the binary was invoked.
set -uo pipefail

script="$(readlink -f "${BASH_SOURCE[0]}")"
repo="$(cd "$(dirname "$script")/.." && pwd)"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
fail_msg() { printf '\033[31m::error::stage0: %s\033[0m\n' "$*" >&2; }
die() { fail_msg "$*"; exit 1; }
refuse() { # <REASON> <explanation…> — before the binary is ever invoked
  local reason="$1"; shift
  fail_msg "REFUSED reason=$reason — $*"
  printf 'stage0: REFUSED reason=%s commit=%s\n' "$reason" "$(git -C "$repo" rev-parse --short=7 HEAD 2>/dev/null || echo nogit)"
  exit 3
}
head_sha() { git -C "$repo" rev-parse --short=7 HEAD 2>/dev/null || echo nogit; }
readonly SYS_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly CONSENT_PHRASE='stage 0 on arbitrum-one'

# Key-name-scoped redaction, e2e-devnet.sh's filter verbatim.
redact() {
  sed -E "$@" "s/(wallet_private_key|[A-Za-z_]*PRIVATE_KEY|[A-Za-z_]*SECRET_KEY)([\"']?[[:space:]]*[:=][[:space:]]*[\"']?)(0x)?[0-9a-fA-F]{8,}/\1\2<redacted>/g"
}

# ── THE predicate (the only copy; nothing else in the tree judges stage 0) ─
#
# One conjunct per line, each tagged `# conjunct:<name>`, so the self-test
# can delete exactly one and prove a fixture flips.
predicate_py() {
  cat <<'PY'
import json, re, sys

def judge(exit_code, text, expected):
    """-> (verdict, reasons, doc). PASS only if every conjunct holds."""
    doc = None
    try:
        s = text.strip()
        doc, end = json.JSONDecoder().raw_decode(s)
        extra = s[end:].strip()
    except ValueError:
        extra = None
    one = doc is not None and isinstance(doc, dict) and extra == ""
    d = doc if isinstance(doc, dict) else {}
    r = d.get("result") if isinstance(d.get("result"), dict) else {}
    cost = r.get("storage_cost_atto")
    blobs = r.get("blob_count")
    CONJUNCTS = [
        ("exit",    exit_code == 0),                                                  # conjunct:exit
        ("onedoc",  one),                                                             # conjunct:onedoc
        ("v",       d.get("v") == 1 and type(d.get("v")) is int),                     # conjunct:v
        ("command", d.get("command") == "seal"),                                      # conjunct:command
        ("ok",      d.get("ok") is True),                                             # conjunct:ok
        ("network", d.get("network") == expected),                                    # conjunct:network
        ("dry_run", r.get("dry_run") is True),                                        # conjunct:dry_run
        ("resume",  "resume" in r and r.get("resume") is False),                      # conjunct:resume
        ("quoted",  r.get("quoted", None) is not False),                              # conjunct:quoted
        ("blobs",   type(blobs) is int and blobs >= 1),                               # conjunct:blobs
        ("cost",    isinstance(cost, str) and re.fullmatch(r"[0-9]+", cost) is not None and int(cost) > 0),  # conjunct:cost
    ]
    reasons = [name for name, held in CONJUNCTS if not held]
    return ("STOP" if reasons else "PASS"), reasons, d

def line(verdict, reasons, d, exit_code, expected):
    r = d.get("result") if isinstance(d.get("result"), dict) else {}
    err = d.get("error") if isinstance(d.get("error"), dict) else {}
    msg = str(err.get("message", ""))[:200].replace("\n", " ")
    return ("stage0: %s network=%s expected=%s exit=%s failed=[%s] blob_count=%s storage_cost_atto=%s%s"
            % (verdict, d.get("network", "-"), expected, exit_code, ",".join(reasons),
               r.get("blob_count", "-"), r.get("storage_cost_atto", "-"),
               (' error_class=%s message="%s"' % (err.get("class", "-"), msg)) if err else ""))

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "judge":                 # judge <expected-network> <exit> <stdout-file>
        text = open(sys.argv[4], encoding="utf-8", errors="replace").read()
        v, reasons, d = judge(int(sys.argv[3]), text, sys.argv[2])
        print(line(v, reasons, d, int(sys.argv[3]), sys.argv[2]))
        sys.exit(0 if v == "PASS" else 1)
    elif mode == "table":               # table <expected-network>  (stdin: label\texit\tjson lines)
        for raw in sys.stdin:
            label, code, enc = raw.rstrip("\n").split("\t", 2)
            v, reasons, d = judge(int(code), json.loads(enc), sys.argv[2])
            print("%s\t%s\t%s" % (label, v, ",".join(reasons)))
PY
}

# predicate source → verdict for one recorded invocation
judge_file() { # <expected-network> <exit> <stdout-file> [predicate-source]
  local src="${4:-$(predicate_py)}"
  python3 -I -c "$src" judge "$1" "$2" "$3"
}

# ── --self-test ───────────────────────────────────────────────────────────
readonly ENVELOPES_REL='crates/antseal-cli/tests/snapshots/json-envelopes.txt'
readonly LBL_ERROR='[seal] error'
readonly LBL_SEAL='[seal] result'
readonly LBL_DRY='[seal] result (--dry-run)'
readonly LBL_RESUME='[seal] result (--dry-run over a resumable work)'
readonly ALL_CONJUNCTS='exit onedoc v command ok network dry_run resume quoted blobs cost'

# The fixtures: the four committed seal envelopes (exit code paired from the
# envelope itself) and mutations of the plain dry run, each tagged with the
# verdict the STRICT predicate must reach. TSV: label, exit, json, want.
fixtures() { # <envelopes-file>
  python3 -I - "$1" "$LBL_ERROR" "$LBL_SEAL" "$LBL_DRY" "$LBL_RESUME" <<'PY'
import json, sys
path, l_err, l_seal, l_dry, l_res = sys.argv[1:6]
lines = open(path, encoding="utf-8").read().splitlines()
env = {}
for i, l in enumerate(lines):
    if l in (l_err, l_seal, l_dry, l_res):
        if l in env:
            sys.exit(f"the label {l!r} appears twice in {path}")
        env[l] = lines[i + 1] if i + 1 < len(lines) else ""
missing = [l for l in (l_err, l_seal, l_dry, l_res) if l not in env]
if missing:
    sys.exit(f"committed envelope(s) gone from {path}: {missing} — the self-test has no subject")
docs = {k: json.loads(v) for k, v in env.items()}
def code(d):
    return 0 if d.get("ok") is True else int(d.get("error", {}).get("exit_code", 1))
out = []
def add(label, exit_code, doc_or_text, want):
    text = doc_or_text if isinstance(doc_or_text, str) else json.dumps(doc_or_text, separators=(",", ":"))
    out.append((label, exit_code, text, want))
add(l_err, code(docs[l_err]), docs[l_err], "STOP")
add(l_seal, code(docs[l_seal]), docs[l_seal], "STOP")
add(l_dry, code(docs[l_dry]), docs[l_dry], "PASS")
add(l_res, code(docs[l_res]), docs[l_res], "STOP")
dry = docs[l_dry]
def mut(label, fn, want="STOP", exit_code=0):
    d = json.loads(json.dumps(dry)); fn(d); add("dry-run mutated: " + label, exit_code, d, want)
def setr(k, v):
    return lambda d: d["result"].__setitem__(k, v)
def delr(k):
    return lambda d: d["result"].pop(k)
mut("exit 23 with the dry-run document", lambda d: None, "STOP", 23)
add("dry-run mutated: two documents on stdout", 0, env[l_dry] + "\n" + env[l_dry], "STOP")
add("dry-run mutated: empty stdout", 0, "", "STOP")
add("dry-run mutated: truncated document", 0, env[l_dry][:200], "STOP")
add("dry-run mutated: a JSON array", 0, "[" + env[l_dry] + "]", "STOP")
mut("schema v 2", lambda d: d.__setitem__("v", 2))
mut("schema v true", lambda d: d.__setitem__("v", True))
mut("command reveal", lambda d: d.__setitem__("command", "reveal"))
mut("ok false", lambda d: d.__setitem__("ok", False))
mut("network arbitrum-sepolia", lambda d: d.__setitem__("network", "arbitrum-sepolia"))
mut("network absent", lambda d: d.pop("network"))
mut("dry_run false", setr("dry_run", False))
mut("dry_run absent", delr("dry_run"))
mut("resume true", setr("resume", True))
mut("resume absent", delr("resume"))
mut("quoted false", setr("quoted", False))
mut("quoted true", setr("quoted", True), "PASS")
mut("blob_count 0", setr("blob_count", 0))
mut("blob_count -1", setr("blob_count", -1))
mut("blob_count \"5\"", setr("blob_count", "5"))
mut("blob_count true", setr("blob_count", True))
mut("blob_count absent", delr("blob_count"))
mut("blob_count 1", setr("blob_count", 1), "PASS")
mut("storage_cost_atto \"0\"", setr("storage_cost_atto", "0"))
mut("storage_cost_atto \"\"", setr("storage_cost_atto", ""))
mut("storage_cost_atto \"0x10\"", setr("storage_cost_atto", "0x10"))
mut("storage_cost_atto \"1e3\"", setr("storage_cost_atto", "1e3"))
mut("storage_cost_atto \"-5\"", setr("storage_cost_atto", "-5"))
mut("storage_cost_atto 4200 (a number)", setr("storage_cost_atto", 4200))
mut("storage_cost_atto absent", delr("storage_cost_atto"))
mut("storage_cost_atto \"1\"", setr("storage_cost_atto", "1"), "PASS")
for label, exit_code, text, want in out:
    print("%s\t%s\t%s\t%s" % (label, exit_code, json.dumps(text), want))
PY
}

# Run a predicate source over the fixtures: "label<TAB>verdict<TAB>reasons".
# Field 3 of a fixture is the stdout text JSON-encoded, so a fixture with
# two documents or a stray tab stays one row.
table_of() { # <predicate-source> <fixtures-tsv>
  python3 -I -c "$1" table arbitrum-one < <(cut -f1-3 <<<"$2")
}

self_test() {
  local fail=0 arms=0 fx strict naive got want label out rc st c cut flipped
  ok()  { arms=$((arms + 1)); printf '  planted fault: %-64s -> %s\n' "$1" "$2"; }
  bad() { arms=$((arms + 1)); printf '::error:: %s\n' "$*"; fail=1; }
  fx="$(fixtures "$repo/$ENVELOPES_REL" 2>&1)" || { bad "$fx"; printf '\nstage0: SELF-TEST BROKEN arms=%s commit=%s\n' "$arms" "$(head_sha)"; return 1; }
  # Every fixture against the STRICT predicate.
  strict="$(table_of "$(predicate_py)" "$fx")"
  local verdict reasons
  while IFS=$'\t' read -r label rc want; do
    verdict="$(awk -F'\t' -v l="$label" '$1 == l {print $2}' <<<"$strict")"
    reasons="$(awk -F'\t' -v l="$label" '$1 == l {print $3}' <<<"$strict")"
    if [ "$verdict" = "$want" ]; then ok "$label" "$want${reasons:+ (failed: $reasons)}"
    else bad "strict predicate on [$label]: ${verdict:-no verdict}, expected $want"; fi
  done < <(cut -f1,2,4 <<<"$fx")

  # The plant (D177 R10): the naive reading — exit 0, one document, ok,
  # dry_run — PASSES the resume-plan envelope, which proves no route and no
  # quote. Built by deleting every other conjunct from the one source.
  cut="$(predicate_py)"
  for c in v command network resume quoted blobs cost; do cut="$(sed "/# conjunct:$c\$/d" <<<"$cut")"; done
  naive="$(table_of "$cut" "$fx")"
  got="$(awk -F'\t' -v l="$LBL_RESUME" '$1 == l {print $2}' <<<"$naive")"
  st="$(awk -F'\t' -v l="$LBL_RESUME" '$1 == l {print $2}' <<<"$strict")"
  if [ "$got" = PASS ] && [ "$st" = STOP ]; then
    ok "THE PLANT: $LBL_RESUME" "naive=PASS strict=STOP"
  else
    bad "the naive predicate was expected to PASS the resume-plan envelope and the strict one to STOP it (naive=$got strict=$st)"
  fi
  got="$(awk -F'\t' -v l="$LBL_DRY" '$1 == l {print $2}' <<<"$naive")"
  [ "$got" = PASS ] && ok "control: the naive reading still passes a real dry run" "naive=PASS" || bad "the naive reading failed the plain dry run"

  # Every conjunct load-bearing: delete it alone and a fixture the strict
  # predicate STOPs must flip to PASS. A conjunct no fixture exercises is a
  # check that cannot fail.
  for c in $ALL_CONJUNCTS; do
    cut="$(sed "/# conjunct:$c\$/d" <<<"$(predicate_py)")"
    if [ "$cut" = "$(predicate_py)" ]; then bad "conjunct $c could not be deleted — the predicate's shape changed"; continue; fi
    flipped="$(paste <(cut -f1,2 <<<"$strict") <(cut -f2 <<<"$(table_of "$cut" "$fx")") | awk -F'\t' '$2 == "STOP" && $3 == "PASS" {print $1}' | head -1)"
    if [ -n "$flipped" ]; then ok "conjunct '$c' deleted" "[$flipped] flips STOP -> PASS"
    else bad "deleting conjunct $c flips no fixture — nothing proves it can fail"; fi
  done

  refusal_arms
  rehearse_arms
  printf '\nstage0: SELF-TEST %s arms=%s commit=%s — the predicate over the committed envelopes and %s mutations; the binary was never run\n' \
    "$([ "$fail" = 0 ] && echo ok || echo BROKEN)" "$arms" "$(head_sha)" "$(( $(grep -c . <<<"$fx") - 4 ))"
  return "$fail"
}

# The refusals --rehearse and --gate promise, each proven with a stub binary
# that records any invocation: a refused run must never invoke it.
refusal_arms() {
  local t stub out rc
  t="$(mktemp -d "${TMPDIR:-/tmp}/stage0-selftest.XXXXXX")" || { bad "cannot create a temp dir"; return; }
  stub="$t/antseal"
  printf '#!/bin/sh\n: > "%s/INVOKED"\nexit 0\n' "$t" > "$stub"; chmod +x "$stub"
  printf 'smoke\n' > "$t/smoke.txt"; printf 'not-a-real-passphrase\n' > "$t/pass"
  printf "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:18545/'\n" > "$t/export.env"
  arm_r() { # <label> <want-rc> <want-text> <cmd…>
    local label="$1" want_rc="$2" want="$3"; shift 3
    rm -f "$t/INVOKED"
    out="$("$@" 2>&1 < /dev/null)"; rc=$?
    if [ "$rc" = "$want_rc" ] && grep -qF -- "$want" <<<"$out" && [ ! -e "$t/INVOKED" ]; then ok "$label" "$want (binary never invoked)"
    else bad "$label -> exit $rc (wanted $want_rc), [$want] $(grep -qF -- "$want" <<<"$out" && echo present || echo absent), binary $( [ -e "$t/INVOKED" ] && echo INVOKED || echo not invoked)"; fi
  }
  arm_r "--rehearse outside a network namespace" 3 "reason=NOT-ISOLATED" \
    bash "$script" --rehearse --bin "$stub" --export "$t/export.env" --workdir "$t/w"
  arm_r "--gate with no interactive terminal" 3 "reason=NO-TTY" \
    env -u ANTSEAL_DEVNET_ENV bash "$script" --gate --bin "$stub" --smoke-file "$t/smoke.txt" --passphrase-file "$t/pass" --evidence-dir "$t/ev1"
  arm_r "--gate with a devnet export in the environment" 3 "reason=DEVNET-EXPORT-SET" \
    env ANTSEAL_DEVNET_ENV="$t/export.env" bash "$script" --gate --bin "$stub" --smoke-file "$t/smoke.txt" --passphrase-file "$t/pass" --evidence-dir "$t/ev2"
  arm_r "--gate without a smoke file" 3 "reason=SMOKE-FILE" \
    env -u ANTSEAL_DEVNET_ENV bash "$script" --gate --bin "$stub" --smoke-file "$t/absent.txt" --passphrase-file "$t/pass" --evidence-dir "$t/ev3"
  out="$(bash "$script" --plan 2>&1)"; rc=$?
  if [ "$rc" = 0 ] && grep -q '^stage0: PLAN' <<<"$out" && ! grep -q '^stage0: PASS' <<<"$out"; then ok "--plan prints PLAN, never PASS" "stage0: PLAN"
  else bad "--plan did not print PLAN alone (rc=$rc)"; fi
  rm -rf "$t"
}

# The rehearsal's PLUMBING, with no real binary and no network: a stub CLI
# that answers each arm as the real one is expected to — and checks that the
# passphrase arrives on fd 3 and, for init only, the key on fd 4 — run by
# --rehearse inside a throwaway network namespace. The control must come out
# PASS; each plant must come out FAIL, naming the arm.
rehearse_arms() {
  local t out rc mode
  t="$(mktemp -d "${TMPDIR:-/tmp}/stage0-rehearse.XXXXXX")" || { bad "cannot create a temp dir"; return; }
  python3 -I - "$repo/$ENVELOPES_REL" "$LBL_DRY" "$LBL_RESUME" "$t" <<'PY2'
import json, sys
path, l_dry, l_res, t = sys.argv[1:5]
lines = open(path, encoding="utf-8").read().splitlines()
for label, name in ((l_dry, "dry.json"), (l_res, "resume.json")):
    doc = json.loads(lines[lines.index(label) + 1])
    doc["network"] = "devnet"
    open(f"{t}/{name}", "w").write(json.dumps(doc, separators=(",", ":")) + "\n")
PY2
  { printf "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:18545/'\nANTSEAL_DEVNET_CHAIN_ID='31337'\n"
    printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='0x%s'\n" "$(printf 'ab%.0s' $(seq 32))"
    printf "ANTSEAL_DEVNET_BOOTSTRAP='127.0.0.1:20001,127.0.0.1:20002'\n"; } > "$t/export.env"
  # mode: good | invert-dead-rpc | wrong-reason | live-resume
  mk_stub() {
    cat > "$t/antseal" <<STUB
#!/bin/sh
case " \$* " in
  *" init "*) [ -e /proc/self/fd/4 ] && [ -e /proc/self/fd/3 ] || { echo "stub: init without fd 3 and 4" >&2; exit 64; }; exit 0 ;;
esac
[ -e /proc/self/fd/3 ] || { echo "stub: no passphrase fd" >&2; exit 64; }
if grep -q "127.0.0.1:18546/" "\$ANTSEAL_DEVNET_ENV"; then
  case "$1" in
    invert-dead-rpc) cat "$t/dry.json"; exit 0 ;;
    wrong-reason) echo '{"command":"seal","error":{"class":"network-failure","exit_code":23,"message":"network failure: data directory unresolvable"},"network":"devnet","ok":false,"v":1}'; exit 23 ;;
  esac
  echo '{"command":"seal","error":{"class":"network-failure","exit_code":23,"message":"network failure: payment RPC unreachable (eth_chainId): connection refused"},"network":"devnet","ok":false,"v":1}'; exit 23
fi
if grep -q "127.0.0.1:29901" "\$ANTSEAL_DEVNET_ENV"; then
  echo '{"command":"seal","error":{"class":"network-failure","exit_code":23,"message":"network failure: no peer answered"},"network":"devnet","ok":false,"v":1}'; exit 23
fi
[ "$1" = live-resume ] && { cat "$t/resume.json"; exit 0; }
cat "$t/dry.json"; exit 0
STUB
    chmod +x "$t/antseal"
  }
  for mode in good invert-dead-rpc wrong-reason live-resume; do
    mk_stub "$mode"; rm -rf "$t/w"
    out="$(unshare --user --map-root-user --net bash "$script" --rehearse --bin "$t/antseal" --export "$t/export.env" --workdir "$t/w" --timeout 20 2>&1)"; rc=$?
    case "$mode" in
      good)
        if [ "$rc" = 0 ] && grep -q '^stage0-rehearsal: PASS arms=3 failed=0' <<<"$out"; then ok "rehearsal plumbing (stub CLI, throwaway netns)" "stage0-rehearsal: PASS arms=3"
        else bad "the rehearsal plumbing did not PASS with a well-behaved stub (rc=$rc): $(grep -E '^arm |stage0' <<<"$out" | head -4)"; fi ;;
      invert-dead-rpc)
        if [ "$rc" = 1 ] && grep -q '^arm dead-rpc: exit=0 verdict=WRONG-REASON:PASS expected=STOP' <<<"$out"; then ok "dead RPC answered as if live (inverted)" "arm dead-rpc: verdict=...PASS expected=STOP"
        else bad "an inverted dead-RPC arm was not caught (rc=$rc): $(grep -E '^arm dead-rpc' <<<"$out")"; fi ;;
      wrong-reason)
        if [ "$rc" = 1 ] && grep -q '^arm dead-rpc: exit=23 verdict=WRONG-REASON:STOP expected=STOP' <<<"$out"; then ok "dead RPC: exit 23 for another reason" "WRONG-REASON (judged by message)"
        else bad "a 23 for the wrong reason was accepted (rc=$rc): $(grep -E '^arm dead-rpc' <<<"$out")"; fi ;;
      live-resume)
        if [ "$rc" = 1 ] && grep -q '^arm live: exit=0 verdict=STOP expected=PASS' <<<"$out"; then ok "live arm answered with the resume-plan document" "arm live: verdict=STOP expected=PASS"
        else bad "a resume-plan answer on the live arm was not caught (rc=$rc): $(grep -E '^arm live' <<<"$out")"; fi ;;
    esac
  done
  rm -rf "$t"
}

# ── --rehearse: the loopback arms (D173 §2 R16, D177 R10) ─────────────────
#
# Inside an isolated network namespace only (s41-interop.sh runs it in its
# own, cap-dropped): links=[lo], both main route tables empty. Read-only
# checks — this mode never configures anything.
assert_isolated_ro() {
  local links r4 r6
  links="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | LC_ALL=C sort | paste -sd, -)"
  r4="$(ip -4 route show table main 2>/dev/null | paste -sd';' -)"
  r6="$(ip -6 route show table main 2>/dev/null | paste -sd';' -)"
  if [ "$links" != lo ] || [ -n "$r4" ] || [ -n "$r6" ]; then
    refuse NOT-ISOLATED "the rehearsal arms run only inside an isolated network namespace (links=[$links]); run them through scripts/s41-interop.sh"
  fi
}

# One export line rewritten, the rest kept: the arms differ from the live
# export in exactly one key.
export_with() { # <export> <KEY> <value> <out>
  awk -v k="$2" -v v="$3" 'BEGIN {FS = OFS = "="} $1 == k {print k "='"'"'" v "'"'"'"; next} {print}' "$1" > "$4"
}

rehearse() { # <bin> <export> <workdir> <timeout>
  local bin="$1" exp="$2" w="$3" tmo="$4" arm arm_exp want rc secs v line msg fails=0 t0
  [ -x "$bin" ] || refuse BIN "--bin $bin is not executable"
  [ -s "$exp" ] || refuse EXPORT "--export $exp is missing or empty"
  assert_isolated_ro
  mkdir -p "$w/vault" "$w/home" "$w/xdg" || refuse WORKDIR "cannot create $w"
  # A throwaway vault on the devnet's funded key (Anvil account 0, a public
  # constant). The key and the test passphrase cross only file descriptors
  # (D41) and never reach a log.
  ( umask 077
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$w/pass"
    sed -n "s/^ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='\(.*\)'$/\1/p" "$exp" > "$w/key" )
  [ -s "$w/key" ] || refuse EXPORT "the export carries no ANTSEAL_DEVNET_WALLET_PRIVATE_KEY"
  printf 'stage 0 rehearsal smoke file\n' > "$w/smoke.txt"
  run_cli() { # <export> <stdout> <stderr> <cli args…>
    local e="$1" so="$2" se="$3"; shift 3
    env -i PATH="$SYS_PATH" HOME="$w/home" XDG_DATA_HOME="$w/xdg" LANG=C.UTF-8 TZ=UTC ANTSEAL_DIR="$w/vault" \
      ANTSEAL_DEVNET_ENV="$e" timeout --kill-after=10 "$tmo" "$bin" "$@" 3< "$w/pass" > "$so" 2> >(redact > "$se")
  }
  # fd 4 carries the key to init only; the file is gone before any arm runs.
  run_cli "$exp" "$w/init.stdout" "$w/init.stderr" --network devnet --passphrase-fd 3 init --wallet import --wallet-key-fd 4 4< "$w/key"
  rc=$?; rm -f "$w/key"
  [ "$rc" = 0 ] || refuse VAULT "init of the rehearsal vault failed (exit $rc; $w/init.stderr)"
  export_with "$exp" ANTSEAL_DEVNET_RPC_URL "http://127.0.0.1:18546/" "$w/export-dead-rpc.env"
  export_with "$exp" ANTSEAL_DEVNET_BOOTSTRAP "127.0.0.1:29901,127.0.0.1:29902" "$w/export-dead-nodes.env"
  for arm in dead-rpc dead-nodes live; do
    case "$arm" in
      dead-rpc)   arm_exp="$w/export-dead-rpc.env"; want=STOP ;;
      dead-nodes) arm_exp="$w/export-dead-nodes.env"; want=STOP ;;
      live)       arm_exp="$exp"; want=PASS ;;
    esac
    t0="$(date +%s)"
    run_cli "$arm_exp" "$w/$arm.stdout.json" "$w/$arm.stderr.txt" --network devnet --json --passphrase-fd 3 seal --dry-run "$w/smoke.txt"
    rc=$?; secs=$(( $(date +%s) - t0 ))
    [ "$rc" = 124 ] || [ "$rc" = 137 ] && printf '    arm %s: timed out after %ss — a timeout is a STOP\n' "$arm" "$tmo"
    line="$(judge_file devnet "$rc" "$w/$arm.stdout.json")"; v="$(awk '{print $2}' <<<"$line")"
    msg=""
    case "$arm" in
      dead-rpc)
        # Judged by MESSAGE, not exit code alone: a 23 for any other reason
        # (a data-directory refusal, a peer refusal) proves nothing about the RPC.
        if [ "$rc" != 23 ] || ! grep -qF 'payment RPC unreachable (eth_chainId)' "$w/$arm.stdout.json"; then
          msg=" (wanted exit 23 naming \"payment RPC unreachable (eth_chainId)\")"; v="WRONG-REASON:$v"
        fi ;;
      dead-nodes)
        if [ "$rc" != 23 ] && [ "$rc" != 124 ] && [ "$rc" != 137 ]; then msg=" (wanted exit 23 or a timeout)"; v="WRONG-REASON:$v"; fi ;;
    esac
    printf 'arm %s: exit=%s verdict=%s expected=%s secs=%s%s\n    %s\n' "$arm" "$rc" "$v" "$want" "$secs" "$msg" "$line"
    [ "$v" = "$want" ] || fails=$((fails + 1))
  done
  printf '\nstage0-rehearsal: %s arms=3 failed=%s commit=%s network=devnet binary_sha256=%s date=%s\n' \
    "$([ "$fails" = 0 ] && echo PASS || echo FAIL)" "$fails" "$(head_sha)" "$(sha256sum "$bin" | awk '{print $1}')" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ "$fails" = 0 ]
}

# ── --gate: THE REAL MODE, arbitrum-one. Written; never run off the gate. ──
#
# Every refusal comes before the binary is invoked, and the last one is the
# consent: the phrase typed at an interactive terminal in this sitting. An
# agent session has no such terminal, so it cannot reach the invocation.
gate() { # <bin> <smoke-file> <passphrase-file> <evidence-dir>
  local bin="$1" smoke="$2" pass="$3" ev="$4" typed rc line binsha smokesha
  [ -z "${ANTSEAL_DEVNET_ENV:-}" ] || refuse DEVNET-EXPORT-SET "ANTSEAL_DEVNET_ENV is set, so this shell was pointed at a devnet; stage 0 runs against arbitrum-one from a clean environment (unset it and start again)"
  [ -n "$bin" ] && [ -x "$bin" ] || refuse BIN "--bin must name the RELEASED antseal binary the smoke seal will use"
  [ -n "$smoke" ] && [ -s "$smoke" ] || refuse SMOKE-FILE "--smoke-file must name the smoke file the seal will use (missing or empty: $smoke)"
  [ -n "$pass" ] && [ -s "$pass" ] || refuse PASSPHRASE "--passphrase-file is missing or empty (it crosses fd 3 only, D41)"
  [ -n "$ev" ] || refuse EVIDENCE-DIR "--evidence-dir is required: the output is gate evidence"
  if [ -e "$ev" ] && [ -n "$(ls -A "$ev" 2>/dev/null)" ]; then
    refuse EVIDENCE-DIR "$ev is not empty — each sitting keeps its own evidence"
  fi
  if ! [ -t 0 ] || ! [ -t 1 ]; then
    refuse NO-TTY "stage 0 contacts the public network; it runs only on the maintainer's express consent, typed at an interactive terminal in this sitting"
  fi
  binsha="$(sha256sum "$bin" | awk '{print $1}')"; smokesha="$(sha256sum "$smoke" | awk '{print $1}')"
  printf '\nStage 0 of the M4 gate (docs/threat-model.md §2.9, ruled 2026-10-15).\n'
  printf '  binary      %s  sha256 %s\n  smoke file  %s  sha256 %s\n' "$bin" "$binsha" "$smoke" "$smokesha"
  printf '  It runs: antseal --network arbitrum-one --json seal --dry-run <smoke file>\n'
  printf '  It contacts storage peers of the public network and the public Arbitrum RPC. It pays nothing,\n'
  printf '  uploads nothing and writes nothing to the vault. The smoke seal must follow IN THIS SITTING,\n'
  printf '  with this binary and this smoke file, or not at all.\n\n'
  printf 'Type exactly "%s" to run it, anything else to stop: ' "$CONSENT_PHRASE"
  IFS= read -r typed < /dev/tty
  [ "$typed" = "$CONSENT_PHRASE" ] || refuse NO-CONSENT "the confirmation phrase was not typed; nothing was contacted"
  mkdir -p "$ev" || refuse EVIDENCE-DIR "cannot create $ev"
  printf 'date=%s\nbinary=%s\nbinary_sha256=%s\nsmoke_file=%s\nsmoke_sha256=%s\nconsent_phrase_typed=yes\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$bin" "$binsha" "$smoke" "$smokesha" > "$ev/stage0-context.txt"
  "$bin" --network arbitrum-one --json --passphrase-fd 3 seal --dry-run "$smoke" 3< "$pass" \
    > "$ev/stage0.stdout.json" 2> >(redact > "$ev/stage0.stderr.txt")
  rc=$?
  line="$(judge_file arbitrum-one "$rc" "$ev/stage0.stdout.json")"
  printf '%s binary_sha256=%s smoke_sha256=%s date=%s\n' "$line" "$binsha" "$smokesha" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    | tee "$ev/stage0-verdict.txt"
  if [ "$(awk '{print $2}' <<<"$line")" = PASS ]; then
    printf '\033[32mstage0: PASS — the gate may proceed to the smoke seal in THIS sitting, with binary %s… and smoke file %s…\033[0m\n' "${binsha:0:16}" "${smokesha:0:16}"
    return 0
  fi
  fail_msg "STOP — no seal is attempted in this sitting (docs/threat-model.md §2.9). Evidence: $ev"
  return 1
}

print_plan() {
  note "stage 0 (Q32, D177 R10): one predicate, three modes that run it"
  printf '    predicate  STRICT, %s conjuncts: %s\n' "$(wc -w <<<"$ALL_CONJUNCTS")" "$ALL_CONJUNCTS"
  printf '    --self-test  the committed seal envelopes (%s) + mutations; naive vs strict; each conjunct deleted in turn\n' "$ENVELOPES_REL"
  printf '    --rehearse   loopback only, inside an isolated namespace: dead-rpc -> STOP (exit 23), dead-nodes -> STOP, live -> PASS\n'
  printf '    --gate       arbitrum-one, the released binary, the smoke file; typed consent at a terminal; evidence kept\n'
  printf '\nstage0: PLAN commit=%s predicate=strict conjuncts=%s — nothing executed; the binary was never run\n' \
    "$(head_sha)" "$(wc -w <<<"$ALL_CONJUNCTS")"
}

main() {
  local mode="" bin="" exp="" work="" tmo=300 smoke="" pass="" ev="" net="" code="" out=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --plan|--self-test|--judge|--rehearse|--gate) mode="${1#--}" ;;
      --bin) bin="$(readlink -m "${2:-}")"; shift ;;
      --export) exp="$(readlink -m "${2:-}")"; shift ;;
      --workdir) work="$(readlink -m "${2:-}")"; shift ;;
      --timeout) tmo="${2:-}"; shift; [[ $tmo =~ ^[0-9]+$ ]] || die "--timeout needs seconds" ;;
      --smoke-file) smoke="${2:-}"; shift ;;
      --passphrase-file) pass="${2:-}"; shift ;;
      --evidence-dir) ev="${2:-}"; shift ;;
      --network) net="${2:-}"; shift ;;
      --exit) code="${2:-}"; shift ;;
      --stdout) out="${2:-}"; shift ;;
      -h|--help) awk 'NR > 1 && /^set -uo pipefail/ {exit} NR > 1 {print}' "$script"; exit 0 ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
  done
  case "$mode" in
    plan) print_plan ;;
    self-test) self_test ;;
    judge)
      [ -n "$net" ] && [[ $code =~ ^[0-9]+$ ]] && [ -f "$out" ] || die "--judge needs --network NET --exit N --stdout FILE"
      judge_file "$net" "$code" "$out" ;;
    rehearse)
      [ -n "$bin" ] && [ -n "$exp" ] && [ -n "$work" ] || die "--rehearse needs --bin, --export and --workdir"
      rehearse "$bin" "$exp" "$work" "$tmo" ;;
    gate) gate "$bin" "$smoke" "$pass" "$ev" ;;
    *) die "name a mode: --plan, --self-test, --judge, --rehearse or --gate (see --help)" ;;
  esac
}

main "$@"; exit $?
