#!/usr/bin/env bash
# S41 / D177 — the foreign-node interop harness.
#
# Question (tasks/S.md S41, D173 §2 R17): can antseal's PINNED client
# (ant-core =0.5.0) quote, pay, store, fetch and restore against the
# ant-node release the network actually runs? `devnet-launcher` cannot say:
# it links ant-node 0.15.0 in-process through ant-core 0.5.0's `devnet`
# feature (D177 R1). So this harness runs upstream's RELEASED, SIGNED
# ant-node binaries — the bytes the fleet installs — as 14 processes plus
# Anvil, and points the repository's own devnet suites at them through a
# hand-written ten-key export (ANTSEAL_DEVNET_ENV). Nothing upstream is
# built, and no product or launcher code changes for it (D177 R2, R3).
#
# ── Safety model (D177 R2 and its amendment) ─────────────────────────────
#
# The binary under test auto-discovers the mainnet peers shipped next to it,
# defaults to Arbitrum One, and polls GitHub hourly to upgrade itself with
# no off switch (docs/devnet/foreign-node-interop.md, "Hazards"). Flags are
# a second layer only. The guarantee is the NAMESPACE:
#
#   L1  user + network + mount + pid + ipc + uts namespaces, entered
#       unprivileged. The ONLY interface is lo; this is PROVEN inside, first,
#       before anything starts (links=[lo], both main route tables empty,
#       egress ENETUNREACH, loopback ECONNREFUSED), and the harness refuses
#       otherwise. The operator's home, /tmp, /var/tmp, /dev/shm and
#       /run/user/<uid> are masked with empty tmpfs; only the repository,
#       the cargo and rustup homes, the foundry bin directory and this
#       run's directory are bound back, and ~/.cargo/credentials* are
#       overlaid with /dev/null. Proven with a canary file and the ruled
#       secret paths (~/.minisign ~/.ssh ~/.gnupg ~/.config/gh
#       ~/.local/share/ant ~/.cargo/credentials*).
#   L2  a nested mount + pid namespace for the ant-node processes only:
#       the home mask is redone WITHOUT the repository or the cargo and
#       rustup homes (a node that could write ~/.cargo/bin or .git/hooks
#       could run code outside the next time the operator does), and only
#       the nodes' own directory (rw) and the binary (ro) are bound back.
#       L1 proves L2's view from outside it (nsenter), before the nodes
#       start and after they stop.
#   Every workload — Anvil, cast, cargo, the suites, stage 0, the nodes —
#   runs with an EMPTY capability bounding set, no_new_privs and `env -i`,
#   so none of them can undo a mask or inherit SSH_AUTH_SOCK, a session bus
#   address or a token. Only the L1 controller keeps capabilities.
#
# Why a PID namespace and the runtime-dir masks, beyond the ruling's
# "user + network + mount": measured 2026-10-16 (runbook, "Why these
# layers"). Without a PID namespace a process inside sees every host PID,
# reads the operator's command lines and may signal the operator's
# processes (kill -0 succeeded). And a network namespace does NOT isolate
# path-named Unix sockets: a socket under /tmp was connectable from inside
# until /tmp was masked — the class of the ssh-agent, the session bus and
# terminal IPC sockets under /run/user/<uid>.
#
# ── The control arm (D177 R4) ────────────────────────────────────────────
#
# The v0.15.0 release binary — the version the client was developed
# against — runs FIRST under the identical harness. A red control means
# the harness is broken, not the client: the run stops with exit 2 and
# "harness defect, no S41 verdict". Only a green control lets the subject
# arm's result become the S41 verdict line (D177 R7).
#
# ── Usage ─────────────────────────────────────────────────────────────────
#
#   scripts/s41-interop.sh --plan
#       the plan; nothing executed, nothing verified. Prints PLAN, never PASS.
#   scripts/s41-interop.sh --self-test [--sigcheck BIN --archive-dir DIR]
#       planted faults, temp directories and stubs only; starts no node and
#       no chain. With a verifier and a fetched archive, also the real
#       one-flipped-byte signature plant. Prints SELF-TEST, never PASS.
#   scripts/s41-interop.sh --fetch TAG|latest DIR
#       read-only GETs (GitHub releases API, the release assets, ant-node's
#       src/upgrade/signature.rs at the tag, the crates.io index). Writes
#       only DIR, which must be new or empty.
#   scripts/s41-interop.sh --extract-key SIGNATURE_RS OUT
#       the release key embedded in ant-node's source, checked against the
#       pinned digest.
#   scripts/s41-interop.sh --probe-namespace [--run-dir DIR]
#       the isolation and masking proofs alone; starts no node, no chain.
#   scripts/s41-interop.sh --boot-only --node-dir DIR [--sigcheck BIN]
#                          [--run-dir DIR] [--hold SECS]
#       measurement: verify, enter the namespace, Anvil + contracts, 14
#       nodes, readiness, hold, stop. No suites, no verdict.
#   scripts/s41-interop.sh --control-dir DIR --subject-dir DIR
#                          [--sigcheck BIN | --allow-unchecked-signature]
#                          [--run-dir DIR] [--skip-prebuild]
#       THE RUN: control arm, then subject arm, then the R7 verdict line.
#
# DIR arguments are directories written by --fetch. A run without a
# verifier prints sig=unchecked, and refuses to start a node at all unless
# --allow-unchecked-signature says so out loud (D177 R12).
#
# Exit: 0 = PASS (PLAN / SELF-TEST ok / PROBE ok / BOOT-ONLY ok in those
# modes) · 1 = FAIL (a green control and a red subject: the S41 red) ·
# 2 = harness defect (red control; no S41 verdict) · 3 = REFUSED before
# any node started (isolation, signature, digest or preflight).
#
# Not wired into scripts/local-gate.sh or any workflow (D177): a standing
# manual check, like scripts/e2e-sepolia.sh, re-run at Q34's date.
set -uo pipefail

script="$(readlink -f "${BASH_SOURCE[0]}")"
repo="$(cd "$(dirname "$script")/.." && pwd)"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m::warning::s41-interop: %s\033[0m\n' "$*" >&2; }
fail_msg() { printf '\033[31m::error::s41-interop: %s\033[0m\n' "$*" >&2; }
die()  { fail_msg "$*"; exit 1; }
# A named refusal: one greppable line, exit 3, and the promise that no node,
# chain or suite was started by this invocation.
refuse() { # <REASON> <explanation…>
  local reason="$1"; shift
  fail_msg "REFUSED reason=$reason — $*"
  printf 's41-interop: REFUSED reason=%s commit=%s\n' "$reason" "$(head_sha)"
  exit 3
}
head_sha() { git -C "$repo" rev-parse --short=7 HEAD 2>/dev/null || echo nogit; }

# ── Pins (each a reviewed value; a change is a deliberate event) ──────────
#
# The release-signing key embedded in ant-node's src/upgrade/signature.rs
# (`RELEASE_SIGNING_KEY`, ML-DSA-65, 1952 bytes). Measured 2026-10-16: the
# file is byte-identical at tags v0.15.0 and v0.22.0, and the crates.io
# ant-node 0.22.0 crate carries the same key. The crate's own
# sign/release-signing-key.pub is a DIFFERENT key and does not verify the
# releases (D177 M7) — never use it.
readonly SIGNING_CONTEXT='ant-node-release-v1'
readonly RELEASE_KEY_SHA256='163f903d7b56cede4a049fe3eb871d8ac434b124059d992932f07f4ce1606643'
readonly ARCHIVE_NAME='ant-node-cli-linux-x64.tar.gz'
readonly UPSTREAM_REPO='WithAutonomi/ant-node'
# The dev pin: the node version ant-core 0.5.0 was developed against, and
# the control arm (Cargo.toml `ant-node = "=0.15.0"`).
readonly CONTROL_TAG='v0.15.0'
# Archive digests measured 2026-10-16: file = SHA256SUMS = API digest.
# Every release this harness has verified stays in the table. An unknown tag
# is accepted on SHA256SUMS = API digest alone, and says so (pin=none).
known_archive_sha256() {
  case "$1" in
    v0.15.0) printf '%s' 1dacf3ce27c5bbc5e448337c9fbd9ceeddd4652c1b9334ca353f9a35ae026e5d ;;
    v0.22.0) printf '%s' 993671ed54925f0bbae5beae4d40425a1efd61925396b8a26482dba997b85e8b ;;
    v0.23.0) printf '%s' 5962825adb28604af4cf1a710bcb533dccc616ddf636bff7f182f326eefd39b3 ;;
    *) printf '' ;;
  esac
}
# The payment contracts, from the PINNED evmlib's artifacts (byte-identical
# to evmlib 0.10.0's, D177 M11). The two files are in DIFFERENT formats:
# AutonomiNetworkToken.json is Hardhat's (`.bytecode` is a hex string) and
# PaymentVaultV2.json is Foundry's (`.bytecode.object` is). Reading the token
# with `.bytecode.object` yields nothing, and cast then deploys an empty
# contract without complaint (D177 R3) — hence a per-file type branch, a hex
# check, and on-chain code sizes.
readonly EVMLIB_VERSION='0.9.0'
readonly TOKEN_ARTIFACT_SHA256='28dcd8430214a9e82400916ead3f5146396b4f81d538c4294bf514714430a6d7'
readonly VAULT_ARTIFACT_SHA256='75e14932dc2a297b5ccdd2bbbff5e39769c47eda4382c98a0e3d94704a80feb5'
readonly TOKEN_CODE_BYTES=7889 VAULT_CODE_BYTES=3937
readonly PREMINE_ATTO='2500000000000000000000000'
readonly BATCH_LIMIT=512
readonly NODES=14 BOOTSTRAP_NODES=3 BASE_PORT=20001 ANVIL_PORT=18545 CHAIN_ID=31337
# Account 0 pays; accounts 1..14 are the nodes' DISTINCT rewards addresses
# (D177 R5: with one shared address the node's redirection check cannot
# fail, so it would test nothing).
readonly ANVIL_ACCOUNTS=16
# The paths D177's amendment names, relative to the operator's home.
readonly RULED_SECRET_PATHS='.minisign .ssh .gnupg .config/gh .local/share/ant .cargo/credentials .cargo/credentials.toml'
readonly SYS_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly DROP_CAPS='setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs --'

# Key-name-scoped redaction, e2e-devnet.sh's filter verbatim (project rule
# 6 binds the PATTERN: the Anvil dev key is public and guards nothing, and
# it still never reaches a capture). Digests and addresses survive.
redact() {
  sed -E "$@" "s/(wallet_private_key|[A-Za-z_]*PRIVATE_KEY|[A-Za-z_]*SECRET_KEY)([\"']?[[:space:]]*[:=][[:space:]]*[\"']?)(0x)?[0-9a-fA-F]{8,}/\1\2<redacted>/g"
}
capture_through() { redact -u | tee "$1"; }

# Strip terminal control sequences from text another program wrote (node
# logs are the node's own words; they never reach the terminal raw).
sanitize() { sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -cd '\11\12\40-\176'; }

# ── Parameters across the namespace boundary ──────────────────────────────
#
# The outer harness writes KEY=VALUE lines BEFORE anything untrusted
# starts; the inner side reads them, never sources them.
param() { # <file> <KEY>
  local n
  n="$(grep -c "^$2=" "$1" 2>/dev/null)"
  if [ "$n" != 1 ]; then
    fail_msg "parameter $2 appears ${n:-0} times in $1 (exactly once wanted)"
    return 1
  fi
  sed -n "s/^$2=//p" "$1"
}

# ── Python helpers (stdlib only, run with -I) ─────────────────────────────
s41_py() {
  cat <<'PY'
import hashlib, json, re, sys

def ver(t):
    core = t.lstrip("v").split("+")[0]
    if "-" in core:
        return None
    try:
        return tuple(int(x) for x in core.split("."))
    except ValueError:
        return None

cmd = sys.argv[1]
if cmd == "release-meta":           # <release.json> <tag> <asset>
    rel = json.load(open(sys.argv[2], encoding="utf-8"))
    tag, name = sys.argv[3], sys.argv[4]
    assets = [a for a in rel.get("assets", []) if a.get("name") == name]
    if rel.get("tag_name") != tag or len(assets) != 1:
        sys.exit(f"release.json is for tag {rel.get('tag_name')!r} with {len(assets)} asset(s) named {name}")
    dig = assets[0].get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", dig):
        sys.exit(f"the API carries no sha256 digest for {name} ({dig!r})")
    print(f"digest={dig[7:]} size={assets[0].get('size')} draft={rel.get('draft')} "
          f"prerelease={rel.get('prerelease')} published={rel.get('published_at')}")
elif cmd == "latest":               # <releases.json>
    rels = json.load(open(sys.argv[2], encoding="utf-8"))
    final = [r for r in rels if not r.get("draft") and not r.get("prerelease")]
    final.sort(key=lambda r: r.get("published_at") or "", reverse=True)
    if not final:
        sys.exit("no non-prerelease release in the listing")
    print(final[0]["tag_name"])
elif cmd == "lag":                  # <releases.json> <ant-core.index> <control-tag>
    rels = json.load(open(sys.argv[2], encoding="utf-8"))
    tags = [r["tag_name"] for r in rels if not r.get("draft") and not r.get("prerelease")]
    pin = ver(sys.argv[4])
    if sys.argv[4] not in tags:
        sys.exit(f"{sys.argv[4]} is not in the listing; N cannot be counted from it")
    after = sorted((t for t in tags if ver(t) and ver(t) > pin), key=ver)
    core = [json.loads(l) for l in open(sys.argv[3], encoding="utf-8") if l.strip()]
    lag = sorted((c["vers"] for c in core if ver(c["vers"]) and ver(c["vers"]) > (0, 5, 0)
                  and not c.get("yanked")), key=ver)
    print(f"N={len(after)} N_tags={','.join(after)} ant_core_lag={len(lag)} ant_core_after_0.5.0={','.join(lag)}")
elif cmd == "extract-key":          # <signature.rs> <out.bin>
    src = open(sys.argv[2], encoding="utf-8").read()
    blocks = re.findall(r"const RELEASE_SIGNING_KEY: &\[u8\] = &\[(.*?)\];", src, re.S)
    if len(blocks) != 1:
        sys.exit(f"expected one RELEASE_SIGNING_KEY block, found {len(blocks)}")
    items = [t.strip() for t in blocks[0].split(",") if t.strip()]
    if not all(re.fullmatch(r"0x[0-9a-fA-F]{2}", t) for t in items):
        sys.exit("RELEASE_SIGNING_KEY holds an element that is not a 0xNN byte")
    key = bytes(int(t, 16) for t in items)
    ctx = re.findall(r'pub const SIGNING_CONTEXT: &\[u8\] = b"([^"]*)";', src)
    if len(key) != 1952 or len(ctx) != 1:
        sys.exit(f"key is {len(key)} bytes (1952 wanted), {len(ctx)} SIGNING_CONTEXT line(s)")
    open(sys.argv[3], "wb").write(key)
    print(f"key_sha256={hashlib.sha256(key).hexdigest()} context={ctx[0]}")
elif cmd == "tag-commit":           # <commit.json>
    sha = json.load(open(sys.argv[2], encoding="utf-8")).get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        sys.exit("no commit sha in the API answer")
    print(sha)
elif cmd == "flip":                 # <file> <offset>
    p, o = sys.argv[2], int(sys.argv[3])
    b = bytearray(open(p, "rb").read()); b[o] ^= 1; open(p, "wb").write(b)
elif cmd == "probe":                # isolation: egress must be unreachable, loopback alive
    import socket
    out = []
    for label, fam, addr in (("egress4", socket.AF_INET, ("192.0.2.1", 443)),
                             ("egress6", socket.AF_INET6, ("2001:db8::1", 443)),
                             ("loopback", socket.AF_INET, ("127.0.0.1", 9))):
        import errno
        s = None
        try:
            s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(3)
            s.connect(addr); out.append(f"{label}=CONNECTED")
        except OSError as e:
            out.append(f"{label}={errno.errorcode.get(e.errno, 'TIMEOUT' if e.errno is None else e.errno)}")
        finally:
            if s is not None:
                s.close()
    print(" ".join(out))
else:
    sys.exit(f"unknown helper {cmd}")
PY
}
s41py() { python3 -I -c "$(s41_py)" "$@"; }

# ── --fetch: read-only GETs into a new, empty directory ───────────────────
fetch_release() { # <tag|latest> <dir>
  local want="$1" dir="$2" api="https://api.github.com/repos/$UPSTREAM_REPO" tag f lag
  [ -n "$want" ] && [ -n "$dir" ] || die "--fetch needs TAG|latest and DIR"
  if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    die "--fetch: $dir is not empty — downloads are untrusted data and go into a new, empty directory"
  fi
  mkdir -p "$dir" || die "cannot create $dir"
  get() { curl -sSfL --proto '=https' --proto-redir '=https' --max-time 300 --retry 2 -o "$2" "$1" \
            || die "GET $1 failed"; }
  get "$api/releases?per_page=100" "$dir/releases.json"
  if [ "$want" = latest ]; then tag="$(s41py latest "$dir/releases.json")" || die "no latest release"; else tag="$want"; fi
  [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "not a release tag: $tag"
  note "fetching ant-node $tag (read-only GETs)"
  get "$api/releases/tags/$tag" "$dir/release.json"
  for f in "$ARCHIVE_NAME" "$ARCHIVE_NAME.sig" SHA256SUMS.txt; do
    get "https://github.com/$UPSTREAM_REPO/releases/download/$tag/$f" "$dir/$f"
  done
  get "https://raw.githubusercontent.com/$UPSTREAM_REPO/$tag/src/upgrade/signature.rs" "$dir/signature.rs"
  get "$api/commits/$tag" "$dir/tag-commit.json"
  get "https://index.crates.io/an/t-/ant-core" "$dir/ant-core.index"
  printf 'tag=%s\nfetched_at=%s\n' "$tag" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$dir/fetch.txt"
  lag="$(s41py lag "$dir/releases.json" "$dir/ant-core.index" "$CONTROL_TAG" 2>&1)" || lag="(not counted: $lag)"
  printf 's41-interop: FETCHED tag=%s archive_sha256=%s lag: %s\n' "$tag" \
    "$(sha256sum "$dir/$ARCHIVE_NAME" | awk '{print $1}')" "$lag"
  note "nothing was verified or executed; the run verifies before it extracts"
}

# ── Identity of an arm: digests, release key, signature, extraction ───────
SIG_STATE=unchecked
SIGCHECK=""
ALLOW_UNCHECKED=0

# A verifier is believed only if it can say NO: the genuine archive must
# verify, and a one-byte-flipped copy and a wrong context must not.
sig_verify() { # <key.bin> <archive> <scratch-dir>
  local key="$1" archive="$2" tmp="$3" out rc size flipped
  SIG_STATE=unchecked
  if [ -z "$SIGCHECK" ]; then
    [ "$ALLOW_UNCHECKED" = 1 ] || refuse SIGNATURE-UNCHECKED "no --sigcheck verifier was given, so the ML-DSA-65 signature of ${archive##*/} cannot be checked. Build the verifier (docs/devnet/foreign-node-interop.md, \"The verifier\"), or pass --allow-unchecked-signature to run with sig=unchecked on the verdict line"
    warn "running WITHOUT a signature check: the verdict line will say sig=unchecked"
    return 0
  fi
  [ -x "$SIGCHECK" ] || refuse SIGNATURE "--sigcheck $SIGCHECK is not an executable file"
  size="$(stat -c %s "$archive")"
  out="$("$SIGCHECK" "$key" "$archive" "$archive.sig" "$SIGNING_CONTEXT" 2>&1)"; rc=$?
  if [ "$rc" != 0 ] || [ "$out" != "VERIFY OK ctx=\"$SIGNING_CONTEXT\" msg_len=$size" ]; then
    refuse SIGNATURE "the archive's ML-DSA-65 signature does not verify: $(sanitize <<<"$out") (rc=$rc)"
  fi
  flipped="$tmp/flipped-${archive##*/}"
  cp "$archive" "$flipped" && s41py flip "$flipped" "$((size / 2))" \
    || refuse SIGNATURE "cannot build the flipped-byte negative control"
  out="$("$SIGCHECK" "$key" "$flipped" "$archive.sig" "$SIGNING_CONTEXT" 2>&1)"; rc=$?
  rm -f "$flipped"
  if [ "$rc" != 1 ] || ! grep -q '^VERIFY FAIL' <<<"$out"; then
    refuse SIGNATURE "the verifier ACCEPTED an archive with one flipped byte (rc=$rc) — a verifier that cannot say no is not a verifier"
  fi
  out="$("$SIGCHECK" "$key" "$archive" "$archive.sig" "${SIGNING_CONTEXT}-wrong" 2>&1)"; rc=$?
  if [ "$rc" != 1 ] || ! grep -q '^VERIFY FAIL' <<<"$out"; then
    refuse SIGNATURE "the verifier ACCEPTED the wrong signing context (rc=$rc) — a verifier that cannot say no is not a verifier"
  fi
  SIG_STATE=ok
  printf 'signature: VERIFY OK ctx="%s" msg_len=%s; flipped byte -> VERIFY FAIL; wrong context -> VERIFY FAIL\n' \
    "$SIGNING_CONTEXT" "$size"
}

# D177 R5: extract ONLY the ant-node member. bootstrap_peers.toml beside the
# binary is the first place the node looks for mainnet peers.
extract_node() { # <archive> <bindir>
  local members
  members="$(tar -tvzf "$1" 2>/dev/null | awk '$NF == "ant-node" {print substr($1, 1, 1)}')"
  [ "$members" = "-" ] || refuse ARCHIVE "the archive must hold exactly one regular-file member named ant-node (found: [$(tr '\n' ' ' <<<"$members")])"
  mkdir -p "$2" || refuse ARCHIVE "cannot create $2"
  tar -xzf "$1" -C "$2" --no-same-owner --no-same-permissions ant-node || refuse ARCHIVE "cannot extract ant-node from $1"
  [ -f "$2/ant-node" ] && [ ! -L "$2/ant-node" ] || refuse ARCHIVE "the extracted ant-node is not a regular file"
  [ "$(ls -A "$2")" = ant-node ] || refuse ARCHIVE "$2 holds more than the ant-node member"
  chmod 0555 "$2/ant-node"
}

# verify_arm <label> <fetched-dir> <armdir>: every identity check, before
# anything is extracted; writes <armdir>/results/identity (KEY=VALUE).
verify_arm() {
  local label="$1" src="$2" armdir="$3" tag archive actual sums_hex meta api_hex api_size draft pre published known pin keyline key_sha ctx commit bin_sha
  [ -f "$src/fetch.txt" ] || refuse NOT-FETCHED "$src holds no fetch.txt — fill it with: scripts/s41-interop.sh --fetch <tag> $src"
  tag="$(param "$src/fetch.txt" tag)" || refuse NOT-FETCHED "$src/fetch.txt names no tag"
  archive="$src/$ARCHIVE_NAME"
  local f
  for f in "$archive" "$archive.sig" "$src/SHA256SUMS.txt" "$src/release.json" "$src/signature.rs" "$src/tag-commit.json"; do
    [ -s "$f" ] || refuse NOT-FETCHED "$f is missing or empty"
  done
  mkdir -p "$armdir/results" "$armdir/bin" || refuse PREFLIGHT "cannot create $armdir"
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  sums_hex="$(awk -v n="$ARCHIVE_NAME" '$2 == n || $2 == "*" n {print $1}' "$src/SHA256SUMS.txt")"
  [ "$(grep -c . <<<"$sums_hex")" = 1 ] || refuse DIGEST "SHA256SUMS.txt must name $ARCHIVE_NAME exactly once"
  meta="$(s41py release-meta "$src/release.json" "$tag" "$ARCHIVE_NAME" 2>&1)" || refuse DIGEST "$meta"
  api_hex="$(sed -n 's/.*digest=\([0-9a-f]*\).*/\1/p' <<<"$meta")"
  api_size="$(sed -n 's/.*size=\([0-9]*\).*/\1/p' <<<"$meta")"
  draft="$(sed -n 's/.*draft=\([A-Za-z]*\).*/\1/p' <<<"$meta")"
  pre="$(sed -n 's/.*prerelease=\([A-Za-z]*\).*/\1/p' <<<"$meta")"
  published="$(sed -n 's/.*published=\([^ ]*\).*/\1/p' <<<"$meta")"
  [ "$actual" = "$sums_hex" ] || refuse DIGEST "$label: archive sha256 $actual != SHA256SUMS.txt's $sums_hex"
  [ "$actual" = "$api_hex" ] || refuse DIGEST "$label: archive sha256 $actual != the release API's digest $api_hex"
  [ "$(stat -c %s "$archive")" = "$api_size" ] || refuse DIGEST "$label: archive size != the release API's $api_size"
  known="$(known_archive_sha256 "$tag")"; pin=none
  if [ -n "$known" ]; then
    [ "$actual" = "$known" ] || refuse DIGEST "$label: archive sha256 $actual != the digest this script pins for $tag ($known)"
    pin=match
  fi
  [ "$draft" = False ] && [ "$pre" = False ] || refuse RELEASE "$label: $tag is a draft or a prerelease (draft=$draft prerelease=$pre); the subject is the latest NON-prerelease and the control is $CONTROL_TAG"
  keyline="$(s41py extract-key "$src/signature.rs" "$armdir/results/release-key.bin" 2>&1)" || refuse KEY "$label: $keyline"
  key_sha="$(sed -n 's/^key_sha256=\([0-9a-f]*\).*/\1/p' <<<"$keyline")"
  ctx="$(sed -n 's/.* context=\(.*\)$/\1/p' <<<"$keyline")"
  [ "$key_sha" = "$RELEASE_KEY_SHA256" ] || refuse KEY "$label: the key embedded in signature.rs at $tag has sha256 $key_sha, not the pinned $RELEASE_KEY_SHA256 — upstream rotated its release key; re-pin only after reviewing why"
  [ "$ctx" = "$SIGNING_CONTEXT" ] || refuse KEY "$label: signature.rs at $tag signs under context '$ctx', not '$SIGNING_CONTEXT'"
  sig_verify "$armdir/results/release-key.bin" "$archive" "$armdir/results"
  extract_node "$archive" "$armdir/bin"
  commit="$(s41py tag-commit "$src/tag-commit.json" 2>/dev/null || echo unknown)"
  bin_sha="$(sha256sum "$armdir/bin/ant-node" | awk '{print $1}')"
  {
    printf 'tag=%s\narchive_sha256=%s\nsig=%s\npin=%s\nbin_sha256=%s\ntag_commit=%s\npublished=%s\nkey_sha256=%s\n' \
      "$tag" "$actual" "$SIG_STATE" "$pin" "$bin_sha" "$commit" "$published" "$key_sha"
  } > "$armdir/results/identity"
  printf '%s: ant-node %s archive_sha256=%s (= SHA256SUMS = API digest, pin=%s) sig=%s key_sha256=%s… tag_commit=%s\n' \
    "$label" "$tag" "$actual" "$pin" "$SIG_STATE" "${key_sha:0:16}" "${commit:0:7}"
}

# ── The namespace: isolation, masking, proofs ─────────────────────────────

# FIRST thing inside, before any parameter is trusted. Short-circuits:
# egress is probed only once links and routes already show there is
# nowhere to go, so a harness entered without its network namespace never
# sends a packet — it refuses on the interface list.
assert_isolated() {
  local links r4 r6 probe
  ip link set lo up 2>/dev/null
  links="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | LC_ALL=C sort | paste -sd, -)"
  r4="$(ip -4 route show table main 2>/dev/null | paste -sd';' -)"
  r6="$(ip -6 route show table main 2>/dev/null | paste -sd';' -)"
  if [ "$links" != lo ] || [ -n "$r4" ] || [ -n "$r6" ]; then
    fail_msg "REFUSED reason=NOT-ISOLATED — not inside an isolated network namespace: links=[$links] routes4(main)=[$r4] routes6(main)=[$r6]; no node, chain or suite was started"
    return 1
  fi
  probe="$(s41py probe 2>&1)"
  case "$probe" in
    "egress4=ENETUNREACH egress6=ENETUNREACH loopback=ECONNREFUSED"|"egress4=ENETUNREACH egress6=EAFNOSUPPORT loopback=ECONNREFUSED") ;;
    *) fail_msg "REFUSED reason=NOT-ISOLATED — links and routes look isolated but the socket probe says: $probe; no node, chain or suite was started"
       return 1 ;;
  esac
  printf 'isolation: links=[lo] routes4(main)=[] routes6(main)=[] %s\n' "$probe"
}

# mask_view <view> <spec>… — spec is rw:<abs path> or ro:<abs path>. Every
# mask root becomes an empty tmpfs and each spec is bound back at its own
# path. Specs are stashed on a private tmpfs first: once the home is masked
# there is no path left to bind them from. Needs namespace root.
mask_view() {
  local view="$1"; shift
  local -a specs=("$@") roots keep=()
  local s p m i ok
  roots=("$S41_OPHOME" /tmp /var/tmp "/run/user/$S41_OPUID")
  for s in "${specs[@]}"; do
    p="${s#*:}"
    case "$p" in /*) ;; *) fail_msg "mask($view): $p is not absolute"; return 1 ;; esac
    for m in "${roots[@]}" /dev/shm; do
      if [ "$p" = "$m" ] || [[ $m == "$p"/* ]]; then
        fail_msg "mask($view): bind-back $p would re-expose the mask root $m"; return 1
      fi
    done
  done
  # A spec inside another spec is already visible through it — and its
  # mountpoint would otherwise be created in the real filesystem.
  for s in "${specs[@]}"; do
    p="${s#*:}"; ok=1
    for i in "${specs[@]}"; do
      [ "$i" = "$s" ] && continue
      if [[ $p == "${i#*:}"/* ]]; then ok=0; fi
    done
    if [ "$ok" = 1 ]; then keep+=("$s"); fi
  done
  mount -n -t tmpfs -o mode=0700,size=1m s41-stash /dev/shm || { fail_msg "mask($view): cannot mount the stash"; return 1; }
  i=0
  for s in "${keep[@]}"; do
    p="${s#*:}"
    mkdir -p "/dev/shm/b$i" && mount -n --rbind "$p" "/dev/shm/b$i" || { fail_msg "mask($view): cannot stash $p"; return 1; }
    if [ "${s%%:*}" = ro ]; then
      mount -n -o remount,bind,ro "/dev/shm/b$i" || { fail_msg "mask($view): cannot make $p read-only"; return 1; }
    fi
    i=$((i + 1))
  done
  for m in "${roots[@]}"; do
    [ -d "$m" ] || continue
    mount -n -t tmpfs -o mode=0755,size=512m,nosuid,nodev "s41-mask-$view" "$m" || { fail_msg "mask($view): cannot mask $m"; return 1; }
  done
  i=0
  for s in "${keep[@]}"; do
    p="${s#*:}"
    mkdir -p "$p" && mount -n --move "/dev/shm/b$i" "$p" || { fail_msg "mask($view): cannot bind $p back"; return 1; }
    i=$((i + 1))
  done
  umount -n /dev/shm && mount -n -t tmpfs -o mode=1777,size=64m,nosuid,nodev "s41-shm-$view" /dev/shm \
    || { fail_msg "mask($view): cannot mask /dev/shm"; return 1; }
}

# ~/.cargo is bound back for the suites' cargo, so its credentials files —
# the ruled ~/.cargo/credentials* — are overlaid with /dev/null.
mask_cargo_credentials() {
  local f
  for f in "$S41_CARGO_HOME/credentials" "$S41_CARGO_HOME/credentials.toml"; do
    if [ -e "$f" ]; then mount -n --bind /dev/null "$f" || { fail_msg "cannot overlay $f"; return 1; }; fi
  done
}

# prove_view <view> <allowed-home-entries> [prefix…] — the masks as a
# WORKLOAD sees them (no capabilities, empty environment). With a prefix
# (nsenter -t PID -m --) it reads another view from outside it. Prints one
# line per claim and returns nonzero if any fails.
prove_view() {
  local view="$1" allowed="$2"; shift 2
  local -a pre=("$@")
  local fails=0 p path inside seen extra n_pids
  wl() { "${pre[@]}" $DROP_CAPS env -i PATH="$SYS_PATH" "$@"; }
  if wl cat "$S41_CANARY" >/dev/null 2>&1; then
    printf 'masking(%s): canary READABLE at its own path — FAIL\n' "$view"; fails=1
  else
    printf 'masking(%s): canary unreadable (it is readable outside)\n' "$view"
  fi
  for p in $RULED_SECRET_PATHS; do
    path="$S41_OPHOME/$p"
    if wl test -c "$path"; then inside='masked(/dev/null)'
    elif wl test -e "$path"; then inside=EXPOSED; fails=1
    else inside=absent; fi
    printf 'masking(%s): ~/%s outside=%s inside=%s\n' "$view" "$p" "$(param "$S41_PARAMS" "OUT_$(tr '/.' '__' <<<"$p")" 2>/dev/null || echo '?')" "$inside"
  done
  seen="$(wl ls -A "$S41_OPHOME" 2>/dev/null | LC_ALL=C sort | paste -sd, -)"
  extra=""
  for p in ${seen//,/ }; do
    case ",$allowed," in *",$p,"*) ;; *) extra+="$p " ;; esac
  done
  if [ -n "$extra" ]; then
    printf 'masking(%s): the home shows entries that are not bind-backs: %s— FAIL\n' "$view" "$extra"; fails=1
  else
    printf 'masking(%s): the home shows [%s] (outside: %s entries), all bind-backs\n' "$view" "$seen" "$(param "$S41_PARAMS" OUT_HOME_ENTRIES 2>/dev/null || echo '?')"
  fi
  if [ -n "$(wl ls -A "/run/user/$S41_OPUID" 2>/dev/null)" ]; then
    printf 'masking(%s): /run/user/<uid> is NOT empty — FAIL\n' "$view"; fails=1
  else
    printf 'masking(%s): /run/user/<uid> empty (agent, bus and terminal sockets unreachable)\n' "$view"
  fi
  if [ -n "${S41_AGENT_SOCK:-}" ] && wl test -e "$S41_AGENT_SOCK"; then
    printf 'masking(%s): the ssh-agent socket path is visible — FAIL\n' "$view"; fails=1
  fi
  if wl umount -n /tmp >/dev/null 2>&1; then
    printf 'masking(%s): a workload could UNMOUNT /tmp — FAIL\n' "$view"; fails=1
  else
    printf 'masking(%s): a workload cannot unmount a mask (no capabilities)\n' "$view"
  fi
  n_pids="$(wl ls /proc 2>/dev/null | grep -c '^[0-9][0-9]*$')"
  printf 'masking(%s): %s process(es) visible in this view'"'"'s /proc\n' "$view" "$n_pids"
  return "$fails"
}

# ── L1: the chain ─────────────────────────────────────────────────────────
# Every workload: no capabilities, empty environment plus what it needs.
wl_env() { $DROP_CAPS env -i PATH="$S41_FOUNDRY_BIN:$SYS_PATH" LANG=C.UTF-8 TZ=UTC "$@"; }
rpc_url() { printf 'http://127.0.0.1:%s/' "$ANVIL_PORT"; }
cast_() { wl_env HOME="$RES/cast-home" "$S41_FOUNDRY_BIN/cast" "$@"; }

start_anvil() {
  mkdir -p "$RES/anvil-home" "$RES/cast-home"
  wl_env HOME="$RES/anvil-home" "$S41_FOUNDRY_BIN/anvil" --host 127.0.0.1 --port "$ANVIL_PORT" \
    --chain-id "$CHAIN_ID" --accounts "$ANVIL_ACCOUNTS" --config-out "$RES/anvil.json" \
    < /dev/null > "$RES/anvil.log" 2>&1 &
  ANVIL_PID=$!
  local i
  for i in $(seq 1 100); do
    [ "$(cast_ chain-id --rpc-url "$(rpc_url)" 2>/dev/null)" = "$CHAIN_ID" ] && [ -s "$RES/anvil.json" ] && return 0
    sleep 0.2
  done
  fail_msg "Anvil did not answer eth_chainId=$CHAIN_ID within 20 s (see anvil.log)"
  return 1
}

# The pinned artifact's creation bytecode as non-empty 0x-hex, or a refusal:
# Hardhat's string form or Foundry's {object: …} form, nothing else.
artifact_bytecode() { # <artifact.json>
  local code
  code="$(jq -er '.bytecode | if type == "string" then . elif type == "object" and (.object | type) == "string" then .object else error("no bytecode") end' "$1" 2>/dev/null)" || code=""
  if ! [[ $code =~ ^0x([0-9a-fA-F]{2})+$ ]]; then
    fail_msg "bytecode extraction from ${1##*/} produced $(( ${#code} > 2 ? (${#code} - 2) / 2 : 0 )) bytes of hex — refusing to deploy an empty contract"
    return 1
  fi
  printf '%s' "$code"
}

code_bytes() { # <address> → on-chain code size in bytes
  local hex
  hex="$(cast_ code --rpc-url "$(rpc_url)" "$1" 2>/dev/null)" || hex=""
  [[ $hex =~ ^0x([0-9a-fA-F]{2})*$ ]] || { printf 'unreadable'; return; }
  printf '%s' $(( (${#hex} - 2) / 2 ))
}

assert_code_size() { # <label> <address> <expected-bytes>
  local got
  got="$(code_bytes "$2")"
  if [ "$got" != "$3" ]; then
    fail_msg "$1 code bytes: $got (expected $3) at $2 — the contract is not what the pinned artifact deploys"
    return 1
  fi
  printf 'deploy: %s code bytes: %s\n' "$1" "$got"
}

deploy_contracts() {
  local art token_code vault_code acct0 bal anttoken limit
  art="$(find "$S41_CARGO_HOME/registry/src" -maxdepth 2 -type d -name "evmlib-$EVMLIB_VERSION" 2>/dev/null | LC_ALL=C sort | head -1)/artifacts"
  [ -d "$art" ] || { fail_msg "the pinned evmlib $EVMLIB_VERSION artifacts are not in the cargo registry (build the workspace once)"; return 1; }
  [ "$(sha256sum "$art/AutonomiNetworkToken.json" | awk '{print $1}')" = "$TOKEN_ARTIFACT_SHA256" ] \
    && [ "$(sha256sum "$art/PaymentVaultV2.json" | awk '{print $1}')" = "$VAULT_ARTIFACT_SHA256" ] \
    || { fail_msg "an evmlib $EVMLIB_VERSION artifact's sha256 differs from the pin"; return 1; }
  token_code="$(artifact_bytecode "$art/AutonomiNetworkToken.json")" || return 1
  vault_code="$(artifact_bytecode "$art/PaymentVaultV2.json")" || return 1
  acct0="$(jq -r '.available_accounts[0]' "$RES/anvil.json")"
  TOKEN="$(cast_ send --rpc-url "$(rpc_url)" --unlocked --from "$acct0" --json --create "$token_code" 2>>"$RES/deploy.err" | jq -r '.contractAddress // empty')"
  [[ $TOKEN =~ ^0x[0-9a-fA-F]{40}$ ]] || { fail_msg "the token deployment returned no contract address (deploy.err)"; return 1; }
  VAULT="$(cast_ send --rpc-url "$(rpc_url)" --unlocked --from "$acct0" --json --create "$vault_code" \
           'constructor(address,uint256)' "$TOKEN" "$BATCH_LIMIT" 2>>"$RES/deploy.err" | jq -r '.contractAddress // empty')"
  [[ $VAULT =~ ^0x[0-9a-fA-F]{40}$ ]] || { fail_msg "the vault deployment returned no contract address (deploy.err)"; return 1; }
  printf 'deploy: token %s vault %s (evmlib %s artifacts, sha256 pinned)\n' "$TOKEN" "$VAULT" "$EVMLIB_VERSION"
  assert_code_size token "$TOKEN" "$TOKEN_CODE_BYTES" || return 1
  assert_code_size vault "$VAULT" "$VAULT_CODE_BYTES" || return 1
  bal="$(cast_ call --rpc-url "$(rpc_url)" "$TOKEN" 'balanceOf(address)(uint256)' "$acct0" 2>/dev/null | awk '{print $1}')"
  [ "$bal" = "$PREMINE_ATTO" ] || { fail_msg "token.balanceOf(payer) = ${bal:-?}, expected $PREMINE_ATTO"; return 1; }
  anttoken="$(cast_ call --rpc-url "$(rpc_url)" "$VAULT" 'antToken()(address)' 2>/dev/null)"
  [ "${anttoken,,}" = "${TOKEN,,}" ] || { fail_msg "vault.antToken() = ${anttoken:-?}, expected the token $TOKEN"; return 1; }
  limit="$(cast_ call --rpc-url "$(rpc_url)" "$VAULT" 'batchLimit()(uint256)' 2>/dev/null | awk '{print $1}')"
  [ "$limit" = "$BATCH_LIMIT" ] || { fail_msg "vault.batchLimit() = ${limit:-?}, expected $BATCH_LIMIT"; return 1; }
  printf 'deploy: token.balanceOf(payer)=%s vault.antToken()=token vault.batchLimit()=%s\n' "$bal" "$limit"
}

# D177 R5: distinct rewards addresses, none of them the payer's.
assert_distinct_rewards() { # <newline-separated addresses> <payer>
  local n distinct
  n="$(grep -c . <<<"$1")"
  distinct="$(tr 'A-F' 'a-f' <<<"$1" | LC_ALL=C sort -u | grep -c .)"
  if [ "$n" != "$NODES" ] || [ "$distinct" != "$NODES" ]; then
    fail_msg "rewards addresses not distinct: $distinct of $n (want $NODES of $NODES)"; return 1
  fi
  if grep -qix -- "$2" <<<"$1"; then
    fail_msg "a node's rewards address is the payer's own"; return 1
  fi
  printf 'rewards: %s of %s distinct, none is the payer\n' "$distinct" "$n"
}

# ── L2: the node view and the node supervisor ─────────────────────────────
#
# Runs as `bash -c "<declarations>; l2_main"` in a nested mount + pid
# namespace (launch_l2). It masks again WITHOUT the repository and the
# cargo/rustup homes, signals L1, waits for L1's go (L1 proves this view
# from outside first), then drops every capability and starts the nodes.
l2_main() {
  mask_view l2 "rw:$S41_NODES" "ro:$S41_BINDIR" || exit 4
  $DROP_CAPS env -i PATH="$SYS_PATH" HOME="$S41_NODES" "$S41_BINDIR/ant-node" --version \
    < /dev/null > "$S41_NODES/version.txt" 2>&1
  : > "$S41_NODES/.l2-masked"
  local i=0
  while [ ! -e "$S41_NODES/.l2-go" ]; do
    i=$((i + 1)); [ "$i" -le 600 ] || exit 5
    sleep 0.1
  done
  exec $DROP_CAPS env -i PATH="$SYS_PATH" S41_NODES="$S41_NODES" S41_BINDIR="$S41_BINDIR" \
    S41_N="$NODES" S41_BOOT_N="$BOOTSTRAP_NODES" S41_BASE_PORT="$BASE_PORT" S41_RPC="$S41_RPC" \
    S41_TOKEN="$S41_TOKEN" S41_VAULT="$S41_VAULT" S41_REWARDS="$S41_REWARDS" S41_READY_MSG="$S41_READY_MSG" \
    bash -c "$(declare -f l2_nodes); l2_nodes"
}

# PID 1 of the node namespace, capability-free. Upstream's own devnet shape
# (ant-node src/devnet.rs): three bootstrap nodes with no peers, then the
# rest bootstrapping from those three, 200 ms apart.
l2_nodes() {
  local i port dir rw k
  local -a boot=() reward
  IFS=, read -r -a reward <<<"$S41_REWARDS"
  for k in $(seq 1 "$S41_BOOT_N"); do boot+=(--bootstrap "127.0.0.1:$((S41_BASE_PORT + k - 1))"); done
  for i in $(seq 1 "$S41_N"); do
    port=$((S41_BASE_PORT + i - 1)); dir="$S41_NODES/node-$(printf %02d "$i")"
    mkdir -p "$dir/root" "$dir/home" "$dir/xdg/config" "$dir/xdg/data" "$dir/xdg/cache" "$dir/xdg/state" "$dir/xdg/run"
    rw="${reward[$((i - 1))]}"
    local -a extra=()
    [ "$i" -gt "$S41_BOOT_N" ] && extra=("${boot[@]}")
    env -i PATH=/usr/bin:/bin HOME="$dir/home" XDG_CONFIG_HOME="$dir/xdg/config" XDG_DATA_HOME="$dir/xdg/data" \
      XDG_CACHE_HOME="$dir/xdg/cache" XDG_STATE_HOME="$dir/xdg/state" XDG_RUNTIME_DIR="$dir/xdg/run" \
      ANT_BOOTSTRAP_PEERS_PATH="$dir/no-such-bootstrap-peers.toml" ANT_DISABLE_WEBRTC_DIRECT=true RUST_BACKTRACE=1 \
      "$S41_BINDIR/ant-node" --root-dir "$dir/root" --port "$port" --ipv4-only --network-mode development \
      --metrics-port 0 --rewards-address "$rw" --evm-rpc-url "$S41_RPC" --evm-payment-token "$S41_TOKEN" \
      --evm-payment-vault "$S41_VAULT" --enable-logging --log-format json --log-level info --stop-on-upgrade \
      "${extra[@]}" < /dev/null > "$dir/node.log" 2>&1 &
    if [ "$i" -eq "$S41_BOOT_N" ]; then
      for k in $(seq 1 600); do
        [ "$(cat "$S41_NODES"/node-0[1-9]/node.log 2>/dev/null | grep -cF "$S41_READY_MSG")" -ge "$S41_BOOT_N" ] && break
        sleep 0.1
      done
    fi
    sleep 0.2
  done
  wait
}

# ── L1: launching, proving and watching the node view ─────────────────────
readonly READY_MSG='Node running, waiting for shutdown signal'
# 30x the measured boot (4 s, v0.15.0, 2026-10-16). A node that EXITS before
# it is ready fails the wait at once, with its own first lines (wait_ready).
BOOT_TIMEOUT=120

home_entries_of() { # <abs path>… → the first component of each path under the operator's home
  local p rel out=""
  for p in "$@"; do
    case "$p" in "$S41_OPHOME"/*) rel="${p#"$S41_OPHOME"/}"; out+="${rel%%/*},";; esac
  done
  printf '%s' "${out%,}"
}

launch_l2() {
  local decl i
  rm -f "$S41_NODES/.l2-masked" "$S41_NODES/.l2-go"
  decl="$(declare -p SYS_PATH DROP_CAPS NODES BOOTSTRAP_NODES BASE_PORT S41_OPHOME S41_OPUID S41_NODES \
           S41_BINDIR S41_RPC S41_TOKEN S41_VAULT S41_REWARDS S41_READY_MSG); $(declare -f fail_msg mask_view l2_main l2_nodes)"
  unshare --mount --pid --fork --kill-child --mount-proc --propagation private \
    bash -c "$decl; l2_main" < /dev/null > "$RES/l2.out" 2>&1 &
  L2_UNSHARE=$!
  for i in $(seq 1 600); do
    [ -e "$S41_NODES/.l2-masked" ] && break
    sleep 0.1
  done
  [ -e "$S41_NODES/.l2-masked" ] || { fail_msg "the node view did not come up (l2.out)"; return 1; }
  L2_INIT="$(cat "/proc/$L2_UNSHARE/task/$L2_UNSHARE/children" 2>/dev/null | awk '{print $1}')"
  [[ $L2_INIT =~ ^[0-9]+$ ]] || { fail_msg "cannot find the node namespace's init"; return 1; }
}

# What only the node view must lack: the repository, the cargo home, and
# L1's own results (the funded key lives there).
prove_l2_extra() {
  local fails=0 p
  for p in "$S41_REPO/Cargo.toml" "$S41_CARGO_HOME/bin" "$RES/anvil.json" "$RES/params"; do
    if nsenter -t "$L2_INIT" -m -- $DROP_CAPS env -i PATH="$SYS_PATH" test -e "$p"; then
      printf 'masking(l2): %s is VISIBLE to the nodes — FAIL\n' "${p/#"$S41_OPHOME"/~}"; fails=1
    fi
  done
  [ "$fails" = 0 ] && printf 'masking(l2): the repository, the cargo home and L1'"'"'s results are invisible to the nodes\n'
  return "$fails"
}

node_dir() { printf '%s/node-%02d' "$S41_NODES" "$1"; }

wait_ready() {
  local i ready=0 deadline started
  deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
  EARLY_EXIT=""
  while :; do
    ready=0
    for i in $(seq 1 "$NODES"); do
      if grep -qF "$READY_MSG" "$(node_dir "$i")/node.log" 2>/dev/null; then ready=$((ready + 1)); fi
    done
    [ "$ready" = "$NODES" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    # Once every node has been started, a node process count below the node
    # count means a node EXITED before it was ready: fail now, in its words.
    started="$(cat "/proc/$L2_INIT/task/$L2_INIT/children" 2>/dev/null | wc -w)"
    if [ -s "$(node_dir "$NODES")/node.log" ] && [ "$started" -lt "$NODES" ]; then
      map_node_pids
      for i in $(seq 1 "$NODES"); do
        [ -n "${NODE_PIDS[$i]:-}" ] && continue
        EARLY_EXIT="node $i exited before the fleet was ready: $(head -2 "$(node_dir "$i")/node.log" 2>/dev/null | sanitize | paste -sd' ' - | cut -c1-200)"
        break
      done
      [ -n "$EARLY_EXIT" ] && break
    fi
    sleep 1
  done
  READY_COUNT="$ready"
  BOOT_SECS=$(( $(date +%s) - L2_STARTED ))
}

# Stabilization, upstream's criterion (ant-node src/devnet.rs: each node
# holds min(3, n-1) connections): every node has logged at least
# STABLE_PEERS distinct "Added peer <id> to DHT routing table" lines.
# Measured 2026-10-16 on v0.15.0: 176 such lines across 14 nodes within
# 50 s of boot. Only after this does any suite see the export.
readonly STABLE_PEERS=3
STABLE_TIMEOUT=180
dht_peers() { # <node.log> → distinct peers the node added to its routing table
  grep -o 'Added peer [0-9a-f]* to DHT routing table' "$1" 2>/dev/null | LC_ALL=C sort -u | grep -c .
}
wait_stable() {
  local i n least deadline t0
  t0="$(date +%s)"; deadline=$(( t0 + STABLE_TIMEOUT ))
  while :; do
    least=999
    for i in $(seq 1 "$NODES"); do
      n="$(dht_peers "$(node_dir "$i")/node.log")"
      [ "$n" -lt "$least" ] && least="$n"
    done
    [ "$least" -ge "$STABLE_PEERS" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 1
  done
  STABLE_LEAST="$least"; STABLE_SECS=$(( $(date +%s) - t0 ))
}

# index → pid (in L1's numbering): the supervisor's children, by --port.
map_node_pids() {
  local d p ppid port
  NODE_PIDS=()
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    ppid="$(awk '{print $4}' "$d/stat" 2>/dev/null)" || continue
    [ "$ppid" = "$L2_INIT" ] || continue
    port="$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | awk 'prev == "--port" {print; exit} {prev = $0}')"
    [[ $port =~ ^[0-9]+$ ]] || continue
    NODE_PIDS[$((port - BASE_PORT + 1))]="$p"
  done
}

# Liveness: every node that became ready must still be the same process.
# Prints one line per dead node; returns the number alive in LIVE_COUNT.
check_liveness() {
  local i p ppid dead=0
  LIVE_COUNT=0
  for i in $(seq 1 "$NODES"); do
    p="${NODE_PIDS[$i]:-}"
    ppid="$( [ -n "$p" ] && awk '{print $4}' "/proc/$p/stat" 2>/dev/null)"
    if [ -n "$p" ] && [ "$ppid" = "$L2_INIT" ]; then
      LIVE_COUNT=$((LIVE_COUNT + 1))
    else
      fail_msg "node $i (pid ${p:-none}) exited during the run"; dead=$((dead + 1))
    fi
  done
  return "$dead"
}

# The node's own claims (self-reported; the archive digest and signature are
# the identity proof): version and build commit from its first log line.
node_claims() { # <node.log> → "version=<v> commit=<c>"
  python3 -I -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if "ant-node starting" not in line:
        continue
    try:
        f = json.loads(line)
    except ValueError:
        continue
    if not isinstance(f, dict):
        continue
    f = f.get("fields", f) if isinstance(f.get("fields"), dict) else f
    print("version=%s commit=%s" % (f.get("version", "?"), f.get("commit", "?")))
    break
else:
    print("version=? commit=?")' "$1" 2>/dev/null | sanitize
}

write_export() {
  local key boot
  key="$(jq -r '.private_keys[0] // empty' "$RES/anvil.json")"
  [[ $key =~ ^0x[0-9a-fA-F]{64}$ ]] || { fail_msg "anvil.json carries no account-0 key"; return 1; }
  boot="$(for i in $(seq 0 $((NODES - 1))); do printf '127.0.0.1:%s\n' $((BASE_PORT + i)); done | paste -sd, -)"
  ( umask 077
    { printf "ANTSEAL_DEVNET_RPC_URL='%s'\n" "$(rpc_url)"
      printf "ANTSEAL_DEVNET_CHAIN_ID='%s'\n" "$CHAIN_ID"
      printf "ANTSEAL_DEVNET_TOKEN_ADDRESS='%s'\n" "$TOKEN"
      printf "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='%s'\n" "$VAULT"
      printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='%s'\n" "$key"
      printf "ANTSEAL_DEVNET_BOOTSTRAP='%s'\n" "$boot"
      printf "ANTSEAL_DEVNET_NODE_COUNT='%s'\n" "$NODES"
      printf "ANTSEAL_DEVNET_BASE_PORT='%s'\n" "$BASE_PORT"
      printf "ANTSEAL_DEVNET_DATA_DIR='%s'\n" "$S41_NODES"
      printf "ANTSEAL_DEVNET_PID='%s'\n" "$L2_UNSHARE"
    } > "$RES/devnet.env" )
  [ "$(cut -d= -f1 "$RES/devnet.env" | paste -sd, -)" = "ANTSEAL_DEVNET_RPC_URL,ANTSEAL_DEVNET_CHAIN_ID,ANTSEAL_DEVNET_TOKEN_ADDRESS,ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS,ANTSEAL_DEVNET_WALLET_PRIVATE_KEY,ANTSEAL_DEVNET_BOOTSTRAP,ANTSEAL_DEVNET_NODE_COUNT,ANTSEAL_DEVNET_BASE_PORT,ANTSEAL_DEVNET_DATA_DIR,ANTSEAL_DEVNET_PID" ] \
    || { fail_msg "the export does not carry the ten keys in the launcher's order"; return 1; }
  printf 'export: ten keys, the launcher'"'"'s order (crates/devnet-launcher/src/export.rs), pid %s is the node namespace\n' "$L2_UNSHARE"
}

# ── L1: the suites (D177 R6) and stage 0 (R10) ────────────────────────────
suite_env() {
  $DROP_CAPS env -i PATH="$S41_CARGO_HOME/bin:$S41_FOUNDRY_BIN:$SYS_PATH" HOME="$S41_SUITE_HOME" \
    CARGO_HOME="$S41_CARGO_HOME" RUSTUP_HOME="$S41_RUSTUP_HOME" CARGO_NET_OFFLINE=true \
    TMPDIR="$S41_TMPDIR" LANG=C.UTF-8 TZ=UTC "$@"
}

# One suite log → "listed=… passed=… failed=… ignored=… skip_lines=…".
# Any SKIP line is a FAIL (D177 R6): the suites print SKIP and return Ok
# when the export is missing, unparseable or names a dead pid.
suite_counts() { # <log> <listed>
  local passed failed ignored skips
  passed="$(sed -n 's/.*test result: [a-zA-Z]*\. \([0-9]*\) passed.*/\1/p' "$1" | awk '{s += $1} END {print s + 0}')"
  failed="$(sed -n 's/.*test result: [a-zA-Z]*\. [0-9]* passed; \([0-9]*\) failed.*/\1/p' "$1" | awk '{s += $1} END {print s + 0}')"
  ignored="$(sed -n 's/.*passed; [0-9]* failed; \([0-9]*\) ignored.*/\1/p' "$1" | awk '{s += $1} END {print s + 0}')"
  skips="$(grep -c 'SKIP:' "$1")"
  printf 'listed=%s passed=%s failed=%s ignored=%s skip_lines=%s' "$2" "$passed" "$failed" "$ignored" "$skips"
}

# PASS only if: exit 0, no SKIP line, nothing failed or ignored, and the
# passed count equals what `--list` enumerated (and is not zero).
suite_judgement() { # <exit> <counts line> → ok | FAIL:<why>
  local rc="$1" listed passed failed ignored skips
  listed="$(sed -n 's/.*listed=\([0-9]*\).*/\1/p' <<<"$2")"; passed="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$2")"
  failed="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$2")"; ignored="$(sed -n 's/.*ignored=\([0-9]*\).*/\1/p' <<<"$2")"
  skips="$(sed -n 's/.*skip_lines=\([0-9]*\).*/\1/p' <<<"$2")"
  if [ "$skips" != 0 ]; then printf 'FAIL:%s SKIP lines' "$skips"
  elif [ "$rc" != 0 ]; then printf 'FAIL:exit %s' "$rc"
  elif [ "$failed" != 0 ] || [ "$ignored" != 0 ]; then printf 'FAIL:%s failed, %s ignored' "$failed" "$ignored"
  elif [ "${listed:-0}" = 0 ] || [ "$passed" != "$listed" ]; then printf 'FAIL:passed %s != listed %s' "$passed" "$listed"
  else printf 'ok'; fi
}

run_suites() {
  local rows status task pkg feat target what listed log rc counts judged
  SUITES_RUN=0; TESTS=0; SKIPPED=0; FAILED_SUITES=""
  rows="$(bash "$S41_REPO/scripts/e2e-devnet.sh" --list-suites)" || { fail_msg "e2e-devnet.sh --list-suites failed"; return 1; }
  while IFS='|' read -r status task pkg feat target what; do
    [ "$status" = live ] || continue
    log="$RES/suite-$task.log"
    listed="$( (cd "$S41_REPO" && suite_env cargo test -p "$pkg" --features "$feat" --locked --test "$target" -- --list 2>/dev/null) | grep -c ': test$')"
    note "suite $task: cargo test -p $pkg --features $feat --test $target ($listed listed)"
    (cd "$S41_REPO" && suite_env ANTSEAL_DEVNET_ENV="$RES/devnet.env" cargo test -p "$pkg" --features "$feat" \
       --locked --test "$target" -- --nocapture) 2>&1 | capture_through "$log" > /dev/null
    rc="${PIPESTATUS[0]}"
    counts="$(suite_counts "$log" "$listed")"
    judged="$(suite_judgement "$rc" "$counts")"
    printf 'suite %s: exit=%s %s verdict=%s\n' "$task" "$rc" "$counts" "$judged" | tee -a "$RES/suites.txt"
    SUITES_RUN=$((SUITES_RUN + 1))
    TESTS=$((TESTS + $(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$counts")))
    SKIPPED=$((SKIPPED + $(sed -n 's/.*skip_lines=\([0-9]*\).*/\1/p' <<<"$counts")))
    [ "$judged" = ok ] || FAILED_SUITES+="$task,"
  done <<<"$rows"
  FAILED_SUITES="${FAILED_SUITES%,}"
}

run_stage0() {
  local rc
  mkdir -p "$RES/stage0"
  (cd "$S41_REPO" && suite_env bash "$S41_REPO/scripts/stage0.sh" --rehearse --bin "$S41_ANTSEAL_BIN" \
     --export "$RES/devnet.env" --workdir "$RES/stage0") 2>&1 | capture_through "$RES/stage0.log" > /dev/null
  rc="${PIPESTATUS[0]}"
  STAGE0="$(grep -o '^stage0-rehearsal: [A-Z]*' "$RES/stage0.log" | tail -1 | awk '{print $2}')"
  STAGE0="${STAGE0:-NONE}(exit=$rc)"
}

teardown() {
  local i p
  for i in $(seq 1 "$NODES"); do
    p="${NODE_PIDS[$i]:-}"; [ -n "$p" ] && kill -TERM "$p" 2>/dev/null
  done
  for i in $(seq 1 30); do
    [ -z "$(cat "/proc/${L2_INIT:-0}/task/${L2_INIT:-0}/children" 2>/dev/null)" ] && break
    sleep 0.5
  done
  [ -n "${L2_INIT:-}" ] && kill -KILL "$L2_INIT" 2>/dev/null
  [ -n "${L2_UNSHARE:-}" ] && kill -KILL "$L2_UNSHARE" 2>/dev/null
  [ -n "${ANVIL_PID:-}" ] && kill -TERM "$ANVIL_PID" 2>/dev/null
  wait 2>/dev/null
}

# ── --inner: the L1 controller, PID 1 of the namespace ────────────────────
load_params() {
  local k v
  for k in MODE ARM ARMDIR RUNDIR OPHOME OPUID REPO CARGO_HOME RUSTUP_HOME FOUNDRY_BIN CANARY TAG EXPECT_VERSION HOLD ANTSEAL_BIN AGENT_SOCK; do
    v="$(param "$S41_PARAMS" "$k")" || return 1
    printf -v "S41_$k" '%s' "$v"
  done
  RES="$S41_ARMDIR/results"; S41_NODES="$S41_ARMDIR/nodes"; S41_BINDIR="$S41_ARMDIR/bin"
  S41_SUITE_HOME="$S41_RUNDIR/suite-home"; S41_TMPDIR="$S41_RUNDIR/tmp"
  S41_RPC="$(rpc_url)"; S41_READY_MSG="$READY_MSG"
}

# The arm names a release; the binary must say it is that release.
assert_version() { # <`ant-node --version` output> <expected version>
  if [ "$1" != "ant-node $2" ]; then
    fail_msg "node version ${1#ant-node } != expected $2 — this is not the binary the arm names; no node was started"
    return 1
  fi
}

# One KEY=VALUE file the outer harness reads back (never sources).
write_result() { # <KEY=VALUE>…
  printf '%s\n' "$@" >> "$RES/arm.result"
}

inner_main() {
  local iso rc payer rewards ver claims
  iso="$(assert_isolated)" || exit 3
  printf '%s\n' "$iso"
  [ "$(id -u)" = 0 ] || { fail_msg "REFUSED reason=NOT-NS-ROOT — --inner runs only as the namespace's root"; exit 3; }
  { [ -n "${S41_PARAMS:-}" ] && [ -f "$S41_PARAMS" ]; } || { fail_msg "REFUSED reason=NO-PARAMS — no parameter file"; exit 3; }
  load_params || exit 3
  hostname s41-interop 2>/dev/null || true
  : > "$RES/arm.result"
  printf '%s\n' "$iso" > "$RES/isolation.txt"
  write_result "arm=$S41_ARM" "tag=$S41_TAG" "isolation=ok"
  if ! $DROP_CAPS env -i PATH="$SYS_PATH" cat "$S41_CANARY" > /dev/null 2>&1; then
    fail_msg "REFUSED reason=MASKING — the canary is unreadable BEFORE masking, so its unreadability after would prove nothing"; exit 3
  fi
  mask_view l1 "rw:$S41_REPO" "rw:$S41_CARGO_HOME" "rw:$S41_RUSTUP_HOME" "ro:$S41_FOUNDRY_BIN" "rw:$S41_RUNDIR" || exit 3
  mask_cargo_credentials || exit 3
  prove_view l1 "$(home_entries_of "$S41_REPO" "$S41_CARGO_HOME" "$S41_RUSTUP_HOME" "$S41_FOUNDRY_BIN" "$S41_RUNDIR")" > "$RES/masking-l1.txt"
  rc=$?; cat "$RES/masking-l1.txt"
  [ "$rc" = 0 ] || { fail_msg "REFUSED reason=MASKING — the L1 view leaks (masking-l1.txt)"; exit 3; }
  mkdir -p "$S41_SUITE_HOME" "$S41_TMPDIR" "$S41_NODES"

  if [ "$S41_MODE" = probe ]; then
    S41_TOKEN=0x0 S41_VAULT=0x0 S41_REWARDS=none
    launch_l2 || exit 3
    prove_view l2 "$(home_entries_of "$S41_NODES" "$S41_BINDIR")" nsenter -t "$L2_INIT" -m -- > "$RES/masking-l2.txt"; rc=$?
    prove_l2_extra >> "$RES/masking-l2.txt" || rc=1
    cat "$RES/masking-l2.txt"
    teardown
    [ "$rc" = 0 ] || { fail_msg "REFUSED reason=MASKING — the node view leaks (masking-l2.txt)"; exit 3; }
    write_result "masking=ok" "rc=0"
    printf 's41-arm: PROBE isolation=ok masking(l1)=ok masking(l2)=ok — no node and no chain was started\n'
    exit 0
  fi

  start_anvil || { write_result "deploy=FAIL:anvil" "rc=1"; exit 1; }
  deploy_contracts > "$RES/deploy.txt" 2>&1; rc=$?
  cat "$RES/deploy.txt"
  [ "$rc" = 0 ] || { write_result "deploy=FAIL" "rc=1"; teardown; exit 1; }
  TOKEN="$(sed -n 's/^deploy: token \(0x[0-9a-fA-F]*\) vault.*/\1/p' "$RES/deploy.txt")"
  VAULT="$(sed -n 's/^deploy: token 0x[0-9a-fA-F]* vault \(0x[0-9a-fA-F]*\) .*/\1/p' "$RES/deploy.txt")"
  payer="$(jq -r '.available_accounts[0]' "$RES/anvil.json")"
  rewards="$(jq -r --argjson n "$NODES" '.available_accounts[1:($n + 1)][]' "$RES/anvil.json")"
  assert_distinct_rewards "$rewards" "$payer" || { write_result "rewards=FAIL" "rc=1"; teardown; exit 1; }
  S41_TOKEN="$TOKEN" S41_VAULT="$VAULT" S41_REWARDS="$(paste -sd, - <<<"$rewards")"
  write_result "deploy=ok" "rewards=ok" "anvil=$(wl_env HOME="$RES/anvil-home" "$S41_FOUNDRY_BIN/anvil" --version 2>/dev/null | head -1 | grep -o '[0-9][0-9.]*[0-9]' | head -1)"

  launch_l2 || { write_result "nodes=FAIL:view" "rc=1"; teardown; exit 1; }
  prove_view l2 "$(home_entries_of "$S41_NODES" "$S41_BINDIR")" nsenter -t "$L2_INIT" -m -- > "$RES/masking-l2.txt"; rc=$?
  prove_l2_extra >> "$RES/masking-l2.txt" || rc=1
  cat "$RES/masking-l2.txt"
  [ "$rc" = 0 ] || { fail_msg "REFUSED reason=MASKING — the node view leaks; no node was started"; teardown; exit 3; }
  write_result "masking=ok"
  ver="$(sanitize < "$S41_NODES/version.txt" | head -1)"
  if ! assert_version "$ver" "$S41_EXPECT_VERSION"; then
    write_result "version=${ver#ant-node }" "rc=1"; teardown; exit 1
  fi
  write_result "version=$S41_EXPECT_VERSION"
  L2_STARTED="$(date +%s)"
  : > "$S41_NODES/.l2-go"
  note "$S41_ARM: starting $NODES ant-node $S41_EXPECT_VERSION processes in the node view (load: $(cut -d' ' -f1-3 /proc/loadavg))"
  wait_ready
  map_node_pids
  claims="$(node_claims "$(node_dir 1)/node.log")"
  printf 'boot: %s of %s nodes logged "%s" in %s s (load: %s); node claims: %s\n' \
    "$READY_COUNT" "$NODES" "$READY_MSG" "$BOOT_SECS" "$(cut -d' ' -f1-3 /proc/loadavg)" "$claims" | tee "$RES/boot.txt"
  write_result "nodes_ready=$READY_COUNT" "boot_secs=$BOOT_SECS" "node_commit=$(sed -n 's/.*commit=\([^ ]*\).*/\1/p' <<<"$claims")"
  if [ "$READY_COUNT" != "$NODES" ]; then
    [ -n "$EARLY_EXIT" ] && fail_msg "$EARLY_EXIT"
    fail_msg "only $READY_COUNT of $NODES nodes became ready within ${BOOT_TIMEOUT}s"
    write_result "rc=1"; teardown; exit 1
  fi
  wait_stable
  printf 'stable: every node holds >= %s DHT peers after %s s more (fewest: %s; load: %s)\n' \
    "$STABLE_PEERS" "$STABLE_SECS" "$STABLE_LEAST" "$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$RES/boot.txt"
  write_result "stable_secs=$STABLE_SECS" "stable_least=$STABLE_LEAST"
  if [ "$STABLE_LEAST" -lt "$STABLE_PEERS" ]; then
    fail_msg "the fleet did not stabilize: a node holds $STABLE_LEAST DHT peer(s) after ${STABLE_TIMEOUT}s (want >= $STABLE_PEERS)"
    write_result "rc=1"; teardown; exit 1
  fi

  if [ "$S41_MODE" = boot-only ]; then
    write_export | tee -a "$RES/boot.txt" || write_result "export=FAIL"
    boot_measure "$S41_HOLD"
    check_liveness; write_result "nodes_live=$LIVE_COUNT"
    prove_view l2 "$(home_entries_of "$S41_NODES" "$S41_BINDIR")" nsenter -t "$L2_INIT" -m -- > "$RES/masking-l2-after.txt" \
      && write_result "masking_after=ok" || write_result "masking_after=FAIL"
    teardown
    write_result "rc=0"
    printf 's41-arm: BOOT-ONLY %s nodes_ready=%s/%s nodes_live=%s boot_secs=%s — no suite ran; this is a measurement, not a verdict\n' \
      "$S41_TAG" "$READY_COUNT" "$NODES" "$LIVE_COUNT" "$BOOT_SECS"
    exit 0
  fi

  write_export | tee -a "$RES/boot.txt" || { write_result "export=FAIL" "rc=1"; teardown; exit 1; }
  run_suites
  run_stage0
  check_liveness
  prove_view l2 "$(home_entries_of "$S41_NODES" "$S41_BINDIR")" nsenter -t "$L2_INIT" -m -- > "$RES/masking-l2-after.txt" \
    && write_result "masking_after=ok" || write_result "masking_after=FAIL"
  teardown
  write_result "suites_run=$SUITES_RUN" "tests=$TESTS" "skipped=$SKIPPED" "failed=$FAILED_SUITES" \
    "nodes_live=$LIVE_COUNT" "stage0=$STAGE0"
  if [ "$SUITES_RUN" -ge 1 ] && [ -z "$FAILED_SUITES" ] && [ "$SKIPPED" = 0 ] && [ "$LIVE_COUNT" = "$NODES" ]; then
    write_result "rc=0"; exit 0
  fi
  write_result "rc=1"; exit 1
}

# Boot-only measurement: resource use while the fleet idles.
boot_measure() { # <hold-seconds>
  local i p rss=0 t
  for i in $(seq 1 "$NODES"); do
    p="${NODE_PIDS[$i]:-}"
    [ -n "$p" ] && rss=$((rss + $(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)))
  done
  printf 'measure: after ready: load %s, nodes RSS %s MiB total\n' "$(cut -d' ' -f1-3 /proc/loadavg)" "$((rss / 1024))" | tee -a "$RES/boot.txt"
  for t in $(seq 1 "${1:-0}"); do sleep 1; done
  rss=0
  for i in $(seq 1 "$NODES"); do
    p="${NODE_PIDS[$i]:-}"
    [ -n "$p" ] && rss=$((rss + $(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)))
  done
  printf 'measure: after %ss hold: load %s, nodes RSS %s MiB total, node logs %s KiB\n' "${1:-0}" \
    "$(cut -d' ' -f1-3 /proc/loadavg)" "$((rss / 1024))" "$(du -sk "$S41_NODES" | awk '{print $1}')" | tee -a "$RES/boot.txt"
}

# ── The outer harness ─────────────────────────────────────────────────────
RUN=""
CANARY_DIR=""
cleanup_outer() { [ -n "$CANARY_DIR" ] && rm -rf "$CANARY_DIR"; }

need_tools() {
  local t missing=""
  for t in unshare nsenter setpriv ip tar sha256sum python3 jq curl awk sed; do
    command -v "$t" > /dev/null 2>&1 || missing+="$t "
  done
  command -v anvil > /dev/null 2>&1 && command -v cast > /dev/null 2>&1 || missing+="anvil/cast(foundry) "
  [ -z "$missing" ] || refuse PREFLIGHT "missing tools: $missing"
  unshare --user --map-root-user --net true 2> /dev/null \
    || refuse PREFLIGHT "unprivileged user + network namespaces are not available here (kernel.unprivileged_userns_clone / user.max_user_namespaces)"
}

make_canary() {
  CANARY_DIR="$(mktemp -d /tmp/s41-canary.XXXXXX)" || refuse PREFLIGHT "cannot create the canary"
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$CANARY_DIR/canary.txt"
  [ -s "$CANARY_DIR/canary.txt" ] || refuse PREFLIGHT "the canary is empty"
}

write_params() { # <armdir> <mode> <arm> <tag> <hold> <antseal-bin>
  local armdir="$1" p
  mkdir -p "$armdir/results" "$armdir/bin" "$armdir/nodes"
  {
    printf 'MODE=%s\nARM=%s\nARMDIR=%s\nRUNDIR=%s\n' "$2" "$3" "$armdir" "$RUN"
    printf 'OPHOME=%s\nOPUID=%s\nREPO=%s\n' "$HOME" "$(id -u)" "$repo"
    printf 'CARGO_HOME=%s\nRUSTUP_HOME=%s\nFOUNDRY_BIN=%s\n' "${CARGO_HOME:-$HOME/.cargo}" "${RUSTUP_HOME:-$HOME/.rustup}" \
      "$(dirname "$(readlink -f "$(command -v anvil)")")"
    printf 'CANARY=%s\nTAG=%s\nEXPECT_VERSION=%s\nHOLD=%s\nANTSEAL_BIN=%s\n' "$CANARY_DIR/canary.txt" "$4" "${4#v}" "$5" "$6"
    printf 'AGENT_SOCK=%s\n' "${SSH_AUTH_SOCK:-}"
    printf 'OUT_HOME_ENTRIES=%s\n' "$(ls -A "$HOME" 2>/dev/null | grep -c .)"
    for p in $RULED_SECRET_PATHS; do
      printf 'OUT_%s=%s\n' "$(tr '/.' '__' <<<"$p")" "$( [ -e "$HOME/$p" ] && echo present || echo absent)"
    done
  } > "$armdir/results/params"
}

enter_namespace() { # <armdir> → the inner's exit status
  unshare --user --map-root-user --net --mount --pid --fork --kill-child --mount-proc --ipc --uts \
    --propagation private env -i PATH="$SYS_PATH" S41_PARAMS="$1/results/params" bash "$script" --inner
}

run_arm() { # <arm> <mode> <fetched-dir|""> <hold> <antseal-bin> → ARM_RC
  local arm="$1" mode="$2" src="$3" armdir="$RUN/$1" tag="none"
  mkdir -p "$armdir/results"
  if [ -n "$src" ]; then
    verify_arm "$arm" "$src" "$armdir"           # refuses (exit 3) before any extraction or start
    tag="$(param "$armdir/results/identity" tag)"
  fi
  write_params "$armdir" "$mode" "$arm" "$tag" "$4" "$5"
  note "$arm: entering the namespace (user+net+mount+pid+ipc+uts) — $mode"
  enter_namespace "$armdir" 2>&1 | capture_through "$armdir/results/inner.log"
  ARM_RC="${PIPESTATUS[0]}"
}

result_of() { # <armdir> <KEY> → the last value written
  sed -n "s/^$2=//p" "$1/results/arm.result" 2>/dev/null | tail -1
}

# D177 R6: the suites are built OUTSIDE the namespace, in the environment
# they run in inside, so nothing compiles inside and nothing is fetched.
prebuild() {
  local rows status task pkg feat target what
  rows="$(bash "$repo/scripts/e2e-devnet.sh" --list-suites)" || return 1
  mkdir -p "$RUN/suite-home" "$RUN/tmp"
  pb_env() {
    env -i PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$(dirname "$(readlink -f "$(command -v anvil)")"):$SYS_PATH" \
      HOME="$RUN/suite-home" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
      CARGO_NET_OFFLINE=true TMPDIR="$RUN/tmp" LANG=C.UTF-8 TZ=UTC "$@"
  }
  while IFS='|' read -r status task pkg feat target what; do
    [ "$status" = live ] || continue
    note "pre-build $task: cargo test -p $pkg --features $feat --locked --test $target --no-run"
    (cd "$repo" && pb_env cargo test -p "$pkg" --features "$feat" --locked --test "$target" --no-run) 2>&1 \
      | capture_through "$RUN/prebuild-$task.log" > /dev/null
    [ "${PIPESTATUS[0]}" = 0 ] || { fail_msg "pre-build of $task failed ($RUN/prebuild-$task.log)"; return 1; }
  done <<<"$rows"
  (cd "$repo" && pb_env cargo build -p antseal-cli --features ant-backend --locked --bin antseal) 2>&1 \
    | capture_through "$RUN/prebuild-antseal.log" > /dev/null
  [ "${PIPESTATUS[0]}" = 0 ] || { fail_msg "pre-build of the antseal binary failed"; return 1; }
  # Where cargo put it, from cargo itself — a configured target-dir moves it.
  local tdir
  tdir="$(cd "$repo" && pb_env cargo metadata --format-version 1 --no-deps --offline 2>/dev/null | jq -r '.target_directory // empty')"
  [ -n "$tdir" ] && [ -x "$tdir/debug/antseal" ] || { fail_msg "cannot locate the built antseal (cargo metadata: '$tdir')"; return 1; }
  mkdir -p "$RUN/antseal-bin" && cp "$tdir/debug/antseal" "$RUN/antseal-bin/antseal" || return 1
  printf 'pre-build: antseal (ant-backend) sha256=%s\n' "$(sha256sum "$RUN/antseal-bin/antseal" | awk '{print $1}')"
}

client_pin() { # what Cargo.lock actually resolves ant-core to
  awk '/^name = "ant-core"$/ {getline; gsub(/"/, "", $3); print $3; exit}' "$repo/Cargo.lock"
}

# D177 R7, verbatim, on S41, Q34 and threat-model §2.11.
verdict() { # <control-armdir> <subject-armdir> <secs> → exit status
  local c="$1" s="$2" control state rc
  if [ "$(result_of "$c" rc)" = 0 ]; then control=PASS; else control=FAIL; fi
  if [ "$control" != PASS ]; then
    printf '\n'
    fail_msg "control arm (ant-node $CONTROL_TAG) FAILED — harness defect, no S41 verdict (see $c/results)"
    printf 's41-interop: HARNESS-DEFECT commit=%s control=FAIL(ant-node-%s) — no S41 verdict date=%s\n' \
      "$(head_sha)" "$CONTROL_TAG" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    return 2
  fi
  if [ "$(result_of "$s" rc)" = 0 ]; then state=PASS; rc=0; else state=FAIL; rc=1; fi
  printf '\ns41-interop: %s commit=%s client=ant-core-%s node=ant-node-%s node_commit=%s archive_sha256=%s sig=%s nodes=%s suites_run=%s tests=%s skipped=%s failed=[%s] control=%s(ant-node-%s) netns=isolated anvil=%s secs=%s date=%s\n' \
    "$state" "$(head_sha)" "$(client_pin)" "$(result_of "$s" tag)" "$(result_of "$s" node_commit)" \
    "$(param "$s/results/identity" archive_sha256)" "$(param "$s/results/identity" sig)" \
    "$(result_of "$s" nodes_live)" "$(result_of "$s" suites_run)" "$(result_of "$s" tests)" "$(result_of "$s" skipped)" \
    "$(result_of "$s" failed)" "$control" "$CONTROL_TAG" "$(result_of "$s" anvil)" "$3" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  return "$rc"
}

print_plan() {
  local rows status task pkg feat target what
  note "S41 interop plan (D177) — nothing below has been executed"
  printf '    arm 1  CONTROL  ant-node %s (the dev pin) — must be green, or: harness defect, no S41 verdict\n' "$CONTROL_TAG"
  printf '    arm 2  SUBJECT  the latest non-prerelease ant-node (--fetch latest)\n'
  printf '    each arm: digests (file = SHA256SUMS = API%s), release key sha256 %s…, ML-DSA-65 signature (%s)\n' \
    " = pin when known" "${RELEASE_KEY_SHA256:0:16}" "$SIGNING_CONTEXT"
  printf '              namespace: user+net+mount+pid+ipc+uts; links=[lo] proven first; home/tmp/run-user/shm masked\n'
  printf '              Anvil :%s chain %s, evmlib %s contracts via cast, %s nodes on 127.0.0.1:%s-%s, distinct rewards\n' \
    "$ANVIL_PORT" "$CHAIN_ID" "$EVMLIB_VERSION" "$NODES" "$BASE_PORT" "$((BASE_PORT + NODES - 1))"
  rows="$(bash "$repo/scripts/e2e-devnet.sh" --list-suites 2>/dev/null)"
  while IFS='|' read -r status task pkg feat target what; do
    [ "$status" = live ] || continue
    printf '              suite %-6s cargo test -p %s --features %s --test %s (SKIP = FAIL, passed = --list)\n' "$task" "$pkg" "$feat" "$target"
  done <<<"$rows"
  printf '              stage 0: scripts/stage0.sh --rehearse (dead RPC -> STOP, dead nodes -> STOP, live -> PASS)\n'
  printf '\ns41-interop: PLAN commit=%s control=ant-node-%s suites_planned=%s nodes_planned=%s — nothing executed, nothing verified, no node started\n' \
    "$(head_sha)" "$CONTROL_TAG" "$(grep -c '^live|' <<<"$rows")" "$NODES"
}

# ── Internal check modes, driven by the self-test in throwaway namespaces ──
# --mask-check <params>: mask_view + prove_view over a FAKE operator home,
# so the self-test never depends on, or touches, the real one.
mask_check() {
  local k v
  S41_PARAMS="$1"
  for k in OPHOME OPUID CANARY CARGO_HOME KEEP; do
    v="$(param "$S41_PARAMS" "$k")" || exit 1
    printf -v "S41_$k" '%s' "$v"
  done
  S41_AGENT_SOCK=""
  local -a specs
  IFS=, read -r -a specs <<<"$S41_KEEP"
  mask_view st "${specs[@]}" || exit 4
  mask_cargo_credentials || exit 4
  prove_view st "$(home_entries_of "${specs[@]#*:}")"
}

# --suites-check <params>: the REAL run_suites over a stub repository and a
# stub cargo, so the plumbing a run depends on (--list counting, the capture,
# the exit status through the pipe, the SKIP count) is proven before any run.
suites_check() {
  local k v
  S41_PARAMS="$1"
  for k in REPO CARGO_HOME RUSTUP_HOME FOUNDRY_BIN RUNDIR ARMDIR; do
    v="$(param "$S41_PARAMS" "$k")" || exit 1
    printf -v "S41_$k" '%s' "$v"
  done
  RES="$S41_ARMDIR/results"; S41_SUITE_HOME="$S41_RUNDIR/suite-home"; S41_TMPDIR="$S41_RUNDIR/tmp"
  mkdir -p "$RES" "$S41_SUITE_HOME" "$S41_TMPDIR"
  run_suites
  printf 'suites: run=%s tests=%s skipped=%s failed=[%s]\n' "$SUITES_RUN" "$TESTS" "$SKIPPED" "$FAILED_SUITES"
}

# ── --self-test: every refusal this script promises, planted ──────────────
#
# Temp directories, stub binaries and throwaway namespaces only: it starts
# no node and no chain, reads the real home for nothing, and writes nothing
# in the tree. Judged by message, not just exit status. With --sigcheck and
# --archive-dir (a --fetch directory) it also runs the real one-flipped-byte
# signature plant; without them that arm is NOT RUN and counted as such.
self_test() {
  local st fail=0 arms=0 not_run=0 out rc f p
  st="$(mktemp -d "${TMPDIR:-/tmp}/s41-selftest.XXXXXX")" || { fail_msg "cannot create a temp dir"; return 1; }
  # shellcheck disable=SC2064
  trap "rm -rf '$st'" RETURN
  ok()  { arms=$((arms + 1)); printf '  planted fault: %-60s -> %s\n' "$1" "$2"; }
  bad() { arms=$((arms + 1)); printf '::error:: %s\n' "$*"; fail=1; }
  expect() { # <label> <want-rc> <want-substring> <rc> <out>
    if [ "$4" = "$2" ] && grep -qF -- "$3" <<<"$5"; then ok "$1" "$3"
    else bad "$1 -> exit $4 (wanted $2) without [$3]: $(tail -3 <<<"$5" | sanitize)"; fi
  }

  # A. The plan is never a verdict.
  out="$(bash "$script" --plan 2>&1)"; rc=$?
  expect "--plan prints PLAN" 0 "s41-interop: PLAN" "$rc" "$out"
  if grep -q '^s41-interop: PASS' <<<"$out"; then bad "--plan printed a PASS line"; else ok "--plan never prints a PASS line" "no PASS"; fi

  # B. The controller entered WITHOUT its namespaces refuses on the
  #    interface list, and the stub node and chain never execute.
  mkdir -p "$st/arm/bin" "$st/arm/results" "$st/foundry"
  for f in "$st/arm/bin/ant-node" "$st/foundry/anvil" "$st/foundry/cast"; do
    printf '#!/bin/sh\n: > "%s/STARTED"\n' "$st" > "$f"; chmod +x "$f"
  done
  printf 'MODE=run\nARM=selftest\nARMDIR=%s\nRUNDIR=%s\nFOUNDRY_BIN=%s\n' "$st/arm" "$st" "$st/foundry" > "$st/arm/results/params"
  out="$(env -i PATH="$SYS_PATH" S41_PARAMS="$st/arm/results/params" bash "$script" --inner 2>&1)"; rc=$?
  expect "the controller run outside any namespace" 3 "not inside an isolated network namespace: links=[" "$rc" "$out"
  if [ -e "$st/STARTED" ]; then bad "a stub node or chain STARTED although isolation was refused"
  else ok "... and no node or chain was started" "stubs never executed"; fi
  out="$(unshare --user --map-root-user bash "$script" --isolation-check 2>&1)"; rc=$?
  expect "a user namespace WITHOUT a network namespace" 1 "not inside an isolated network namespace" "$rc" "$out"
  out="$(unshare --user --map-root-user --net bash "$script" --isolation-check 2>&1)"; rc=$?
  expect "control: user + network namespaces" 0 "isolation: links=[lo] routes4(main)=[] routes6(main)=[] egress4=ENETUNREACH" "$rc" "$out"

  # B2. The mount namespace omitted (D177 §3): isolation holds, so the
  #     controller gets as far as the masks — and must refuse at the first
  #     one, before any stub runs. Fake home, fake cargo home, temp canary.
  mkdir -p "$st/b2/ophome/.ssh" "$st/b2/cargo" "$st/b2/rustup" "$st/b2/repo" "$st/b2/run/arm/results" "$st/b2/run/arm/bin" "$st/b2/run/arm/nodes"
  printf 'b2 canary\n' > "$st/b2/canary.txt"
  cp "$st/arm/bin/ant-node" "$st/b2/run/arm/bin/ant-node"
  { printf 'MODE=run\nARM=selftest\nARMDIR=%s\nRUNDIR=%s\nOPHOME=%s\nOPUID=%s\nREPO=%s\n' "$st/b2/run/arm" "$st/b2/run" "$st/b2/ophome" "$(id -u)" "$st/b2/repo"
    printf 'CARGO_HOME=%s\nRUSTUP_HOME=%s\nFOUNDRY_BIN=%s\nCANARY=%s\nTAG=v0.0.0\nEXPECT_VERSION=0.0.0\nHOLD=0\nANTSEAL_BIN=\nAGENT_SOCK=\n' \
      "$st/b2/cargo" "$st/b2/rustup" "$st/foundry" "$st/b2/canary.txt"; } > "$st/b2/run/arm/results/params"
  out="$(unshare --user --map-root-user --net env -i PATH="$SYS_PATH" S41_PARAMS="$st/b2/run/arm/results/params" bash "$script" --inner 2>&1)"; rc=$?
  expect "the mount namespace omitted" 3 "cannot mount the stash" "$rc" "$out"
  if [ -e "$st/STARTED" ]; then bad "a stub node or chain STARTED without a mount namespace"
  else ok "... and no node or chain was started" "stubs never executed"; fi

  # C. Masking, over a FAKE home: the control, then three plants.
  local fh="$st/fakehome"
  mkdir -p "$fh/.ssh" "$fh/.gnupg" "$fh/.config/gh" "$fh/.local/share/ant" "$fh/.minisign" "$fh/.cargo" "$fh/work" "$st/canary" "$st/keep"
  printf 'fake\n' > "$fh/.ssh/id_planted"; printf 'token = "planted"\n' > "$fh/.cargo/credentials.toml"
  printf 'planted canary\n' > "$st/canary/canary.txt"; cp "$st/canary/canary.txt" "$st/keep/canary.txt"
  mk_params() { # <canary> <comma-separated specs>
    { printf 'OPHOME=%s\nOPUID=%s\nCANARY=%s\nCARGO_HOME=%s\nKEEP=%s\n' "$fh" "$(id -u)" "$1" "$fh/.cargo" "$2"
      printf 'OUT_HOME_ENTRIES=%s\n' "$(ls -A "$fh" | grep -c .)"
      for p in $RULED_SECRET_PATHS; do
        printf 'OUT_%s=%s\n' "$(tr '/.' '__' <<<"$p")" "$( [ -e "$fh/$p" ] && echo present || echo absent)"
      done
    } > "$st/keep/params"
  }
  ns_mask() { unshare --user --map-root-user --mount --pid --fork --kill-child --mount-proc --propagation private \
                env -i PATH="$SYS_PATH" bash "$script" --mask-check "$st/keep/params" 2>&1; }
  mk_params "$st/canary/canary.txt" "rw:$st/keep,rw:$fh/.cargo"
  out="$(ns_mask)"; rc=$?
  expect "control: a masked view of a fake home" 0 "masking(st): canary unreadable" "$rc" "$out"
  expect "control: ~/.ssh hidden" 0 "~/.ssh outside=present inside=absent" "$rc" "$out"
  expect "control: ~/.cargo/credentials.toml overlaid" 0 "~/.cargo/credentials.toml outside=present inside=masked(/dev/null)" "$rc" "$out"
  expect "control: no capability to unmount a mask" 0 "a workload cannot unmount a mask" "$rc" "$out"
  mk_params "$st/keep/canary.txt" "rw:$st/keep,rw:$fh/.cargo"
  out="$(ns_mask)"; rc=$?
  expect "a canary left inside a bind-back" 1 "canary READABLE" "$rc" "$out"
  mk_params "$st/canary/canary.txt" "rw:$st/keep,rw:$fh/.ssh"
  out="$(ns_mask)"; rc=$?
  expect "a bind-back that re-exposes ~/.ssh" 1 "~/.ssh outside=present inside=EXPOSED" "$rc" "$out"
  mk_params "$st/canary/canary.txt" "rw:$st"
  out="$(ns_mask)"; rc=$?
  expect "a bind-back that contains a mask root" 4 "would re-expose the mask root" "$rc" "$out"

  # D. The signature: only a verifier that can say no is believed.
  mkdir -p "$st/sig"
  head -c 4096 /dev/urandom > "$st/sig/genuine.tar.gz"; : > "$st/sig/genuine.tar.gz.sig"; head -c 1952 /dev/zero > "$st/sig/key.bin"
  printf '#!/bin/sh\nn=$(stat -c %%s "$2")\nif [ "$(sha256sum "$2" | cut -c1-64)" = "%s" ] && [ "$4" = "%s" ]; then echo "VERIFY OK ctx=\\"$4\\" msg_len=$n"; exit 0; fi\necho "VERIFY FAIL ctx=\\"$4\\" msg_len=$n"; exit 1\n' \
    "$(sha256sum "$st/sig/genuine.tar.gz" | cut -c1-64)" "$SIGNING_CONTEXT" > "$st/sig/honest"
  printf '#!/bin/sh\necho "VERIFY OK ctx=\\"$4\\" msg_len=$(stat -c %%s "$2")"\n' > "$st/sig/liar"
  chmod +x "$st/sig/honest" "$st/sig/liar"
  out="$( (SIGCHECK="$st/sig/honest"; sig_verify "$st/sig/key.bin" "$st/sig/genuine.tar.gz" "$st/sig"; echo "SIG_STATE=$SIG_STATE") 2>&1)"; rc=$?
  expect "control: an honest verifier" 0 "SIG_STATE=ok" "$rc" "$out"
  out="$( (SIGCHECK="$st/sig/liar"; sig_verify "$st/sig/key.bin" "$st/sig/genuine.tar.gz" "$st/sig") 2>&1)"; rc=$?
  expect "a verifier that accepts everything" 3 "ACCEPTED an archive with one flipped byte" "$rc" "$out"
  cp "$st/sig/genuine.tar.gz" "$st/sig/tampered.tar.gz"; cp "$st/sig/genuine.tar.gz.sig" "$st/sig/tampered.tar.gz.sig"; s41py flip "$st/sig/tampered.tar.gz" 100
  out="$( (SIGCHECK="$st/sig/honest"; sig_verify "$st/sig/key.bin" "$st/sig/tampered.tar.gz" "$st/sig") 2>&1)"; rc=$?
  expect "a tampered archive (stub verifier)" 3 "signature does not verify" "$rc" "$out"
  out="$( (SIGCHECK=""; ALLOW_UNCHECKED=0; sig_verify "$st/sig/key.bin" "$st/sig/genuine.tar.gz" "$st/sig") 2>&1)"; rc=$?
  expect "no verifier and no opt-out" 3 "reason=SIGNATURE-UNCHECKED" "$rc" "$out"
  out="$( (SIGCHECK=""; ALLOW_UNCHECKED=1; sig_verify "$st/sig/key.bin" "$st/sig/genuine.tar.gz" "$st/sig"; echo "SIG_STATE=$SIG_STATE") 2>&1)"; rc=$?
  expect "no verifier, --allow-unchecked-signature" 0 "SIG_STATE=unchecked" "$rc" "$out"
  if [ -n "$SIGCHECK" ] && [ -n "${ST_ARCHIVE_DIR:-}" ] && [ -s "$ST_ARCHIVE_DIR/$ARCHIVE_NAME" ] && [ -s "$ST_ARCHIVE_DIR/signature.rs" ]; then
    local real="$st/real" size
    mkdir -p "$real"
    s41py extract-key "$ST_ARCHIVE_DIR/signature.rs" "$real/key.bin" > /dev/null
    cp "$ST_ARCHIVE_DIR/$ARCHIVE_NAME" "$real/flipped.tar.gz"; cp "$ST_ARCHIVE_DIR/$ARCHIVE_NAME.sig" "$real/flipped.tar.gz.sig"
    size="$(stat -c %s "$real/flipped.tar.gz")"
    s41py flip "$real/flipped.tar.gz" 5000001
    out="$( (sig_verify "$real/key.bin" "$real/flipped.tar.gz" "$real") 2>&1)"; rc=$?
    expect "REAL: one flipped byte in the release archive" 3 "VERIFY FAIL ctx=\"$SIGNING_CONTEXT\" msg_len=$size" "$rc" "$out"
    out="$( (sig_verify "$real/key.bin" "$ST_ARCHIVE_DIR/$ARCHIVE_NAME" "$real"; echo "SIG_STATE=$SIG_STATE") 2>&1)"; rc=$?
    expect "REAL control: the genuine release archive" 0 "SIG_STATE=ok" "$rc" "$out"
  else
    not_run=$((not_run + 2))
    printf '  NOT RUN:       %-60s -> %s\n' "REAL signature plant + control" "needs --sigcheck BIN --archive-dir DIR"
  fi

  # E. An arm's identity: digests, release flags, key pin, the one member.
  local fx="$st/fetch"
  mkdir -p "$fx/src"
  printf '#!/bin/sh\nexit 0\n' > "$fx/src/ant-node"; chmod +x "$fx/src/ant-node"; printf 'peers = []\n' > "$fx/src/bootstrap_peers.toml"
  tar -czf "$fx/$ARCHIVE_NAME" -C "$fx/src" ant-node bootstrap_peers.toml
  head -c 3309 /dev/zero > "$fx/$ARCHIVE_NAME.sig"
  mk_fetch() { # <sums-hex> <api-hex> <prerelease>
    local size; size="$(stat -c %s "$fx/$ARCHIVE_NAME")"
    printf '%s  %s\n' "$1" "$ARCHIVE_NAME" > "$fx/SHA256SUMS.txt"
    printf '{"tag_name":"v9.9.9","draft":false,"prerelease":%s,"published_at":"2026-01-01T00:00:00Z","assets":[{"name":"%s","size":%s,"digest":"sha256:%s"}]}\n' \
      "$3" "$ARCHIVE_NAME" "$size" "$2" > "$fx/release.json"
    printf 'tag=v9.9.9\n' > "$fx/fetch.txt"; printf '{"sha":"%s"}\n' "$(printf '%040d' 7)" > "$fx/tag-commit.json"
    { printf 'pub const SIGNING_CONTEXT: &[u8] = b"%s";\nconst RELEASE_SIGNING_KEY: &[u8] = &[\n' "$SIGNING_CONTEXT"
      for p in $(seq 1 1952); do printf '0x01, '; done; printf '\n];\n'; } > "$fx/signature.rs"
  }
  local good other
  good="$(sha256sum "$fx/$ARCHIVE_NAME" | awk '{print $1}')"; other="$(printf '%064d' 0)"
  mk_fetch "$other" "$good" false
  out="$( (verify_arm planted "$fx" "$st/armE") 2>&1)"; rc=$?
  expect "SHA256SUMS disagrees with the archive" 3 "!= SHA256SUMS.txt's" "$rc" "$out"
  mk_fetch "$good" "$other" false
  out="$( (verify_arm planted "$fx" "$st/armE") 2>&1)"; rc=$?
  expect "the release API's digest disagrees" 3 "!= the release API's digest" "$rc" "$out"
  mk_fetch "$good" "$good" true
  out="$( (verify_arm planted "$fx" "$st/armE") 2>&1)"; rc=$?
  expect "a prerelease named as an arm" 3 "is a draft or a prerelease" "$rc" "$out"
  mk_fetch "$good" "$good" false
  out="$( (verify_arm planted "$fx" "$st/armE") 2>&1)"; rc=$?
  expect "signature.rs embeds a key that is not the pin" 3 "upstream rotated its release key" "$rc" "$out"
  out="$( (extract_node "$fx/$ARCHIVE_NAME" "$st/extract"; ls -A "$st/extract") 2>&1)"; rc=$?
  expect "control: extraction takes ONLY the ant-node member" 0 "ant-node" "$rc" "$out"
  if [ -e "$st/extract/bootstrap_peers.toml" ]; then bad "bootstrap_peers.toml was extracted next to the binary"; else ok "... bootstrap_peers.toml is never extracted" "absent"; fi
  ln -s /bin/true "$fx/src/link" && mv "$fx/src/link" "$fx/src/ant-node.l" && rm "$fx/src/ant-node" && mv "$fx/src/ant-node.l" "$fx/src/ant-node"
  tar -czf "$st/symlink.tar.gz" -C "$fx/src" ant-node
  out="$( (extract_node "$st/symlink.tar.gz" "$st/extract2") 2>&1)"; rc=$?
  expect "an archive whose ant-node is a symlink" 3 "exactly one regular-file member named ant-node" "$rc" "$out"

  # F. The contracts: the pinned artifact, and the empty-contract trap.
  local art
  art="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d -name "evmlib-$EVMLIB_VERSION" 2>/dev/null | LC_ALL=C sort | head -1)/artifacts"
  if [ -s "$art/AutonomiNetworkToken.json" ]; then
    out="$(artifact_bytecode "$art/AutonomiNetworkToken.json" 2>&1)"; rc=$?
    if [ "$rc" = 0 ] && [ "${#out}" -gt 1000 ]; then ok "control: the pinned token artifact's bytecode" "$(( (${#out} - 2) / 2 )) bytes"
    else bad "the pinned token artifact yielded no bytecode (rc=$rc)"; fi
    out="$( (eval "$(declare -f artifact_bytecode | sed 's/\.bytecode | if/.bytecode.object | if/')"; artifact_bytecode "$art/AutonomiNetworkToken.json") 2>&1)"; rc=$?
    expect "extraction with .bytecode.object (D177 R3)" 1 "produced 0 bytes of hex" "$rc" "$out"
    out="$(artifact_bytecode "$art/PaymentVaultV2.json" 2>&1)"; rc=$?
    if [ "$rc" = 0 ] && [ "${#out}" -gt 1000 ]; then ok "control: the pinned vault artifact (Foundry's {object} form)" "$(( (${#out} - 2) / 2 )) bytes"
    else bad "the pinned vault artifact yielded no bytecode (rc=$rc)"; fi
    out="$( (eval "$(declare -f artifact_bytecode | sed 's/ elif type == "object" and (.object | type) == "string" then .object//')"; artifact_bytecode "$art/PaymentVaultV2.json") 2>&1)"; rc=$?
    expect "a string-only extraction of the vault artifact" 1 "produced 0 bytes of hex" "$rc" "$out"
  else
    not_run=$((not_run + 2))
    printf '  NOT RUN:       %-60s -> %s\n' "the pinned evmlib artifact arms" "evmlib $EVMLIB_VERSION is not in the cargo registry"
  fi
  out="$( (cast_() { printf '0x\n'; }; assert_code_size token 0x5fbdb2315678afecb367f032d93f642f64180aa3 "$TOKEN_CODE_BYTES") 2>&1)"; rc=$?
  expect "an empty contract on chain" 1 "token code bytes: 0 (expected $TOKEN_CODE_BYTES)" "$rc" "$out"

  # G. The suites: SKIP is FAIL, and passed must equal --list.
  mkdir -p "$st/suite"
  printf 'running 8 tests\ntest result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' > "$st/suite/clean.log"
  { for p in $(seq 1 8); do printf 'SKIP: ANTSEAL_DEVNET_ENV=/nonexistent is not readable (No such file or directory (os error 2)) — is the devnet up?\n'; done
    printf 'test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'; } > "$st/suite/skips.log"
  printf 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' > "$st/suite/short.log"
  printf 'test result: ok. 7 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n' > "$st/suite/ignored.log"
  out="$(suite_judgement 0 "$(suite_counts "$st/suite/clean.log" 8)")"
  expect "control: 8 listed, 8 passed, no SKIP" 0 "ok" 0 "$out"
  out="$(suite_judgement 0 "$(suite_counts "$st/suite/skips.log" 8)")"
  expect "every test SKIPs (export unreadable) yet exits 0" 0 "FAIL:8 SKIP lines" 0 "$out"
  out="$(suite_judgement 0 "$(suite_counts "$st/suite/short.log" 8)")"
  expect "one test fewer than --list enumerates" 0 "FAIL:passed 7 != listed 8" 0 "$out"
  out="$(suite_judgement 0 "$(suite_counts "$st/suite/ignored.log" 8)")"
  expect "an ignored test" 0 "FAIL:0 failed, 1 ignored" 0 "$out"
  out="$(suite_judgement 0 "$(suite_counts "$st/suite/clean.log" 0)")"
  expect "nothing listed at all" 0 "FAIL:passed 8 != listed 0" 0 "$out"

  # G2. run_suites itself, over a stub repository and a stub cargo, inside a
  #     throwaway user namespace (the capability drop needs its root).
  local sr="$st/sr"
  mkdir -p "$sr/repo/scripts" "$sr/cargo/bin" "$sr/run/arm/results"
  bash "$repo/scripts/e2e-devnet.sh" --list-suites > "$sr/rows.txt" 2>/dev/null
  printf '#!/bin/sh\ncat "%s"\n' "$sr/rows.txt" > "$sr/repo/scripts/e2e-devnet.sh"
  cat > "$sr/cargo/bin/cargo" <<STUB
#!/bin/sh
[ "\$CARGO_NET_OFFLINE" = true ] || { echo "stub cargo: CARGO_NET_OFFLINE not set"; exit 70; }
case "\$*" in
  *"-- --list"*) printf 't1: test\nt2: test\nt3: test\n\n3 tests, 0 benchmarks\n'; exit 0 ;;
esac
[ -n "\$ANTSEAL_DEVNET_ENV" ] || { echo "stub cargo: no ANTSEAL_DEVNET_ENV"; exit 71; }
if [ "\$(cat "$sr/mode")" = fail ]; then
  printf 'running 3 tests\ntest result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n'; exit 101
fi
if [ "\$(cat "$sr/mode")" = skip ]; then
  for i in 1 2 3; do echo "SKIP: ANTSEAL_DEVNET_ENV=/nonexistent is not readable (No such file or directory (os error 2)) — is the devnet up?"; done
fi
printf 'running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'
exit 0
STUB
  chmod +x "$sr/cargo/bin/cargo" "$sr/repo/scripts/e2e-devnet.sh"
  printf 'REPO=%s\nCARGO_HOME=%s\nRUSTUP_HOME=%s\nFOUNDRY_BIN=%s\nRUNDIR=%s\nARMDIR=%s\n' "$sr/repo" "$sr/cargo" "$sr/rustup" "$st/foundry" "$sr/run" "$sr/run/arm" > "$sr/params"
  printf 'good\n' > "$sr/mode"
  out="$(unshare --user --map-root-user env -i PATH="$SYS_PATH" bash "$script" --suites-check "$sr/params" 2>&1)"; rc=$?
  expect "control: run_suites over stub cargo (4 suites x 3 tests)" 0 "suites: run=4 tests=12 skipped=0 failed=[]" "$rc" "$out"
  printf 'skip\n' > "$sr/mode"; rm -f "$sr/run/arm/results/suites.txt"
  out="$(unshare --user --map-root-user env -i PATH="$SYS_PATH" bash "$script" --suites-check "$sr/params" 2>&1)"; rc=$?
  expect "every suite SKIPs and exits 0 (through run_suites)" 0 "suite S6-S8: exit=0 listed=3 passed=3 failed=0 ignored=0 skip_lines=3 verdict=FAIL:3 SKIP lines" "$rc" "$out"
  expect "... and the arm names all four as failed" 0 "suites: run=4 tests=12 skipped=12 failed=[S6-S8,S17,S18,S19]" "$rc" "$out"
  printf 'fail\n' > "$sr/mode"; rm -f "$sr/run/arm/results/suites.txt"
  out="$(unshare --user --map-root-user env -i PATH="$SYS_PATH" bash "$script" --suites-check "$sr/params" 2>&1)"; rc=$?
  expect "a suite exits 101 through the capture pipe" 0 "suite S6-S8: exit=101 listed=3 passed=2 failed=1 ignored=0 skip_lines=0 verdict=FAIL:exit 101" "$rc" "$out"

  # H. Rewards: distinct, and never the payer.
  local one many
  one="$(for p in $(seq 1 14); do echo 0x70997970c51812dc3a010c7d01b50e0d17dc79c8; done)"
  many="$(for p in $(seq 1 14); do printf '0x%040x\n' "$p"; done)"
  out="$(assert_distinct_rewards "$one" 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 2>&1)"; rc=$?
  expect "one rewards address for every node" 1 "rewards addresses not distinct: 1 of 14" "$rc" "$out"
  out="$(assert_distinct_rewards "$many" 0x0000000000000000000000000000000000000003 2>&1)"; rc=$?
  expect "a node paid into the payer's own address" 1 "the payer's own" "$rc" "$out"
  out="$(assert_distinct_rewards "$many" 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 2>&1)"; rc=$?
  expect "control: 14 distinct rewards addresses" 0 "rewards: 14 of 14 distinct" "$rc" "$out"

  # I. Node identity and liveness.
  out="$(assert_version "ant-node 0.15.0" 0.22.0 2>&1)"; rc=$?
  expect "the v0.15.0 binary run as the v0.22.0 subject" 1 "node version 0.15.0 != expected 0.22.0" "$rc" "$out"
  out="$(bash -c "$(declare -f check_liveness fail_msg); NODES=2; L2_INIT=\$\$
    sleep 300 & a=\$!; sleep 300 & b=\$!; NODE_PIDS=([1]=\$a [2]=\$b)
    kill -9 \$b; wait \$b 2>/dev/null; check_liveness; echo live=\$LIVE_COUNT; kill \$a" 2>&1)"; rc=$?
  expect "kill -9 one node" 0 "node 2 (pid" "$rc" "$out"
  expect "... and it is counted dead" 0 "live=1" "$rc" "$out"

  # J. The control arm gates the verdict (D177 R4).
  mk_arm() { # <dir> <rc>
    mkdir -p "$1/results"
    printf 'arm=x\ntag=v0.22.0\nnode_commit=008d2ad\nnodes_live=14\nsuites_run=4\ntests=29\nskipped=0\nfailed=\nanvil=1.5.1\nrc=%s\n' "$2" > "$1/results/arm.result"
    printf 'archive_sha256=%s\nsig=ok\n' "$(printf '%064d' 1)" > "$1/results/identity"
  }
  mk_arm "$st/c-red" 1; mk_arm "$st/c-green" 0; mk_arm "$st/s-red" 1; mk_arm "$st/s-green" 0
  out="$(verdict "$st/c-red" "$st/s-green" 1 2>&1)"; rc=$?
  expect "a red control arm" 2 "harness defect, no S41 verdict" "$rc" "$out"
  if grep -q '^s41-interop: PASS' <<<"$out"; then bad "a red control still produced a PASS line"; else ok "... and no PASS line, whatever the subject did" "none"; fi
  out="$(verdict "$st/c-green" "$st/s-red" 1 2>&1)"; rc=$?
  expect "a green control and a red subject" 1 "control=PASS(ant-node-$CONTROL_TAG)" "$rc" "$out"
  expect "... is the S41 red" 1 "s41-interop: FAIL commit=" "$rc" "$out"
  out="$(verdict "$st/c-green" "$st/s-green" 1 2>&1)"; rc=$?
  if [ "$rc" = 0 ] && grep -q '^s41-interop: PASS commit=.* client=ant-core-.* node=ant-node-v0.22.0 node_commit=008d2ad archive_sha256=0\{63\}1 sig=ok nodes=14 suites_run=4 tests=29 skipped=0 failed=\[\] control=PASS(ant-node-v0.15.0) netns=isolated anvil=1.5.1 secs=1 date=' <<<"$out"; then
    ok "control: both arms green forms the R7 line" "(line formed, not printed)"
  else bad "two green arms did not form the R7 PASS line (rc=$rc)"; fi

  # K. Redaction: an export-shaped capture keeps addresses, loses the key.
  out="$(printf "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='0x%s'\nANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n" \
          "$(printf 'a%.0s' $(seq 64))" | capture_through "$st/capture.log")"
  if grep -qE 'a{64}' <<<"$out" || grep -qE 'a{64}' "$st/capture.log"; then bad "a key survived capture_through"
  elif ! grep -qF 0x5FbDB2315678afecb367f032d93F642f64180aa3 "$st/capture.log"; then bad "capture_through destroyed an address"
  else ok "a key-shaped export line in a capture" "redacted on both legs, address kept"; fi

  printf '\ns41-interop: SELF-TEST %s arms=%s not_run=%s commit=%s — planted faults only; no node, chain or suite was started\n' \
    "$([ "$fail" = 0 ] && echo ok || echo BROKEN)" "$arms" "$not_run" "$(head_sha)"
  return "$fail"
}

# ── Entry ─────────────────────────────────────────────────────────────────
main() {
  local mode=run control_dir="" subject_dir="" node_dir="" hold=60 skip_prebuild=0 fetch_tag="" fetch_dir="" key_src="" key_out=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --plan) mode=plan ;;
      --self-test) mode=self-test ;;
      --fetch) mode=fetch; fetch_tag="${2:-}"; fetch_dir="${3:-}"; shift 2 ;;
      --extract-key) mode=extract-key; key_src="${2:-}"; key_out="${3:-}"; shift 2 ;;
      --probe-namespace) mode=probe ;;
      --boot-only) mode=boot-only ;;
      --inner) inner_main; exit $? ;;
      --isolation-check) assert_isolated; exit $? ;;
      --mask-check) mask_check "${2:-}"; exit $? ;;
      --suites-check) suites_check "${2:-}"; exit $? ;;
      --node-dir) node_dir="$(readlink -m "${2:-}")"; shift ;;
      --control-dir) control_dir="$(readlink -m "${2:-}")"; shift ;;
      --subject-dir) subject_dir="$(readlink -m "${2:-}")"; shift ;;
      --sigcheck) SIGCHECK="$(readlink -m "${2:-}")"; shift ;;
      --allow-unchecked-signature) ALLOW_UNCHECKED=1 ;;
      --run-dir) RUN="$(readlink -m "${2:-}")"; shift ;;
      --hold) hold="${2:-}"; shift; [[ $hold =~ ^[0-9]+$ ]] || die "--hold needs seconds" ;;
      --skip-prebuild) skip_prebuild=1 ;;
      --archive-dir) ST_ARCHIVE_DIR="$(readlink -m "${2:-}")"; shift ;;
      -h|--help) awk 'NR > 1 && /^set -uo pipefail/ {exit} NR > 1 {print}' "$script"; exit 0 ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
  done
  case "$mode" in
    plan) print_plan; return 0 ;;
    self-test) self_test; return $? ;;
    fetch) fetch_release "$fetch_tag" "$fetch_dir"; return $? ;;
    extract-key)
      local line
      line="$(s41py extract-key "$key_src" "$key_out" 2>&1)" || die "$line"
      printf '%s (pinned: %s) %s\n' "$line" "$RELEASE_KEY_SHA256" \
        "$([ "$(sed -n 's/^key_sha256=\([0-9a-f]*\).*/\1/p' <<<"$line")" = "$RELEASE_KEY_SHA256" ] && echo MATCH || echo MISMATCH)"
      return 0 ;;
  esac
  need_tools
  [ -n "$RUN" ] || RUN="$repo/target/s41-interop/$(date -u +%Y%m%dT%H%M%SZ)-$(head_sha)"
  mkdir -p "$RUN" || refuse PREFLIGHT "cannot create $RUN"
  make_canary
  trap cleanup_outer EXIT
  local started secs rc
  started="$(date -u +%s)"
  case "$mode" in
    probe)
      run_arm probe probe "" 0 ""
      printf '\ns41-interop: PROBE %s commit=%s — isolation and masking only; no node and no chain was started; evidence=%s\n' \
        "$([ "$ARM_RC" = 0 ] && echo ok || echo FAILED)" "$(head_sha)" "$RUN/probe/results"
      return "$ARM_RC" ;;
    boot-only)
      [ -n "$node_dir" ] || die "--boot-only needs --node-dir DIR (a --fetch directory)"
      run_arm "boot-$(param "$node_dir/fetch.txt" tag 2>/dev/null || echo x)" boot-only "$node_dir" "$hold" ""
      printf '\ns41-interop: BOOT-ONLY %s commit=%s — a measurement, not a verdict; no suite ran; evidence=%s\n' \
        "$([ "$ARM_RC" = 0 ] && echo ok || echo FAILED)" "$(head_sha)" "$RUN"
      return "$ARM_RC" ;;
  esac
  [ -n "$control_dir" ] && [ -n "$subject_dir" ] || die "a run needs --control-dir and --subject-dir (see --help)"
  [ "$(param "$control_dir/fetch.txt" tag 2>/dev/null)" = "$CONTROL_TAG" ] \
    || refuse PREFLIGHT "the control arm must be ant-node $CONTROL_TAG (the dev pin); $control_dir holds another tag"
  [ "$(param "$subject_dir/fetch.txt" tag 2>/dev/null)" != "$CONTROL_TAG" ] || refuse PREFLIGHT "the subject arm is the control's own release"
  if [ "$skip_prebuild" = 0 ]; then prebuild || refuse PREBUILD "the suites did not pre-build outside the namespace"; fi
  [ -x "$RUN/antseal-bin/antseal" ] || refuse PREBUILD "no pre-built antseal (ant-backend) under $RUN/antseal-bin"
  run_arm control run "$control_dir" 0 "$RUN/antseal-bin/antseal"
  # Exit 3 inside the namespace is a refusal before any node started
  # (isolation, masking, the node view's proof), not a harness verdict.
  [ "$ARM_RC" = 3 ] && refuse INNER "the control arm refused inside the namespace before any node started — see $RUN/control/results/inner.log"
  if [ "$(result_of "$RUN/control" rc)" != 0 ]; then
    verdict "$RUN/control" "$RUN/control" "$(( $(date -u +%s) - started ))"; return $?
  fi
  run_arm subject run "$subject_dir" 0 "$RUN/antseal-bin/antseal"
  [ "$ARM_RC" = 3 ] && refuse INNER "the subject arm refused inside the namespace before any node started — see $RUN/subject/results/inner.log"
  secs=$(( $(date -u +%s) - started ))
  verdict "$RUN/control" "$RUN/subject" "$secs"; rc=$?
  printf 's41-interop: notes %s control_tests=%s masking=ok(l1,l2) pidns=yes stage0(control)=%s stage0(subject)=%s evidence=%s\n' \
    "$(s41py lag "$subject_dir/releases.json" "$subject_dir/ant-core.index" "$CONTROL_TAG" 2>/dev/null | cut -d' ' -f1,3 || echo 'N=?')" \
    "$(result_of "$RUN/control" tests)" "$(result_of "$RUN/control" stage0)" "$(result_of "$RUN/subject" stage0)" "$RUN"
  return "$rc"
}

main "$@"; exit $?
