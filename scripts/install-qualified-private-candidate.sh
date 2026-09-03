#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"

(( $# == 0 )) || {
  print -u2 "usage: install-qualified-private-candidate.sh"
  exit 64
}

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 17179869184 --rss-grace-seconds 10 \
    --emergency-rss-bytes 25769803776 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "Fulmar qualified private installation" -- \
    /bin/zsh -f "$0"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Private installation inherited an invalid root-watchdog attestation."
  exit 126
fi

IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
CANDIDATE="/private/tmp/LocalHarnessBuild/Fulmar.app"
INSTALLED="/Applications/Fulmar.app"
MANIFEST="$PROJECT_DIR/build/release-manifest.json"
EVIDENCE_VERIFIER="$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs"
SWIFT_BUILD_JOBS="${FULMAR_SWIFT_BUILD_JOBS:-2}"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

case "$SWIFT_BUILD_JOBS" in
  1|2) ;;
  *)
    print -u2 "FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 2."
    exit 64
    ;;
esac
for required in "$IDENTITY" "$NODE" "$CANDIDATE" "$INSTALLED" "$MANIFEST" \
  "$EVIDENCE_VERIFIER"; do
  [[ -e "$required" && ! -L "$required" ]] || {
    print -u2 "Private installation is missing one exact unlinked input: $required"
    exit 1
  }
done

run_guarded() {
  local label="$1" seconds="$2" maximum="$3" grace="$4" emergency="$5"
  shift 5
  [[ "${1:-}" == "--" ]] || return 64
  shift
  "$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
    --seconds "$seconds" --max-rss-bytes "$maximum" \
    --rss-grace-seconds "$grace" --emergency-rss-bytes "$emergency" \
    --label "$label" -- "$@"
}

verify_qualified_candidate() {
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-frozen-candidate.sh" "$CANDIDATE"
  "$NODE" "$EVIDENCE_VERIFIER" \
    "$IDENTITY" "$MANIFEST" "$PROJECT_DIR/build"
}

# The first proof rejects stale source, archive, manifest, static-scan, runtime,
# toolchain, signature, or full-hardware evidence before a compiler is invoked.
verify_qualified_candidate

umask 077
TOOL_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-private-installer.XXXXXX)"
TOOL_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TOOL_ROOT")" || exit 126
cleanup() {
  local exit_code="${1:-$?}"
  case "$TOOL_ROOT" in
    /private/tmp/fulmar-private-installer.*) ;;
    *) print -u2 "Refusing to remove an invalid private-installer root."; return 126 ;;
  esac
  if [[ -d "$TOOL_ROOT" && ! -L "$TOOL_ROOT" \
     && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TOOL_ROOT" 2>/dev/null)" == "$TOOL_ROOT_IDENTITY" ]]; then
    /bin/rm -rf -- "$TOOL_ROOT" || return 126
  fi
  return "$exit_code"
}
on_signal() {
  local exit_code="$1"
  trap - EXIT HUP INT TERM
  cleanup "$exit_code" || true
  exit "$exit_code"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
/bin/mkdir -m 0700 "$TOOL_ROOT/home" "$TOOL_ROOT/tmp" "$TOOL_ROOT/clang" "$TOOL_ROOT/swift"
export TMPDIR="$TOOL_ROOT/tmp/"
source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"

typeset -a build_environment
build_environment=(
  "HOME=$TOOL_ROOT/home"
  "CFFIXED_USER_HOME=$TOOL_ROOT/home"
  "TMPDIR=$TOOL_ROOT/tmp/"
  "PATH=$SAFE_PATH"
  "USER=$(/usr/bin/id -un)"
  "LOGNAME=$(/usr/bin/id -un)"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
  "SDKROOT=$SDKROOT"
  "CLANG_MODULE_CACHE_PATH=$TOOL_ROOT/clang"
  "SWIFTPM_MODULECACHE_OVERRIDE=$TOOL_ROOT/swift"
)

for target in LocalHarnessAtomicInstallSwapHelper LocalHarnessPrivateInstallCoordinatorTool; do
  run_guarded "private installer $target build" 600 8589934592 5 12884901888 -- \
    /usr/bin/env -i "${build_environment[@]}" /usr/bin/swift build \
      --package-path "$PROJECT_DIR" --configuration release --disable-sandbox \
      --scratch-path "$TOOL_ROOT/build" \
      --jobs "$SWIFT_BUILD_JOBS" --target "$target" -Xswiftc -warnings-as-errors
done
BIN_DIR="$(run_guarded "private installer binary-path query" 120 2147483648 3 3221225472 -- \
  /usr/bin/env -i "${build_environment[@]}" /usr/bin/swift build \
    --package-path "$PROJECT_DIR" --configuration release --disable-sandbox \
    --scratch-path "$TOOL_ROOT/build" \
    --jobs "$SWIFT_BUILD_JOBS" --show-bin-path)"
[[ "$BIN_DIR" == "$TOOL_ROOT/build/"* && -d "$BIN_DIR" && ! -L "$TOOL_ROOT/build" \
   && "${BIN_DIR:A}" == "$BIN_DIR" ]] || {
  print -u2 "SwiftPM returned an unsafe private-installer binary path."
  exit 126
}
COORDINATOR="$BIN_DIR/LocalHarnessPrivateInstallCoordinatorTool"
HELPER="$BIN_DIR/LocalHarnessAtomicInstallSwapHelper"
CURRENT_UID="$(/usr/bin/id -u)"
for executable in "$COORDINATOR" "$HELPER"; do
  EXECUTABLE_DETAILS="$(/usr/bin/stat -f '%u:%Lp:%l:%HT' "$executable")"
  [[ -f "$executable" && ! -L "$executable" && -x "$executable" \
     && "$EXECUTABLE_DETAILS" =~ "^${CURRENT_UID}:[0-7]{1,2}[0145][0145]:1:Regular File$" ]] || {
    print -u2 "The private installer produced an unsafe executable."
    exit 126
  }
done

# Compilation is confined to the private disposable root. Rebind source,
# candidate, archive and retained full-hardware evidence immediately before the swap.
verify_qualified_candidate
NONCE="$("$NODE" -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
[[ "${#NONCE}" == 64 && "$NONCE" != *[^a-f0-9]* ]] || exit 126
run_guarded "Fulmar atomic private swap" 900 4294967296 5 8589934592 -- \
  /usr/bin/env -i HOME="$HOME" CFFIXED_USER_HOME="$HOME" PATH="$SAFE_PATH" \
    USER="$(/usr/bin/id -un)" LOGNAME="$(/usr/bin/id -un)" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    "$COORDINATOR" --nonce "$NONCE"

# The coordinator already performed a signature/tree proof and automatic
# rollback on any failed commit boundary. This independent archive/source proof
# ensures the installed path is byte-identical to the retained candidate too.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-frozen-candidate.sh" "$INSTALLED"
print "Installed the exact qualified Fulmar candidate. The previous app remains in its hidden rollback stage."
