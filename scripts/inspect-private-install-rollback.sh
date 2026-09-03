#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"

typeset -a FORWARD_ARGS
FORWARD_ARGS=("$@")
MODE="${1:-}"
if (( $# > 1 )); then
  print -u2 "usage: inspect-private-install-rollback.sh [recovery-operation]"
  exit 64
fi
case "$MODE" in
  ""|--resume-interrupted|--finalize-interrupted|--cancel-interrupted|--retire-committed|--reconcile-records) ;;
  *)
    print -u2 "usage: inspect-private-install-rollback.sh [--resume-interrupted|--finalize-interrupted|--cancel-interrupted|--retire-committed|--reconcile-records]"
    exit 64
    ;;
esac

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1200 --max-rss-bytes 8589934592 --rss-grace-seconds 5 \
    --emergency-rss-bytes 12884901888 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "Fulmar private install recovery" -- \
    /bin/zsh -f "$0" "${FORWARD_ARGS[@]}"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Rollback inspection inherited an invalid root-watchdog attestation."
  exit 126
fi

SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
SWIFT_BUILD_JOBS="${FULMAR_SWIFT_BUILD_JOBS:-2}"
IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
CANDIDATE="/private/tmp/LocalHarnessBuild/Fulmar.app"
INSTALLED="/Applications/Fulmar.app"
MANIFEST="$PROJECT_DIR/build/release-manifest.json"
SOURCE_INPUTS="$PROJECT_DIR/build/source-build-inputs.json"
EVIDENCE_VERIFIER="$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs"
case "$SWIFT_BUILD_JOBS" in
  1|2) ;;
  *)
    print -u2 "FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 2."
    exit 64
    ;;
esac
for required in "$IDENTITY" "$NODE" "$INSTALLED" "$MANIFEST" "$SOURCE_INPUTS" \
  "$EVIDENCE_VERIFIER" "$PROJECT_DIR/scripts/source-build-input-inventory.mjs"; do
  [[ -e "$required" && ! -L "$required" ]] || {
    print -u2 "Rollback inspection requires the retained exact candidate and qualification evidence: $required"
    exit 1
  }
done
[[ (! -e "$CANDIDATE" && ! -L "$CANDIDATE") \
   || (-d "$CANDIDATE" && ! -L "$CANDIDATE") ]] || {
  print -u2 "Rollback inspection rejected an unsafe retained candidate path."
  exit 1
}

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

verify_qualified_recovery_source() {
  if [[ -d "$CANDIDATE" && ! -L "$CANDIDATE" ]]; then
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-frozen-candidate.sh" "$CANDIDATE"
  else
    "$NODE" "$PROJECT_DIR/scripts/source-build-input-inventory.mjs" \
      verify "$PROJECT_DIR" "$SOURCE_INPUTS"
    "$NODE" "$EVIDENCE_VERIFIER" \
      "$IDENTITY" "$MANIFEST" "$PROJECT_DIR/build"
  fi
}

# A private inspector compiled from a changed checkout must never vouch for an
# older transaction. Bind the checkout and retained qualification evidence—and
# the frozen candidate when it remains present—before compilation. The native
# inspector then binds installed/stage/archive bytes to the durable records.
verify_qualified_recovery_source

umask 077
TOOL_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-private-rollback-inspector.XXXXXX)"
TOOL_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TOOL_ROOT")" || exit 126
cleanup() {
  local exit_code="${1:-$?}"
  case "$TOOL_ROOT" in
    /private/tmp/fulmar-private-rollback-inspector.*) ;;
    *) print -u2 "Refusing to remove an invalid rollback-inspector root."; return 126 ;;
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

typeset -a BUILD_TARGETS
BUILD_TARGETS=(LocalHarnessPrivateRollbackInspectorTool)
if [[ -n "$MODE" ]]; then
  BUILD_TARGETS+=(LocalHarnessAtomicInstallSwapHelper)
fi
for target in "${BUILD_TARGETS[@]}"; do
  run_guarded "private recovery $target build" 600 6442450944 5 9663676416 -- \
    /usr/bin/env -i "${build_environment[@]}" /usr/bin/swift build \
      --package-path "$PROJECT_DIR" --configuration release --disable-sandbox \
      --scratch-path "$TOOL_ROOT/build" \
      --jobs "$SWIFT_BUILD_JOBS" --target "$target" \
      -Xswiftc -warnings-as-errors
done
BIN_DIR="$(run_guarded "private rollback binary-path query" 120 2147483648 3 3221225472 -- \
  /usr/bin/env -i "${build_environment[@]}" /usr/bin/swift build \
    --package-path "$PROJECT_DIR" --configuration release --disable-sandbox \
    --scratch-path "$TOOL_ROOT/build" \
    --jobs "$SWIFT_BUILD_JOBS" --show-bin-path)"
[[ "$BIN_DIR" == "$TOOL_ROOT/build/"* && -d "$BIN_DIR" \
   && ! -L "$TOOL_ROOT/build" && "${BIN_DIR:A}" == "$BIN_DIR" ]] || {
  print -u2 "SwiftPM returned an unsafe rollback-inspector binary path."
  exit 126
}
INSPECTOR="$BIN_DIR/LocalHarnessPrivateRollbackInspectorTool"
HELPER="$BIN_DIR/LocalHarnessAtomicInstallSwapHelper"
CURRENT_UID="$(/usr/bin/id -u)"
typeset -a EXECUTABLES
EXECUTABLES=("$INSPECTOR")
[[ -z "$MODE" ]] || EXECUTABLES+=("$HELPER")
for executable in "${EXECUTABLES[@]}"; do
  EXECUTABLE_DETAILS="$(/usr/bin/stat -f '%u:%Lp:%l:%HT' "$executable")"
  [[ -f "$executable" && ! -L "$executable" && -x "$executable" \
     && "$EXECUTABLE_DETAILS" =~ "^${CURRENT_UID}:[0-7]{1,2}[0145][0145]:1:Regular File$" ]] || {
    print -u2 "Private recovery produced an unsafe executable."
    exit 126
  }
done

# Rebind the reviewed source/evidence state after compilation and immediately
# before the native tool repeats all transaction proofs.
verify_qualified_recovery_source
run_guarded "Fulmar retained rollback proof" 900 4294967296 5 8589934592 -- \
  /usr/bin/env -i HOME="$HOME" CFFIXED_USER_HOME="$HOME" PATH="$SAFE_PATH" \
    USER="$(/usr/bin/id -un)" LOGNAME="$(/usr/bin/id -un)" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    "$INSPECTOR" "${FORWARD_ARGS[@]}"
