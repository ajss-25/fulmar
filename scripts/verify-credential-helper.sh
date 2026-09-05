#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/root-group-lock.zsh"
(( $# <= 1 )) || { print -u2 "Usage: verify-credential-helper.sh [credential-helper]"; exit 64; }
HELPER="${1:-$PROJECT_DIR/.build/debug/LocalHarnessCredentialHelper}"
NODE="${LOCAL_HARNESS_TEST_NODE:-$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node}"

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 17179869184 --rss-grace-seconds 10 \
    --emergency-rss-bytes 25769803776 --lock-dir /private/tmp/FulmarSwiftTests.lock \
    --label "credential helper qualification" -- /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Credential helper qualification inherited an invalid root watchdog."
  exit 126
fi

/bin/zsh -f "$PROJECT_DIR/scripts/verify-telemetry-lock-helper.sh" "$HELPER"
"$NODE" "$PROJECT_DIR/scripts/verify-credential-helper-bounds.mjs" "$HELPER"

# A detached release helper deliberately refuses every broker command. Build
# the existing DEBUG-only historical source seam for the changed-signer fixture;
# the current helper under test remains the exact, unmodified supplied candidate.
TEST_LOCK_DIR="/private/tmp/FulmarSwiftTests.lock"
fulmar_acquire_root_group_lock "$TEST_LOCK_DIR" "legacy credential fixture compilation" 1200
umask 077
FIXTURE_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-legacy-credential-fixture.XXXXXX)"
FIXTURE_ROOT="${FIXTURE_ROOT:A}"
FIXTURE_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$FIXTURE_ROOT")"
cleanup() {
  local exit_code="${1:-$?}"
  if [[ "$FIXTURE_ROOT" == /private/tmp/fulmar-legacy-credential-fixture.* \
     && -d "$FIXTURE_ROOT" && ! -L "$FIXTURE_ROOT" \
     && "$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$FIXTURE_ROOT")" == "$FIXTURE_IDENTITY" ]]; then
    /bin/rm -rf -- "$FIXTURE_ROOT"
  else
    print -u2 "Refusing to remove an invalid legacy credential fixture root."
    exit_code=1
  fi
  fulmar_release_root_group_lock "$TEST_LOCK_DIR"
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
/bin/mkdir -m 0700 "$FIXTURE_ROOT/clang" "$FIXTURE_ROOT/swift"
source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"
typeset -a fixture_build
fixture_build=(
  /usr/bin/env "SDKROOT=$SDKROOT"
  "CLANG_MODULE_CACHE_PATH=$FIXTURE_ROOT/clang"
  "SWIFTPM_MODULECACHE_OVERRIDE=$FIXTURE_ROOT/swift"
  /usr/bin/swift build --package-path "$PROJECT_DIR" --disable-sandbox
  --scratch-path "$FIXTURE_ROOT/build" --jobs 1 -c debug
)
"${fixture_build[@]}" --product LocalHarnessCredentialHelper -Xswiftc -warnings-as-errors
FIXTURE_BIN_PATH="$("${fixture_build[@]}" --show-bin-path)"
FIXTURE_BIN_PATH="${FIXTURE_BIN_PATH:A}"
LEGACY_FIXTURE="$FIXTURE_BIN_PATH/LocalHarnessCredentialHelper"
[[ "$FIXTURE_BIN_PATH" == "$FIXTURE_ROOT/build/"* \
   && -f "$LEGACY_FIXTURE" && ! -L "$LEGACY_FIXTURE" && -x "$LEGACY_FIXTURE" \
   && "$(/usr/bin/stat -f '%u:%l' "$LEGACY_FIXTURE")" == "$(/usr/bin/id -u):1" ]] || {
  print -u2 "The historical credential fixture is not a private regular executable."
  exit 1
}
"$NODE" "$PROJECT_DIR/scripts/verify-keychain-no-ui-transition.mjs" "$HELPER" "$LEGACY_FIXTURE"
