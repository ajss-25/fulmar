#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/root-group-lock.zsh"
(( $# == 1 )) || {
  print -u2 "usage: run-bounded-swift-product-gate.sh <runtime-lease|credential>"
  exit 64
}
GATE="$1"
[[ "$GATE" == runtime-lease || "$GATE" == credential ]] || exit 64

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 17179869184 --rss-grace-seconds 10 \
    --emergency-rss-bytes 25769803776 --lock-dir /private/tmp/FulmarSwiftTests.lock \
    --label "bounded Swift $GATE gate" -- /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The bounded Swift product gate inherited an invalid root-watchdog attestation."
  exit 126
fi

SWIFT_BUILD_JOBS="${FULMAR_SWIFT_BUILD_JOBS:-2}"
[[ "$SWIFT_BUILD_JOBS" == <-> && "$SWIFT_BUILD_JOBS" -ge 1 \
   && "$SWIFT_BUILD_JOBS" -le 2 ]] || {
  print -u2 "FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 2 for product gates."
  exit 64
}

TEST_LOCK_DIR="/private/tmp/FulmarSwiftTests.lock"
fulmar_acquire_root_group_lock "$TEST_LOCK_DIR" "bounded Swift product qualification" 1200
umask 077
ISOLATION_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-swift-product-gate.XXXXXX)"
cleanup() {
  local exit_code="${1:-$?}"
  case "$ISOLATION_ROOT" in
    /private/tmp/fulmar-swift-product-gate.*) /bin/rm -rf -- "$ISOLATION_ROOT" ;;
    *) print -u2 "Refusing to remove an invalid Swift product-gate root." ;;
  esac
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
/bin/mkdir -p "$ISOLATION_ROOT/clang" "$ISOLATION_ROOT/swift"
/bin/chmod 0700 "$ISOLATION_ROOT" "$ISOLATION_ROOT/clang" "$ISOLATION_ROOT/swift"
source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"

build_product() {
  local product="$1"
  /usr/bin/env \
    SDKROOT="$SDKROOT" \
    CLANG_MODULE_CACHE_PATH="$ISOLATION_ROOT/clang" \
    SWIFTPM_MODULECACHE_OVERRIDE="$ISOLATION_ROOT/swift" \
    /usr/bin/swift build \
      --package-path "$PROJECT_DIR" \
      --disable-sandbox \
      --jobs "$SWIFT_BUILD_JOBS" \
      --product "$product" \
      -Xswiftc -warnings-as-errors
}

case "$GATE" in
  runtime-lease)
    build_product LocalHarnessRuntimeLease
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-runtime-lease.sh" \
      "$PROJECT_DIR/.build/debug/LocalHarnessRuntimeLease"
    ;;
  credential)
    build_product LocalHarnessCredentialHelper
    build_product LocalHarnessCredentialBrokerService
    build_product LocalHarnessCredentialMigrationService
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-helper.sh"
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration.sh"
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-transaction-crash.sh"
    ;;
esac
