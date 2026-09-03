#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 300 --max-rss-bytes 1073741824 --rss-grace-seconds 3 \
    --emergency-rss-bytes 2147483648 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete Fulmar clean" -- /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Fulmar clean inherited an invalid root-watchdog capability."
  exit 1
fi
source "$PROJECT_DIR/scripts/release-lock.zsh"

cleanup() {
  local exit_code="${1:-$?}"
  fulmar_release_release_lock
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
fulmar_acquire_release_lock "Fulmar clean"

# Keep the destructive set literal and rooted below the reviewed project/output
# locations.  Never derive it from caller-controlled environment or globs.
/bin/rm -rf -- \
  "$PROJECT_DIR/.build" \
  "$PROJECT_DIR/build/Fulmar.app" \
  "$PROJECT_DIR/build/Fulmar.dSYMs" \
  "$PROJECT_DIR/build/public-release-assets" \
  "/private/tmp/LocalHarnessBuild/Fulmar.app" \
  "/private/tmp/LocalHarnessBuild/Fulmar.dSYMs" \
  "/private/tmp/LocalHarnessBuild/Local Harness.app"
/bin/rm -f -- \
  "$PROJECT_DIR/build/Fulmar.app.zip" \
  "$PROJECT_DIR/build/Fulmar.dSYMs.zip" \
  "$PROJECT_DIR/build/release-manifest.json" \
  "$PROJECT_DIR/build/dependency-audit-summary.json" \
  "$PROJECT_DIR/build/runtime-unsigned-inventory.json" \
  "$PROJECT_DIR/build/runtime-signables.json" \
  "$PROJECT_DIR/build/runtime-release-inventory.json" \
  "$PROJECT_DIR/build/source-build-inputs.json" \
  "$PROJECT_DIR/build/toolchain-inventory.json" \
  "$PROJECT_DIR/build/static-security-summary.json" \
  "$PROJECT_DIR/build/ci-evidence-summary.json" \
  "/private/tmp/LocalHarnessBuild/Info.json"

# Retained candidate-bound `.evidence` sets, qualification logs, history, and
# rollback archives are deliberately outside the deletion set. They are audit
# records, not mutable inputs, and public/release gates never infer freshness
# from them without exact manifest verification.
