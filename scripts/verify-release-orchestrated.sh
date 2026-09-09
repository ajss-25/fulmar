#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
if [[ "${1:-}" != "--signing-profile" || "${2:-}" != "private-stable" ]]; then
  print -u2 "Release orchestration requires --signing-profile private-stable."
  exit 64
fi
typeset -a SIGNING_ARGUMENTS
SIGNING_ARGUMENTS=(--signing-profile private-stable)
shift 2
PROFILE="full-hardware"
if [[ "${1:-}" == "--deterministic-ci" ]]; then
  PROFILE="deterministic-ci"
  shift
fi
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Release orchestration inherited an invalid root-watchdog attestation."
  exit 126
elif (( ROOT_WATCHDOG_STATE == 0 )); then
  if [[ "$PROFILE" == "full-hardware" ]]; then
    exec /bin/zsh -f "$PROJECT_DIR/scripts/verify-release.sh" "${SIGNING_ARGUMENTS[@]}" "$@"
  fi
  exec /bin/zsh -f "$PROJECT_DIR/scripts/verify-release.sh" "${SIGNING_ARGUMENTS[@]}" --deterministic-ci "$@"
fi

/bin/zsh -f "$PROJECT_DIR/scripts/run-watchdog-self-tests.sh"

if [[ "$PROFILE" == "full-hardware" ]]; then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 5400 --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "Fulmar full release root" -- \
    /bin/zsh -f "$PROJECT_DIR/scripts/verify-release.sh" "${SIGNING_ARGUMENTS[@]}" "$@"
fi
exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
  --seconds 5400 --max-rss-bytes 32212254720 --rss-grace-seconds 10 \
  --emergency-rss-bytes 36507222016 --lock-dir /private/tmp/LocalHarnessBuild.lock \
  --label "Fulmar deterministic release root" -- \
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-release.sh" "${SIGNING_ARGUMENTS[@]}" --deterministic-ci "$@"
