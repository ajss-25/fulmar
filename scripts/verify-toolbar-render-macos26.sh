#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
HOST_VERSION="$(/usr/bin/sw_vers -productVersion)"
HOST_MAJOR="${HOST_VERSION%%.*}"

[[ "$HOST_MAJOR" == "26" ]] || {
  print -u2 "The release toolbar-render gate requires macOS 26; this host is macOS $HOST_VERSION."
  exit 1
}

exec /usr/bin/env \
  FULMAR_SWIFT_WATCHDOG_SECONDS=300 \
  FULMAR_SWIFT_WATCHDOG_RSS_BYTES=2147483648 \
  FULMAR_SWIFT_WATCHDOG_RSS_GRACE_SECONDS=3 \
  FULMAR_SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES=3221225472 \
  /bin/zsh -f "$PROJECT_DIR/scripts/run-swift-tests.sh" \
  --focused-filter renderedMacOS26Toolbar
