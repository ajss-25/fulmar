#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
[[ -x "$NODE" && ! -L "$NODE" ]] || {
  print -u2 "The watchdog self-test runtime is unavailable or linked."
  exit 1
}
umask 077
ISOLATION_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-watchdog-self-tests.XXXXXX)"
HOME_ROOT="$ISOLATION_ROOT/home"
TEMP_ROOT="$ISOLATION_ROOT/tmp"
EVENTS="$ISOLATION_ROOT/events.jsonl"
/bin/mkdir -m 0700 "$HOME_ROOT" "$TEMP_ROOT"
ISOLATION_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT")" || exit 126
cleanup() {
  [[ -n "$ISOLATION_ROOT" ]] || return 0
  [[ "$ISOLATION_ROOT" == /private/tmp/fulmar-watchdog-self-tests.* \
     && -d "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" \
     && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT" 2>/dev/null)" == "$ISOLATION_IDENTITY" ]] || return 126
  /bin/rm -rf -- "$ISOLATION_ROOT" || return 126
  [[ ! -e "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" ]] || return 126
  ISOLATION_ROOT=""
}
trap 'cleanup >/dev/null 2>&1 || true' EXIT
trap 'cleanup >/dev/null 2>&1 || true; exit 129' HUP
trap 'cleanup >/dev/null 2>&1 || true; exit 130' INT
trap 'cleanup >/dev/null 2>&1 || true; exit 143' TERM
# These fixtures each create their own session in order to test the production
# supervisor or its drain-before-publication evidence boundary. They therefore
# run before, not inside, the release root. A separate
# process-tree monitor bounds the complete test runner across those sessions,
# aggregates their RSS, and refuses success until every observed descendant is
# gone. --test-force-exit closes Node-handle leaks after each bounded test.
set +e
/usr/bin/env -i \
  HOME="$HOME_ROOT" CFFIXED_USER_HOME="$HOME_ROOT" TMPDIR="$TEMP_ROOT/" \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
  "$NODE" "$PROJECT_DIR/scripts/run-process-tree-watchdog.mjs" \
    --seconds 900 --max-rss-bytes 2147483648 --emergency-rss-bytes 4294967296 \
    --label "Fulmar supervisor and evidence self-test suite" -- \
    "$NODE" --test --experimental-test-isolation=none --test-force-exit \
      --test-concurrency=1 --test-timeout=30000 \
      --test-reporter=spec --test-reporter-destination=stdout \
      --test-reporter="$PROJECT_DIR/scripts/self-root-test-event-reporter.mjs" \
      --test-reporter-destination="$EVENTS" \
      "$PROJECT_DIR/Tests/JS/ReleaseWatchdogTests.mjs" \
      "$PROJECT_DIR/Tests/JS/ReleaseEvidenceRetentionTests.mjs"
suite_status=$?
set -e
if (( suite_status == 0 )); then
  /usr/bin/env -i HOME="$HOME_ROOT" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    "$NODE" "$PROJECT_DIR/scripts/verify-self-root-test-events.mjs" "$EVENTS" || suite_status=$?
fi
trap - EXIT HUP INT TERM
if ! cleanup; then
  print -u2 "The self-root JavaScript suite could not remove its attested private isolation root."
  exit 126
fi
exit "$suite_status"
