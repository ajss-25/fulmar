#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-}"
[[ -n "$APP_DIR" ]] || {
  print -u2 "usage: verify-credential-migration-xpc-live.sh <canonical Fulmar.app>"
  exit 1
}
EXECUTABLE="$APP_DIR/Contents/MacOS/LocalHarness"
SERVICE_EXECUTABLE="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
PROCESS_MONITOR="$PROJECT_DIR/scripts/credential-xpc-live-process-monitor.mjs"
TIMEOUT_SECONDS=15
EXPECTED='FULMAR_CREDENTIAL_XPC_ACCEPTANCE_OK'
PROCESS_EXPECTED='FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK'

[[ -d "$APP_DIR" && ! -L "$APP_DIR" && "${APP_DIR:A}" == "$APP_DIR" \
   && -f "$EXECUTABLE" && ! -L "$EXECUTABLE" && -x "$EXECUTABLE" ]] || {
  print -u2 "Credential XPC live acceptance requires one canonical packaged app."
  exit 1
}
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration-xpc.sh" "$APP_DIR"

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-credential-xpc-live.XXXXXX)"
ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$TEMP_ROOT")"
EXPECTED_UID="$(/usr/bin/id -u)"
PID=0
MONITOR_PID=0
cleanup() {
  local prior_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( PID > 1 )) && /bin/kill -0 "$PID" 2>/dev/null; then
    /bin/kill -TERM "$PID" 2>/dev/null
    /bin/sleep 0.1
    /bin/kill -KILL "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
  if (( MONITOR_PID > 1 )) && /bin/kill -0 "$MONITOR_PID" 2>/dev/null; then
    /bin/kill -TERM "$MONITOR_PID" 2>/dev/null
    /bin/sleep 0.1
    /bin/kill -KILL "$MONITOR_PID" 2>/dev/null
    wait "$MONITOR_PID" 2>/dev/null
  fi
  if [[ -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" && "${TEMP_ROOT:A}" == "$TEMP_ROOT" \
     && "$TEMP_ROOT" == /private/tmp/fulmar-credential-xpc-live.* \
     && "$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$TEMP_ROOT" 2>/dev/null)" == "$ROOT_IDENTITY" \
     && "$ROOT_IDENTITY" == *":$EXPECTED_UID:700" ]]; then
    /bin/rm -rf -- "$TEMP_ROOT"
  else
    print -u2 "Credential XPC live acceptance refused unsafe temporary cleanup."
    prior_status=1
  fi
  exit "$prior_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
STDOUT_FILE="$TEMP_ROOT/stdout"
STDERR_FILE="$TEMP_ROOT/stderr"
DONE_FILE="$TEMP_ROOT/client.done"
READY_FILE="$TEMP_ROOT/monitor.ready"
EVIDENCE_FILE="$TEMP_ROOT/service.evidence"

"$NODE" "$PROCESS_MONITOR" "$SERVICE_EXECUTABLE" "$READY_FILE" "$DONE_FILE" "$EVIDENCE_FILE" \
  >"$TEMP_ROOT/monitor.stdout" 2>"$TEMP_ROOT/monitor.stderr" &
MONITOR_PID=$!
READY_STARTED=$SECONDS
while [[ ! -f "$READY_FILE" ]]; do
  /bin/kill -0 "$MONITOR_PID" 2>/dev/null || exit 1
  (( SECONDS - READY_STARTED < 3 )) || exit 1
  /bin/sleep 0.01
done
[[ ! -L "$READY_FILE" && "$(/usr/bin/stat -f '%u:%Lp:%z' "$READY_FILE")" == "$EXPECTED_UID:600:6" \
   && "$(/bin/cat "$READY_FILE")" == ready ]] || exit 1

"$EXECUTABLE" --credential-migration-xpc-acceptance \
  >"$STDOUT_FILE" 2>"$STDERR_FILE" &
PID=$!
STARTED=$SECONDS
while /bin/kill -0 "$PID" 2>/dev/null; do
  if (( SECONDS - STARTED >= TIMEOUT_SECONDS )); then
    /bin/kill -TERM "$PID" 2>/dev/null || true
    for _ in {1..20}; do
      /bin/kill -0 "$PID" 2>/dev/null || break
      /bin/sleep 0.05
    done
    /bin/kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    print -u2 "Credential XPC live acceptance exceeded its 15-second hard bound."
    exit 1
  fi
  /bin/sleep 0.05
done
set +e
wait "$PID"
STATUS=$?
set -e
PID=0
( set -o noclobber; print -r -- done > "$DONE_FILE" ) || exit 1

MONITOR_STARTED=$SECONDS
while /bin/kill -0 "$MONITOR_PID" 2>/dev/null; do
  if (( SECONDS - MONITOR_STARTED >= 8 )); then
    print -u2 "Credential migration exact-process drain exceeded its hard bound."
    exit 1
  fi
  /bin/sleep 0.05
done
set +e
wait "$MONITOR_PID"
MONITOR_STATUS=$?
set -e
MONITOR_PID=0
[[ "$STATUS" == 0 && ! -s "$STDERR_FILE" \
   && "$(/bin/cat "$STDOUT_FILE")" == "$EXPECTED" ]] || {
  print -u2 "Credential XPC live acceptance failed its exact one-shot contract."
  /bin/cat "$STDERR_FILE" >&2
  exit 1
}
[[ "$MONITOR_STATUS" == 0 && ! -s "$TEMP_ROOT/monitor.stderr" \
   && "$(/bin/cat "$TEMP_ROOT/monitor.stdout")" == "$PROCESS_EXPECTED" \
   && -f "$EVIDENCE_FILE" && ! -L "$EVIDENCE_FILE" \
   && "$(/usr/bin/stat -f '%u:%Lp' "$EVIDENCE_FILE")" == "$EXPECTED_UID:600" \
   && "$(/usr/bin/wc -l < "$EVIDENCE_FILE" | /usr/bin/tr -d ' ')" == 3 \
   && "$(/usr/bin/sed -n '1p' "$EVIDENCE_FILE")" =~ '^pid=[0-9]+$' \
   && "$(/usr/bin/sed -n '3p' "$EVIDENCE_FILE")" =~ '^cdhash=[a-f0-9]{40,128}$' ]] || {
  print -u2 "Credential migration live acceptance lacked exact service identity/drain evidence."
  /bin/cat "$TEMP_ROOT/monitor.stderr" >&2
  exit 1
}

print "Credential migration live XPC acceptance passed without provider references or Keychain values."
