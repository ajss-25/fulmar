#!/bin/zsh -f
set -euo pipefail
# Do not implicitly lower the candidate's priority when zsh backgrounds it;
# hardened qualification runners may deny `setpriority(2)` even though process
# launch itself is permitted.
unsetopt BG_NICE

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/supervised-process-group.zsh"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/release-lock.zsh"
APP_DIR="${1:-}"
[[ -n "$APP_DIR" ]] || {
  print -u2 "usage: verify-app-owned-ollama-generation.sh <candidate.app> [model]"
  exit 1
}
MODEL_ID="${2:-qwen3.8:27b-mlx}"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 600 --max-rss-bytes 30064771072 --rss-grace-seconds 10 \
    --emergency-rss-bytes 34359738368 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete app-owned Ollama qualification" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The app-owned Ollama gate inherited an invalid root-watchdog attestation."
  exit 1
fi
fulmar_acquire_release_lock "app-owned Ollama qualification"
EXPECTED_MANIFEST_DIGEST="5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"
BINARY="$APP_DIR/Contents/MacOS/LocalHarness"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
TEST_ROOT="$(mktemp -d /private/tmp/local-harness-ollama-generation.XXXXXX)"
PROCESS_STATUS_FILE="$TEST_ROOT/app-supervisor.status"
STDOUT_FILE="$TEST_ROOT/evidence.json"
STDERR_FILE="$TEST_ROOT/error.txt"
PROCESS_ID=""
PROCESS_GROUP_ID=""
MAX_SECONDS=210
THERMAL_ABORTED=0
THERMAL_ADMISSION_SAMPLES=5
THERMAL_ADMISSION_INTERVAL_SECONDS=2

read_thermal_state() {
  local state
  state="$(/usr/bin/osascript -l JavaScript -e 'ObjC.import("Foundation"); $.NSProcessInfo.processInfo.thermalState.toString()' 2>/dev/null)" || return 1
  [[ "$state" == <0-3> ]] || return 1
  print -r -- "$state"
}

require_stable_thermal_headroom() {
  local sample state
  for ((sample = 1; sample <= THERMAL_ADMISSION_SAMPLES; sample++)); do
    state="$(read_thermal_state || print 3)"
    if [[ "$state" -ge 1 ]]; then
      print -u2 "The app-owned Ollama generation gate did not start because macOS could not prove sustained nominal thermal headroom. Let the Mac cool down, then rerun it."
      exit 75
    fi
    if (( sample < THERMAL_ADMISSION_SAMPLES )); then
      sleep "$THERMAL_ADMISSION_INTERVAL_SECONDS"
    fi
  done
}

cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$PROCESS_ID" ]]; then
    fulmar_stop_inherited_process "$PROCESS_ID" "app-owned Ollama generation" || true
  fi
  case "$TEST_ROOT" in
    /private/tmp/local-harness-ollama-generation.[A-Za-z0-9]*) rm -rf -- "$TEST_ROOT" ;;
    *) print -u2 "Refusing to remove an unexpected generation-canary path." ;;
  esac
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

[[ -x "$BINARY" ]] || { print -u2 "Missing candidate LocalHarness executable."; exit 1; }
[[ -x "$NODE" ]] || { print -u2 "Missing candidate bundled Node validator."; exit 1; }
chmod 700 "$TEST_ROOT"

require_stable_thermal_headroom

"$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
  --seconds "$MAX_SECONDS" --max-rss-bytes 30064771072 --rss-grace-seconds 10 \
  --emergency-rss-bytes 34359738368 --status-file "$PROCESS_STATUS_FILE" \
  --label "app-owned Ollama generation" -- \
  "$BINARY" --qualify-app-owned-ollama-generation "$MODEL_ID" "$TEST_ROOT" \
  >"$STDOUT_FILE" 2>"$STDERR_FILE" &
PROCESS_ID="$!"
PROCESS_GROUP_ID="$FULMAR_ROOT_WATCHDOG_PGID_V1"
fulmar_attest_pid_in_process_group "$PROCESS_ID" "$PROCESS_GROUP_ID" || {
  print -u2 "The app-owned Ollama generation gate left its attested root process group."
  exit 1
}

ATTEMPT_LIMIT=$(( MAX_SECONDS * 4 ))
THERMAL_POLL_COUNTDOWN=8
for ((attempt = 1; attempt <= ATTEMPT_LIMIT; attempt++)); do
  kill -0 "$PROCESS_ID" >/dev/null 2>&1 || break
  THERMAL_POLL_COUNTDOWN=$(( THERMAL_POLL_COUNTDOWN - 1 ))
  if (( THERMAL_POLL_COUNTDOWN == 0 )); then
    THERMAL_POLL_COUNTDOWN=8
    thermal_state="$(read_thermal_state || print 3)"
    if [[ "$thermal_state" -ge 1 ]]; then
      THERMAL_ABORTED=1
      fulmar_stop_inherited_process "$PROCESS_ID" "app-owned Ollama generation" || true
      PROCESS_ID=""
      PROCESS_GROUP_ID=""
      break
    fi
  fi
  sleep 0.25
done
if (( THERMAL_ABORTED == 1 )); then
  print -u2 "The app-owned Ollama generation gate stopped because macOS reported thermal pressure. Let the Mac cool down, then rerun it."
  exit 75
fi
if kill -0 "$PROCESS_ID" >/dev/null 2>&1; then
  print -u2 "The app-owned Ollama generation gate exceeded $MAX_SECONDS seconds."
  tail -c 8192 "$STDERR_FILE" >&2 || true
  exit 1
fi
for _ in {1..20}; do
  [[ -f "$PROCESS_STATUS_FILE" ]] && break
  sleep 0.05
done
PROCESS_STATUS_METADATA="$(/usr/bin/stat -f '%u:%Lp:%l:%z' "$PROCESS_STATUS_FILE" 2>/dev/null || true)"
case "$PROCESS_STATUS_METADATA" in
  "$(/usr/bin/id -u):600:1:2"|"$(/usr/bin/id -u):600:1:3"|"$(/usr/bin/id -u):600:1:4") ;;
  *)
  print -u2 "The app-owned generation supervisor did not publish a safe bounded status receipt."
  exit 1
  ;;
esac
PROCESS_STATUS="$(/bin/cat "$PROCESS_STATUS_FILE")"
if [[ "$PROCESS_STATUS" != "0" ]]; then
  tail -c 8192 "$STDERR_FILE" >&2 || true
  exit 1
fi
PROCESS_ID=""
PROCESS_GROUP_ID=""

[[ ! -s "$STDERR_FILE" ]]
EVIDENCE_VERSION="$("$NODE" -e '
  const fs = require("node:fs");
  const [file, expectedModel, expectedDigest] = process.argv.slice(1);
  const bytes = fs.readFileSync(file);
  if (bytes.length < 2 || bytes.length > 4096) process.exit(1);
  const value = JSON.parse(bytes.toString("utf8"));
  const keys = Object.keys(value).sort();
  const expectedKeys = [
    "generatedTextRetained", "gpuResident", "manifestDigest", "model", "officialSignature",
    "ollamaVersion", "randomLoopbackEndpoint", "realGeneration", "schema", "seatbeltIsolated"
  ].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)
      || value.schema !== "local-harness-app-owned-ollama-generation-v1"
      || value.model !== expectedModel
      || value.manifestDigest !== expectedDigest
      || value.generatedTextRetained !== false
      || value.gpuResident !== true
      || value.officialSignature !== true
      || value.randomLoopbackEndpoint !== true
      || value.realGeneration !== true
      || value.seatbeltIsolated !== true) process.exit(1);
  if (typeof value.ollamaVersion !== "string") process.exit(1);
  process.stdout.write(value.ollamaVersion);
' "$STDOUT_FILE" "$MODEL_ID" "$EXPECTED_MANIFEST_DIGEST")"
VALIDATED_VERSION="$("$NODE" "$PROJECT_DIR/scripts/ollama-version-policy.mjs" \
  --version "$EVIDENCE_VERSION")"
[[ "$VALIDATED_VERSION" == "$EVIDENCE_VERSION" ]]

set +e
/usr/bin/grep -Eq 'LOCAL_HARNESS_APP_OWNED_QWEN_OK|response|prompt|token' "$STDOUT_FILE"
RETAINED_TEXT_STATUS=$?
set -e
if (( RETAINED_TEXT_STATUS == 0 )); then
  print -u2 "App-owned generation evidence retained generated text."
  exit 1
elif (( RETAINED_TEXT_STATUS != 1 )); then
  print -u2 "App-owned generation evidence could not be scanned safely."
  exit 1
fi
print "Candidate app-owned sandboxed Ollama $EVIDENCE_VERSION performed a bounded real generation with exact model $MODEL_ID and reported GPU residency without retaining generated text."
