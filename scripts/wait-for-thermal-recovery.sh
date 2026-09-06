#!/bin/bash -p
set -euo pipefail

# These direct physical-Qwen gates run outside Fulmar's adaptive controller.
# Preserve the shipping 120-second sustained-load idle period and require a
# continuous 60-second nominal proof before another workload begins.
MINIMUM_IDLE_MILLISECONDS=120000
STABLE_NOMINAL_MILLISECONDS=60000
SAMPLE_INTERVAL_SECONDS=2
MAXIMUM_WAIT_MILLISECONDS=600000
TEST_AUTH_VALUE="enabled-by-behavioral-test"
SAMPLE_SCHEMA="fulmar-thermal-sample-v1"
CLOCK_SCHEMA="fulmar-thermal-clock-v1"

PROBE_PAYLOAD=""
WORK_ROOT=""

usage() {
  printf '%s\n' \
    "usage: wait-for-thermal-recovery.sh --live <native-probe> <app-owned-generation|bash|filesystem|project>" \
    "       wait-for-thermal-recovery.sh --test-probe <native-probe> <scenario> <app-owned-generation|bash|filesystem|project>" >&2
  exit 64
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$WORK_ROOT" ]]; then
    case "$WORK_ROOT" in
      /private/tmp/fulmar-thermal-recovery.[A-Za-z0-9]*) /bin/rm -rf -- "$WORK_ROOT" ;;
      *) printf '%s\n' "Refusing to remove an unexpected thermal recovery path." >&2 ; status=1 ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT

[[ $# -ge 1 ]] || usage
MODE="$1"
shift
SCENARIO=""
case "$MODE" in
  --live)
    [[ $# -eq 2 ]] || usage
    [[ -z "${FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1:-}" ]] || {
      printf '%s\n' "The live thermal recovery gate rejects test-probe authorization." >&2
      exit 64
    }
    ;;
  --test-probe)
    [[ $# -eq 3 ]] || usage
    [[ "${FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1:-}" == "$TEST_AUTH_VALUE" ]] || {
      printf '%s\n' "The thermal recovery test-probe seam requires explicit authorization." >&2
      exit 64
    }
    SCENARIO="$2"
    case "$SCENARIO" in
      hang|hung-once|invalid|monotonic-backward|nominal|reset|stopped-once|timeout|wall-backward|wall-forward) ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac

PROBE_BINARY="$1"
if [[ "$MODE" == "--test-probe" ]]; then
  shift 2
else
  shift
fi
STAGE="$1"
case "$STAGE" in
  app-owned-generation|bash|filesystem|project) ;;
  *) usage ;;
esac

[[ "$PROBE_BINARY" == /* && "$PROBE_BINARY" != *$'\n'* && "$PROBE_BINARY" != *$'\r'* \
   && -f "$PROBE_BINARY" && ! -L "$PROBE_BINARY" && -x "$PROBE_BINARY" \
   && "$(/usr/bin/stat -f '%u:%Lp:%l' "$PROBE_BINARY")" == "$(/usr/bin/id -u):700:1" ]] || {
  printf '%s\n' "The thermal recovery probe must be one private owner executable." >&2
  exit 1
}

WORK_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-thermal-recovery.XXXXXX)"
/bin/chmod 0700 "$WORK_ROOT"
PROBE_STDOUT="$WORK_ROOT/probe.stdout"
PROBE_STDERR="$WORK_ROOT/probe.stderr"

validate_supervisor_stderr() {
  local status="$1" line line_count=0 pid_count=0 watchdog_count=0
  while IFS= read -r line; do
    line_count=$((line_count + 1))
    case "$line" in
      TEST_PROBE_PID=*)
        [[ "$MODE" == "--test-probe" && "$line" =~ ^TEST_PROBE_PID=[0-9]+$ ]] || return 1
        pid_count=$((pid_count + 1))
        ;;
      "The native thermal probe exceeded its one-second watchdog.")
        watchdog_count=$((watchdog_count + 1))
        ;;
      *) return 1 ;;
    esac
  done < "$PROBE_STDERR"
  (( line_count <= 2 && pid_count <= 1 && watchdog_count <= 1 )) || return 1
  if [[ "$MODE" == "--test-probe" ]]; then
    (( pid_count == 1 )) || return 1
  else
    (( pid_count == 0 )) || return 1
  fi
  if (( status == 0 )); then
    (( watchdog_count == 0 )) || return 1
  elif (( status == 124 )); then
    (( watchdog_count == 1 )) || return 1
  fi
}

run_probe() {
  : > "$PROBE_STDOUT"
  : > "$PROBE_STDERR"
  /bin/chmod 0600 "$PROBE_STDOUT" "$PROBE_STDERR"
  local status stderr_bytes
  set +e
  "$PROBE_BINARY" "$@" >"$PROBE_STDOUT" 2>"$PROBE_STDERR"
  status=$?
  set -e
  stderr_bytes="$(/usr/bin/stat -f '%z' "$PROBE_STDERR")" || return 1
  [[ "$stderr_bytes" =~ ^[0-9]+$ && "$stderr_bytes" -le 512 ]] || return 1
  validate_supervisor_stderr "$status" || return 1
  if [[ -s "$PROBE_STDERR" ]]; then
    /bin/cat "$PROBE_STDERR" >&2
  fi
  (( status == 0 )) || return "$status"
  local bytes lines
  bytes="$(/usr/bin/stat -f '%z' "$PROBE_STDOUT")" || return 1
  [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -ge 2 && "$bytes" -le 256 ]] || return 1
  lines="$(/usr/bin/wc -l < "$PROBE_STDOUT" | /usr/bin/tr -d ' ')" || return 1
  [[ "$lines" == "1" ]] || return 1
  IFS= read -r PROBE_PAYLOAD < "$PROBE_STDOUT" || return 1
}

SAMPLED_MILLISECONDS=""
SAMPLED_STATE="invalid"

read_sample() {
  local index="$1" schema milliseconds state wall extra
  if [[ "$MODE" == "--live" ]]; then
    run_probe --supervise-sample || return 1
  else
    run_probe --test-supervise-sample "$SCENARIO" "$index" || return 1
  fi
  IFS=' ' read -r schema milliseconds state wall extra <<< "$PROBE_PAYLOAD"
  [[ "$schema" == "$SAMPLE_SCHEMA" && -z "$extra" \
     && "$milliseconds" =~ ^[0-9]+$ && "$wall" =~ ^-?[0-9]+$ ]] || return 1
  SAMPLED_MILLISECONDS="$milliseconds"
  if [[ "$state" =~ ^[0-3]$ ]]; then
    SAMPLED_STATE="$state"
  else
    SAMPLED_STATE="invalid"
  fi
}

read_monotonic_fallback() {
  local index="$1" schema milliseconds extra
  if [[ "$MODE" == "--live" ]]; then
    run_probe --supervise-monotonic || return 1
  else
    run_probe --test-supervise-monotonic "$SCENARIO" "$index" || return 1
  fi
  IFS=' ' read -r schema milliseconds extra <<< "$PROBE_PAYLOAD"
  [[ "$schema" == "$CLOCK_SCHEMA" && -z "$extra" && "$milliseconds" =~ ^[0-9]+$ ]] || return 1
  SAMPLED_MILLISECONDS="$milliseconds"
  SAMPLED_STATE="invalid"
}

obtain_sample() {
  local index="$1"
  if read_sample "$index"; then return 0; fi
  read_monotonic_fallback "$index" || {
    printf '%s\n' "The native monotonic probe failed, so the thermal deadline cannot be proven." >&2
    return 1
  }
}

sample_index=0
obtain_sample "$sample_index" || exit 1
start_milliseconds="$SAMPLED_MILLISECONDS"
previous_milliseconds="$SAMPLED_MILLISECONDS"
nominal_since_milliseconds=-1

printf 'Thermal recovery after %s: requiring 120s idle and 60s continuously nominal (600s maximum).\n' "$STAGE"
while true; do
  current_milliseconds="$SAMPLED_MILLISECONDS"
  if (( current_milliseconds < previous_milliseconds \
        || current_milliseconds < start_milliseconds )); then
    printf '%s\n' "The native monotonic probe moved backwards; refusing thermal evidence." >&2
    exit 1
  fi
  elapsed_milliseconds=$((current_milliseconds - start_milliseconds))
  if [[ "$SAMPLED_STATE" == "0" ]]; then
    if (( nominal_since_milliseconds < 0 )); then
      nominal_since_milliseconds=$current_milliseconds
    fi
    nominal_milliseconds=$((current_milliseconds - nominal_since_milliseconds))
  else
    nominal_since_milliseconds=-1
    nominal_milliseconds=0
  fi

  if (( elapsed_milliseconds >= MINIMUM_IDLE_MILLISECONDS \
        && nominal_milliseconds >= STABLE_NOMINAL_MILLISECONDS )); then
    printf 'Thermal recovery after %s proved %ss idle with %ss continuously nominal.\n' \
      "$STAGE" "$((elapsed_milliseconds / 1000))" "$((nominal_milliseconds / 1000))"
    exit 0
  fi
  if (( elapsed_milliseconds >= MAXIMUM_WAIT_MILLISECONDS )); then
    printf 'Thermal recovery after %s could not prove 60s continuously nominal within 600s. Let the Mac cool down, then rerun release verification.\n' \
      "$STAGE" >&2
    exit 75
  fi

  previous_milliseconds="$current_milliseconds"
  if [[ "$MODE" == "--live" ]]; then
    /bin/sleep "$SAMPLE_INTERVAL_SECONDS"
  fi
  sample_index=$((sample_index + 1))
  obtain_sample "$sample_index" || exit 1
done
