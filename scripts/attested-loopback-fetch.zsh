#!/bin/zsh -f

source "${${(%):-%N}:A:h}/supervised-process-group.zsh"

# Fetch one bounded loopback JSON response only while the exact expected PID is
# the sole listener and remains in the attested process group. The destination
# is created once through an already-open descriptor; failed or ambiguous
# attempts leave no stale/partial response for a later parser.
fulmar_fetch_attested_loopback_json() (
  set -euo pipefail
  local listener_pid="$1" group_id="$2" port="$3" endpoint="$4"
  local destination="$5" maximum_seconds="$6" maximum_bytes="$7"
  local response_fd listeners listener_count identity initial_umask
  [[ "$listener_pid" == <-> && "$listener_pid" -gt 1 \
     && "$group_id" == <-> && "$group_id" -gt 1 \
     && "$port" == <-> && "$port" -ge 1024 && "$port" -le 65535 \
     && "$endpoint" == /api/(version|tags) \
     && "$maximum_seconds" == <-> && "$maximum_seconds" -ge 1 && "$maximum_seconds" -le 10 \
     && "$maximum_bytes" == <-> && "$maximum_bytes" -ge 1 && "$maximum_bytes" -le 5242880 \
     && "$destination" == /private/tmp/(localharness-agent-route|fulmar-attested-fetch-test).*/* \
     && "$destination" == "${destination:A}" \
     && ! -e "$destination" && ! -L "$destination" ]] || return 64
  local parent="${destination:h}"
  [[ -d "$parent" && ! -L "$parent" \
     && "$parent" == "${parent:A}" \
     && "$(/usr/bin/stat -f '%u:%Lp' "$parent")" == "$(/usr/bin/id -u):700" ]] || return 1

  attest_exact_listener() {
    listeners="$(/usr/sbin/lsof -nP -a -iTCP@127.0.0.1:"$port" -sTCP:LISTEN -t 2>/dev/null)" || return 1
    listener_count="$(print -r -- "$listeners" | /usr/bin/awk 'NF == 1 { count += 1 } END { print count + 0 }')"
    [[ "$listener_count" == 1 && "$listeners" == "$listener_pid" ]] || return 1
    fulmar_attest_pid_in_process_group "$listener_pid" "$group_id" || return 1
    /bin/kill -0 "$listener_pid" >/dev/null 2>&1
  }

  # This preflight is intentionally before curl: an untrusted process that won
  # the released random-port race receives no probe at all.
  attest_exact_listener || return 1
  initial_umask="$(umask)"
  umask 077
  setopt noclobber
  exec {response_fd}> "$destination" || return 1
  unsetopt noclobber
  umask "$initial_umask"
  identity="$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp' "$destination" 2>/dev/null)"
  [[ "$identity" == *:*:1:$(/usr/bin/id -u):600 ]] || {
    exec {response_fd}>&-
    /bin/rm -f -- "$destination"
    return 1
  }
  cleanup_response() {
    local exit_code="${1:-$?}"
    exec {response_fd}>&- 2>/dev/null || true
    /bin/rm -f -- "$destination"
    return "$exit_code"
  }
  on_signal() {
    local exit_code="$1"
    trap - EXIT HUP INT TERM
    cleanup_response "$exit_code" || true
    exit "$exit_code"
  }
  trap cleanup_response EXIT
  trap 'on_signal 129' HUP
  trap 'on_signal 130' INT
  trap 'on_signal 143' TERM
  /usr/bin/curl -fsS --max-time "$maximum_seconds" --max-filesize "$maximum_bytes" \
    "http://127.0.0.1:$port$endpoint" -o "/dev/fd/$response_fd"
  exec {response_fd}>&-
  [[ -f "$destination" && ! -L "$destination" \
     && "$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp' "$destination" 2>/dev/null)" == "$identity" ]] || return 1
  local size="$(/usr/bin/stat -f '%z' "$destination" 2>/dev/null)"
  [[ "$size" == <-> && "$size" -ge 1 && "$size" -le "$maximum_bytes" ]] || return 1
  attest_exact_listener || return 1
  trap - EXIT HUP INT TERM
)

if [[ "${ZSH_EVAL_CONTEXT:-}" == "toplevel" ]]; then
  (( $# == 7 )) || {
    print -u2 "usage: attested-loopback-fetch.zsh <listener-pid> <pgid> <port> </api/version|/api/tags> <new-output> <seconds> <bytes>"
    exit 64
  }
  fulmar_fetch_attested_loopback_json "$@"
fi
