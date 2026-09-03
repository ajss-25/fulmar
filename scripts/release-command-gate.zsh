#!/bin/zsh -f

# Run one release producer through an audited log sink. Both pipeline members
# must succeed and any warning is fatal. Swift's -warnings-as-errors does not
# cover linker or dsymutil diagnostics; this gate deliberately does.
PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
run_release_command_without_warnings() {
  local label="$1"
  local log_path="$2"
  shift 2
  typeset -a captured_statuses
  local log_fd
  unset log_fd
  local log_identity=""
  local previous_umask="$(umask)"
  local noclobber_was_set=0
  local root_watchdog_state
  typeset -a supervised_command
  [[ -o noclobber ]] && noclobber_was_set=1
  [[ ! -e "$log_path" && ! -L "$log_path" ]] || {
    print -u2 "$label refused a pre-existing or linked release log: $log_path."
    return 1
  }
  root_watchdog_state=0
  fulmar_root_watchdog_state || root_watchdog_state=$?
  if (( root_watchdog_state == 0 )); then
    supervised_command=("$@")
  elif (( root_watchdog_state == 1 )); then
    print -u2 "$label requires one attested root watchdog around the entire release pipeline."
    return 126
  else
    print -u2 "$label inherited an invalid root-watchdog attestation."
    return 1
  fi
  umask 077
  setopt noclobber
  set +e
  exec {log_fd}> "$log_path"
  local open_status=$?
  (( noclobber_was_set == 1 )) || unsetopt noclobber
  umask "$previous_umask"
  set -e
  if (( open_status != 0 )) || [[ -z "${log_fd:-}" ]]; then
    print -u2 "$label could not exclusively create its release log: $log_path."
    return 1
  fi
  log_identity="$(/usr/bin/stat -f '%d:%i:%l:%u' "$log_path" 2>/dev/null)"
  [[ "$log_identity" == *:*:1:$(/usr/bin/id -u) ]] || {
    exec {log_fd}>&-
    print -u2 "$label release log has an unsafe initial identity: $log_path."
    return 1
  }
  set +e
  "${supervised_command[@]}" 2>&1 \
    | "$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node" \
        "$PROJECT_DIR/scripts/bounded-redacted-release-stream.mjs" 67108864 \
    | /usr/bin/tee "/dev/fd/$log_fd" \
    | /usr/bin/awk '{ print $0; if (index(tolower($0), "warning:") > 0) warning_found = 1 } END { if (warning_found) exit 86 }'
  captured_statuses=("${pipestatus[@]}")
  exec {log_fd}>&-
  set -e
  if (( ${#captured_statuses[@]} != 4 \
        || captured_statuses[1] != 0 \
        || captured_statuses[2] != 0 \
        || captured_statuses[3] != 0 )); then
    print -u2 "$label failed; see $log_path."
    return 1
  fi
  if (( captured_statuses[4] == 86 )); then
    print -u2 "$label emitted a release-blocking warning."
    return 1
  fi
  if (( captured_statuses[4] != 0 )); then
    print -u2 "$label live warning scan failed closed."
    return 1
  fi
  [[ -f "$log_path" && ! -L "$log_path" \
     && "$(/usr/bin/stat -f '%d:%i:%l:%u' "$log_path" 2>/dev/null)" == "$log_identity" ]] || {
    print -u2 "$label release log disappeared or changed identity: $log_path."
    return 1
  }
}

if [[ "${ZSH_EVAL_CONTEXT:-}" == "toplevel" ]]; then
  (( $# >= 3 )) || {
    print -u2 "usage: release-command-gate.zsh <label> <log-path> <command> [argument ...]"
    exit 64
  }
  run_release_command_without_warnings "$@"
fi
