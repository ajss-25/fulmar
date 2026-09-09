#!/bin/zsh -f

# Return 0 only inside the exact process group created by run-with-watchdog.
# Return 1 when no root marker exists, and 2 for a partial, malformed, stale,
# or wrong-process-group marker. Callers must fail closed on 2.
# Capture the helper's own location while zsh is sourcing this file.  `%N`
# inside a later function call resolves to the caller, so deriving this path in
# fulmar_root_watchdog_state would let a hostile caller PROJECT_DIR redirect the
# attestation binaries.  Re-sourcing this helper deterministically overwrites
# any inherited/environment value with the reviewed source location.
typeset -g FULMAR_WATCHDOG_HELPER_PROJECT_DIR_V1="${${(%):-%N}:A:h:h}"

fulmar_root_watchdog_state() {
  local root_pgid="${FULMAR_ROOT_WATCHDOG_PGID_V1:-}"
  local root_pid="${FULMAR_ROOT_WATCHDOG_PID_V1:-}"
  local depth="${FULMAR_INTERNAL_WATCHDOG_DEPTH:-}"
  local capability="${FULMAR_ROOT_WATCHDOG_CAPABILITY_V1:-}"
  local nonce="${FULMAR_ROOT_WATCHDOG_NONCE_V1:-}"
  local capability_fd="${FULMAR_ROOT_WATCHDOG_FD_V1:-}"
  local project_dir="$FULMAR_WATCHDOG_HELPER_PROJECT_DIR_V1"
  local node="$project_dir/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
  local attestation_path="/usr/bin:/bin:/usr/sbin:/sbin"
  if [[ -z "$root_pgid" && -z "$root_pid" && -z "$depth" \
     && -z "$capability" && -z "$nonce" && -z "$capability_fd" ]]; then
    return 1
  fi
  [[ "$root_pgid" == <-> && "$root_pgid" -gt 1 \
     && "$root_pid" == <-> && "$root_pid" -gt 1 \
     && "$depth" == <-> && "$depth" -ge 1 && "$depth" -le 8 \
     && "${#nonce}" == 64 && "$nonce" != *[^a-f0-9]* \
     && "$capability_fd" == 198 \
     && "$capability" == "/private/tmp/fulmar-watchdog-capability.$root_pid.$nonce" ]] || return 2
  [[ -x "$node" && ! -L "$node" ]] || return 2
  /usr/bin/env -i PATH="$attestation_path" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    /usr/bin/perl "$project_dir/scripts/attest-watchdog-capability-fd.pl" \
    "$capability_fd" "$nonce" "$root_pid" "$root_pgid" || return 2
  /usr/bin/env -i PATH="$attestation_path" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    "$node" "$project_dir/scripts/bounded-process-group-inspector.mjs" \
    root-attest "$root_pid" "$root_pgid" "$capability" "$nonce" >/dev/null 2>&1 || return 2
  return 0
}

fulmar_require_root_watchdog_or_absent() {
  local state=0
  fulmar_root_watchdog_state || state=$?
  (( state != 2 )) || {
    print -u2 "The inherited Fulmar watchdog attestation is invalid."
    return 1
  }
  return "$state"
}

fulmar_append_root_watchdog_environment() {
  local array_name="$1"
  fulmar_root_watchdog_state || return 1
  eval "$array_name+=(\
    \"FULMAR_ROOT_WATCHDOG_PGID_V1=$FULMAR_ROOT_WATCHDOG_PGID_V1\" \
    \"FULMAR_ROOT_WATCHDOG_PID_V1=$FULMAR_ROOT_WATCHDOG_PID_V1\" \
    \"FULMAR_INTERNAL_WATCHDOG_DEPTH=$FULMAR_INTERNAL_WATCHDOG_DEPTH\" \
    \"FULMAR_ROOT_WATCHDOG_CAPABILITY_V1=$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1\" \
    \"FULMAR_ROOT_WATCHDOG_NONCE_V1=$FULMAR_ROOT_WATCHDOG_NONCE_V1\" \
    \"FULMAR_ROOT_WATCHDOG_FD_V1=$FULMAR_ROOT_WATCHDOG_FD_V1\" \
  )"
}
