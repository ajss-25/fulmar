#!/bin/zsh -f

# Attest the one setsid child created by run-with-watchdog.sh. The returned PID
# is also the exact process-group ID and may be retained for bounded fallback
# cleanup if the supervisor itself stops responding.
fulmar_process_inspector() {
  local project_dir="${PROJECT_DIR:-${0:A:h:h}}"
  local node="$project_dir/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
  [[ -x "$node" && ! -L "$node" ]] || return 1
  "$node" "$project_dir/scripts/bounded-process-group-inspector.mjs" "$@"
}

fulmar_attest_supervised_process_group() {
  local supervisor_pid="$1"
  local attempt group_id
  [[ "$supervisor_pid" == <-> && "$supervisor_pid" -gt 1 ]] || return 1
  for ((attempt = 1; attempt <= 40; attempt++)); do
    group_id="$(fulmar_process_inspector child-group "$supervisor_pid" 2>/dev/null)" || group_id=""
    if [[ "$group_id" == <-> && "$group_id" -gt 1 ]]; then
      print -r -- "$group_id"
      return 0
    fi
    /bin/kill -0 "$supervisor_pid" 2>/dev/null || return 1
    /bin/sleep 0.05
  done
  return 1
}

fulmar_process_group_member_count() {
  local group_id="$1"
  fulmar_process_inspector count "$group_id"
}

fulmar_attest_pid_in_process_group() {
  local pid="$1" group_id="$2"
  fulmar_process_inspector pid-in-group "$pid" "$group_id" >/dev/null
}

fulmar_attest_sole_inherited_child() {
  local supervisor_pid="$1" group_id="$2"
  local attempt child_pid
  for ((attempt = 1; attempt <= 40; attempt++)); do
    child_pid="$(fulmar_process_inspector sole-child "$supervisor_pid" "$group_id" 2>/dev/null)" || child_pid=""
    if [[ "$child_pid" == <-> && "$child_pid" -gt 1 ]]; then
      print -r -- "$child_pid"
      return 0
    fi
    /bin/kill -0 "$supervisor_pid" 2>/dev/null || return 1
    /bin/sleep 0.05
  done
  return 1
}

fulmar_stop_inherited_process() {
  local process_pid="$1" label="$2" attempt
  [[ "$process_pid" == <-> && "$process_pid" -gt 1 \
     && "${#label}" -ge 1 && "${#label}" -le 128 ]] || return 1
  /bin/kill -TERM "$process_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 60; attempt++)); do
    /bin/kill -0 "$process_pid" 2>/dev/null || return 0
    /bin/sleep 0.05
  done
  /bin/kill -KILL "$process_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 40; attempt++)); do
    /bin/kill -0 "$process_pid" 2>/dev/null || return 0
    /bin/sleep 0.05
  done
  print -u2 "$label process did not stop after bounded TERM/KILL cleanup."
  return 1
}

fulmar_stop_unattested_supervisor() {
  local supervisor_pid="$1"
  local attempt
  [[ "$supervisor_pid" == <-> && "$supervisor_pid" -gt 1 ]] || return 1
  /bin/kill -TERM "$supervisor_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 100; attempt++)); do
    if ! /bin/kill -0 "$supervisor_pid" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.05
  done
  /bin/kill -KILL "$supervisor_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 40; attempt++)); do
    /bin/kill -0 "$supervisor_pid" 2>/dev/null || return 0
    /bin/sleep 0.05
  done
  return 1
}

fulmar_stop_supervised_process_group() {
  local supervisor_pid="$1" group_id="$2" label="$3"
  local attempt members
  [[ "$supervisor_pid" == <-> && "$supervisor_pid" -gt 1 \
     && "$group_id" == <-> && "$group_id" -gt 1 \
     && "${#label}" -ge 1 && "${#label}" -le 128 ]] || return 1

  # The supervisor owns the first TERM and exact-group drain. A direct exact
  # PGID TERM/KILL is used only as a bounded emergency fallback.
  /bin/kill -TERM "$supervisor_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 80; attempt++)); do
    members="$(fulmar_process_group_member_count "$group_id")" || return 1
    if ! /bin/kill -0 "$supervisor_pid" 2>/dev/null && [[ "$members" == "0" ]]; then
      return 0
    fi
    /bin/sleep 0.05
  done

  /bin/kill -TERM -- "-$group_id" 2>/dev/null || true
  for ((attempt = 1; attempt <= 20; attempt++)); do
    members="$(fulmar_process_group_member_count "$group_id")" || return 1
    [[ "$members" == "0" ]] && break
    /bin/sleep 0.05
  done
  members="$(fulmar_process_group_member_count "$group_id")" || return 1
  if [[ "$members" != "0" ]]; then
    /bin/kill -KILL -- "-$group_id" 2>/dev/null || true
  fi
  /bin/kill -KILL "$supervisor_pid" 2>/dev/null || true
  for ((attempt = 1; attempt <= 40; attempt++)); do
    members="$(fulmar_process_group_member_count "$group_id")" || return 1
    if [[ "$members" == "0" ]] && ! /bin/kill -0 "$supervisor_pid" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.05
  done
  print -u2 "$label exact process group did not drain after bounded TERM/KILL cleanup."
  return 1
}
