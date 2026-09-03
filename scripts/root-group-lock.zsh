#!/bin/zsh -f

source "${${(%):-%N}:A:h}/watchdog-root.zsh"

# Acquire a lock bound to the authenticated outer watchdog, not an inner shell.
# The owner file deliberately survives every inner cleanup. A later contender
# may reclaim it only after both the recorded root PID is dead and its exact
# PGID is empty, so lock release can never precede outer-supervisor drain.
fulmar_acquire_root_group_lock() {
  local lock_dir="$1" label="$2" maximum_attempts="${3:-600}"
  local owner_file="$lock_dir/owner.pid"
  local helper_dir="${${(%):-%N}:A:h}"
  local helper_project_dir="${helper_dir:h}"
  local inspector="$helper_project_dir/scripts/bounded-process-group-inspector.mjs"
  local node="$helper_project_dir/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
  local attempts=0 member_count existing owner_identity owner_size owner_identity_after owner_size_after
  typeset -a fields
  fulmar_root_watchdog_state || {
    print -u2 "$label requires an authenticated root watchdog."
    return 126
  }
  [[ "$lock_dir" == /private/tmp/*.lock && "$maximum_attempts" == <-> \
     && "$maximum_attempts" -ge 1 && "$maximum_attempts" -le 3600 ]] || return 64
  while true; do
    if /bin/mkdir -m 0700 "$lock_dir" 2>/dev/null; then
      [[ -d "$lock_dir" && ! -L "$lock_dir" \
         && "$(/usr/bin/stat -f '%u:%Lp' "$lock_dir")" == "$(/usr/bin/id -u):700" ]] || {
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      setopt localoptions noclobber
      umask 077
      print -r -- "$FULMAR_ROOT_WATCHDOG_PID_V1
$FULMAR_ROOT_WATCHDOG_PGID_V1
$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1
$FULMAR_ROOT_WATCHDOG_NONCE_V1" > "$owner_file" || {
        /bin/rm -f -- "$owner_file" 2>/dev/null || true
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      /bin/chmod 0600 "$owner_file" || {
        /bin/rm -f -- "$owner_file" 2>/dev/null || true
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      owner_identity="$(/usr/bin/stat -f '%u:%Lp:%l' "$owner_file" 2>/dev/null)" || {
        /bin/rm -f -- "$owner_file" 2>/dev/null || true
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      owner_size="$(/usr/bin/stat -f '%z' "$owner_file" 2>/dev/null)" || {
        /bin/rm -f -- "$owner_file" 2>/dev/null || true
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      [[ "$owner_identity" == "$(/usr/bin/id -u):600:1" \
         && "$owner_size" == <-> && "$owner_size" -ge 1 && "$owner_size" -le 1024 ]] || {
        /bin/rm -f -- "$owner_file" 2>/dev/null || true
        /bin/rmdir "$lock_dir" 2>/dev/null || true
        return 1
      }
      return 0
    fi
    (( attempts += 1 ))
    (( attempts <= maximum_attempts )) || {
      print -u2 "$label timed out waiting for its root-group lock."
      return 1
    }
    owner_identity="$(/usr/bin/stat -f '%u:%Lp:%l' "$owner_file" 2>/dev/null || true)"
    owner_size="$(/usr/bin/stat -f '%z' "$owner_file" 2>/dev/null || true)"
    if [[ -f "$owner_file" && ! -L "$owner_file" \
       && "$owner_identity" == "$(/usr/bin/id -u):600:1" \
       && "$owner_size" == <-> && "$owner_size" -ge 1 && "$owner_size" -le 1024 ]]; then
      existing="$(<"$owner_file")"
      owner_identity_after="$(/usr/bin/stat -f '%u:%Lp:%l' "$owner_file" 2>/dev/null || true)"
      owner_size_after="$(/usr/bin/stat -f '%z' "$owner_file" 2>/dev/null || true)"
      [[ "$owner_identity_after" == "$owner_identity" && "$owner_size_after" == "$owner_size" ]] || return 1
      fields=("${(f)existing}")
      if (( ${#fields[@]} == 3 )) \
         && [[ "${fields[1]}" == "FULMAR_LOCK_SUCCESSOR_V1" \
            && "${fields[2]}" == <-> && "${fields[2]}" -gt 1 \
            && "${#fields[3]}" == 64 && "${fields[3]}" != *[^a-f0-9]* ]]; then
        if ! /bin/kill -0 "${fields[2]}" 2>/dev/null; then
          /bin/rm -f -- "$owner_file"
          /bin/rmdir "$lock_dir" 2>/dev/null || return 1
          continue
        fi
        /bin/sleep 0.1
        continue
      fi
      if (( ${#fields[@]} == 4 )) \
         && [[ "${fields[1]}" == "$FULMAR_ROOT_WATCHDOG_PID_V1" \
            && "${fields[2]}" == "$FULMAR_ROOT_WATCHDOG_PGID_V1" \
            && "${fields[3]}" == "$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1" \
            && "${fields[4]}" == "$FULMAR_ROOT_WATCHDOG_NONCE_V1" ]]; then
        return 0
      fi
      if (( ${#fields[@]} == 4 )) && [[ "${fields[1]}" == <-> && "${fields[2]}" == <-> ]]; then
        [[ -x "$node" && ! -L "$node" && -f "$inspector" && ! -L "$inspector" ]] || return 1
        member_count="$("$node" "$inspector" count "${fields[2]}" 2>/dev/null)" || return 1
        if [[ "$member_count" == 0 ]] && ! /bin/kill -0 "${fields[1]}" 2>/dev/null; then
          /bin/rm -f -- "$owner_file"
          /bin/rmdir "$lock_dir" 2>/dev/null || return 1
          continue
        fi
      fi
    elif (( attempts > 20 )); then
      print -u2 "$label found an unsafe or ownerless root-group lock."
      return 1
    fi
    /bin/sleep 0.1
  done
}

fulmar_release_root_group_lock() {
  # Intentionally retained until the next contender proves root-death + PGID
  # emptiness. Inner scripts are never authorized to create a release window.
  return 0
}
