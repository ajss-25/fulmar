#!/bin/zsh -f

source "${${(%):-%N}:A:h}/root-group-lock.zsh"

typeset -g FULMAR_RELEASE_LOCK_DIR="/private/tmp/LocalHarnessBuild.lock"
typeset -gi FULMAR_RELEASE_LOCK_ACQUIRED=0

fulmar_acquire_release_lock() {
  local label="${1:-release operation}"
  (( FULMAR_RELEASE_LOCK_ACQUIRED == 0 )) || {
    print -u2 "$label attempted to acquire the Fulmar release lock twice."
    return 1
  }
  fulmar_acquire_root_group_lock "$FULMAR_RELEASE_LOCK_DIR" "$label" 600 || return
  FULMAR_RELEASE_LOCK_ACQUIRED=1
}

fulmar_release_release_lock() {
  (( FULMAR_RELEASE_LOCK_ACQUIRED == 1 )) || return 0
  fulmar_release_root_group_lock "$FULMAR_RELEASE_LOCK_DIR"
  FULMAR_RELEASE_LOCK_ACQUIRED=0
}
