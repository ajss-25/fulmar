#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"

(( $# == 1 )) || {
  print -u2 "usage: recover-private-install.sh resume|finalize|cancel|retire|reconcile"
  exit 64
}

case "$1" in
  resume) MODE="--resume-interrupted" ;;
  finalize) MODE="--finalize-interrupted" ;;
  cancel) MODE="--cancel-interrupted" ;;
  retire) MODE="--retire-committed" ;;
  reconcile) MODE="--reconcile-records" ;;
  *)
    print -u2 "usage: recover-private-install.sh resume|finalize|cancel|retire|reconcile"
    exit 64
    ;;
esac

# The inspector wrapper owns the authenticated watchdog, global installer lock,
# frozen source/evidence checks, private compiler root, executable proof, and
# final repeated recovery proof. This wrapper only maps a reviewed human verb
# to one exact mutation flag.
exec /bin/zsh -f "$PROJECT_DIR/scripts/inspect-private-install-rollback.sh" "$MODE"
