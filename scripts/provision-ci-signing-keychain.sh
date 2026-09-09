#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
SIGNING_SECRET_FD="${FULMAR_SIGNING_SECRET_FD_V1:-}"
[[ -z "${LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD+x}" ]] || {
  print -u2 "The CI signing password must arrive only through the private watchdog descriptor."
  exit 126
}
[[ "$SIGNING_SECRET_FD" == "196" ]] || {
  print -u2 "CI signing bootstrap requires the authenticated watchdog signing descriptor."
  exit 126
}
(( $# == 1 )) || {
  print -u2 "Usage: provision-ci-signing-keychain.sh </absolute/fulmar-ci.keychain-db|--transport-smoke>"
  exit 64
}

run_without_signing_secret() {
  if [[ "$SIGNING_SECRET_FD" == "196" ]]; then
    "$@" {SIGNING_SECRET_FD}<&-
  else
    "$@"
  fi
}

scratch="$(run_without_signing_secret /usr/bin/mktemp -d /private/tmp/fulmar-ci-keychain-bootstrap.XXXXXX)"
run_without_signing_secret /bin/chmod 0700 "$scratch"
helper="$scratch/provision-ephemeral-keychain"
cleanup() {
  local exit_code="${1:-$?}"
  [[ "$scratch" == /private/tmp/fulmar-ci-keychain-bootstrap.* \
     && -d "$scratch" && ! -L "$scratch" ]] || return 126
  run_without_signing_secret /bin/chmod -R u+rwX "$scratch" 2>/dev/null || true
  run_without_signing_secret /bin/rm -rf -- "$scratch"
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

typeset -a compile_arguments
compile_arguments=(-std=c11 -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations)
if [[ "$1" == "--transport-smoke" ]]; then
  run_without_signing_secret /usr/bin/perl -MPOSIX -e \
    'my $copy = POSIX::dup(196); exit(defined($copy) && $copy >= 0 ? 1 : 0)'
  compile_arguments+=(-DFULMAR_TEST_SECRET_READER)
  run_without_signing_secret /usr/bin/xcrun clang "${compile_arguments[@]}" \
    "$PROJECT_DIR/scripts/provision-ephemeral-keychain-from-fd.c" -o "$helper"
  "$helper"
  exec {SIGNING_SECRET_FD}<&-
  unset FULMAR_SIGNING_SECRET_FD_V1
  SIGNING_SECRET_FD=""
  print "FULMAR_CI_SIGNING_TRANSPORT_OK"
  exit 0
fi

keychain="$1"
[[ "$keychain" == /*/fulmar-ci.keychain-db && "$keychain" != *$'\n'* && "$keychain" != *$'\r'* \
   && ! -e "$keychain" && ! -L "$keychain" ]] || {
  print -u2 "The CI Keychain target must be one absent absolute fulmar-ci.keychain-db path."
  exit 64
}
run_without_signing_secret /usr/bin/xcrun clang "${compile_arguments[@]}" \
  "$PROJECT_DIR/scripts/provision-ephemeral-keychain-from-fd.c" \
  -framework Security -framework CoreFoundation -o "$helper"
"$helper" "$keychain"
[[ -f "$keychain" && ! -L "$keychain" \
   && "$keychain" == "${keychain:A}" \
   && "$(run_without_signing_secret /usr/bin/stat -f '%u:%l' "$keychain")" \
      == "$(run_without_signing_secret /usr/bin/id -u):1" ]] || {
  print -u2 "The CI signing Keychain was not created safely."
  exit 1
}

identity="$(LOCAL_HARNESS_SIGNING_KEYCHAIN="$keychain" \
  /bin/zsh -f "$PROJECT_DIR/scripts/create-local-signing-identity.sh")"
exec {SIGNING_SECRET_FD}<&-
unset FULMAR_SIGNING_SECRET_FD_V1
SIGNING_SECRET_FD=""
[[ "$identity" != *[^A-Fa-f0-9]* && "${#identity}" == 40 ]] || {
  print -u2 "The CI signing identity did not resolve exactly."
  exit 1
}
print -r -- "$identity"
