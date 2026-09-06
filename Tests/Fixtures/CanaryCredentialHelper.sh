#!/bin/sh
set -eu

# Deliberately isolated credential-provider fixture for the web/RPC canary.
# The production helper has its own release gate; using it here would inspect
# the developer's login Keychain and make a clean-state test machine-dependent.
command_name="${1-}"
subject="${2-}"
printf '%s\t%s\n' "$command_name" "$subject" >> "$HOME/canary-credential-helper.log"

case "$command_name" in
  environment-home)
    printf '%s' "$HOME"
    ;;
  get|get-record)
    exit 3
    ;;
  describe)
    printf '0'
    ;;
  list-records)
    printf '[]'
    ;;
  *)
    exit 4
    ;;
esac
