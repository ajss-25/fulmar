#!/bin/zsh -f
set -euo pipefail

TARGET="${1:?signed target is required}"
shift

set +e
OUTPUT="$(codesign --verify "$@" "$TARGET" 2>&1)"
STATUS=$?
set -e
if (( STATUS == 0 )); then
  exit 0
fi

# A private self-signed identity has no Apple trust chain. `codesign` performs
# structural/resource/CMS validation before returning this one trust-policy
# error. Admit only that exact two-line result, and only when the caller has
# explicitly selected private-release verification. Fixed identifiers and the
# common certificate family are checked separately by verify-stable-signing.
if [[ "${LOCAL_HARNESS_ALLOW_PRIVATE_ROOT:-0}" == "1" ]]; then
  REMAINDER="$(print -r -- "$OUTPUT" \
    | sed -E '/: CSSMERR_TP_NOT_TRUSTED$/d; /^In architecture: (arm64|x86_64)$/d; /^[[:space:]]*$/d')"
  if [[ -z "$REMAINDER" && "$OUTPUT" == *"CSSMERR_TP_NOT_TRUSTED"* ]]; then
    exit 0
  fi
fi

print -u2 -r -- "$OUTPUT"
exit "$STATUS"
