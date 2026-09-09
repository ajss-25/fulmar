#!/bin/zsh -f
set -euo pipefail

EXPECTED_MINIMUM="${1-}"
shift || true

[[ "$EXPECTED_MINIMUM" =~ '^[0-9]+\.[0-9]+$' && "$#" -ge 1 ]] || {
  echo "usage: verify-swiftpm-deployment-target.sh <minimum-macos> <Mach-O> [...]" >&2
  exit 64
}

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-swiftpm-deployment.XXXXXX)"
cleanup() {
  local exit_code="${1:-$?}"
  case "$TEMP_ROOT" in
    /private/tmp/fulmar-swiftpm-deployment.*) /bin/rm -rf -- "$TEMP_ROOT" ;;
    *) echo "Refusing to remove an invalid deployment-verifier temporary directory." >&2 ;;
  esac
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

index=0
for executable in "$@"; do
  index=$((index + 1))
  [[ "$executable" == /* && "$executable" != *$'\n'* && "$executable" != *$'\r'* ]] || {
    echo "SwiftPM deployment target input must be one absolute single-line path." >&2
    exit 1
  }
  [[ -f "$executable" && ! -L "$executable" && "${executable:A}" == "$executable" ]] || {
    echo "SwiftPM deployment target input is not an unlinked canonical regular file: $executable" >&2
    exit 1
  }
  [[ "$(/usr/bin/stat -f '%HT:%l' "$executable")" == "Regular File:1" ]] || {
    echo "SwiftPM deployment target input has an unsafe type or link count: $executable" >&2
    exit 1
  }

  file_description="$(/usr/bin/file -b "$executable")"
  [[ "$file_description" == "Mach-O 64-bit executable arm64" \
     || "$file_description" == "Mach-O 64-bit bundle arm64" ]] || {
    echo "SwiftPM output is not one supported thin arm64 Mach-O executable or test bundle: $executable ($file_description)" >&2
    exit 1
  }

  stdout="$TEMP_ROOT/vtool-$index.out"
  stderr="$TEMP_ROOT/vtool-$index.err"
  /usr/bin/vtool -show-build "$executable" >"$stdout" 2>"$stderr" || {
    echo "vtool could not inspect SwiftPM output: $executable" >&2
    exit 1
  }
  [[ ! -s "$stderr" ]] || {
    echo "vtool emitted an unexpected warning while inspecting SwiftPM output: $executable" >&2
    /bin/cat "$stderr" >&2
    exit 1
  }

  command_count="$(/usr/bin/grep -Ec '^[[:space:]]*cmd LC_BUILD_VERSION$' "$stdout" || true)"
  platform_count="$(/usr/bin/grep -Ec '^[[:space:]]*platform MACOS$' "$stdout" || true)"
  minimum_count="$(/usr/bin/grep -Ec "^[[:space:]]*minos ${EXPECTED_MINIMUM//./\\.}$" "$stdout" || true)"
  [[ "$command_count" == 1 && "$platform_count" == 1 && "$minimum_count" == 1 ]] || {
    found_minimum="$(/usr/bin/sed -nE 's/^[[:space:]]*minos[[:space:]]+([^[:space:]]+).*$/\1/p' "$stdout" | /usr/bin/paste -sd, -)"
    [[ -n "$found_minimum" ]] || found_minimum="missing"
    echo "SwiftPM output $executable declares macOS minimum $found_minimum; expected exactly $EXPECTED_MINIMUM with one macOS LC_BUILD_VERSION." >&2
    exit 1
  }
done

echo "Verified SwiftPM deployment target $EXPECTED_MINIMUM in $# product/test Mach-O binaries."
