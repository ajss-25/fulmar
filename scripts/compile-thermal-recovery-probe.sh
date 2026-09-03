#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
[[ "$#" -eq 1 && "$1" == /* && "$1" != *$'\n'* && "$1" != *$'\r'* ]] || {
  print -u2 "usage: compile-thermal-recovery-probe.sh /private/output/path"
  exit 64
}
OUTPUT="$1"
PARENT="${OUTPUT:h}"
[[ -d "$PARENT" && ! -L "$PARENT" && ! -e "$OUTPUT" \
   && "$(/usr/bin/stat -f '%u:%Lp' "$PARENT")" == "$(/usr/bin/id -u):700" ]] || {
  print -u2 "The thermal recovery probe output must be new inside a private owner directory."
  exit 1
}

source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"
MODULE_CACHE="$PARENT/thermal-recovery-module-cache"
SUPERVISOR_OBJECT="$PARENT/thermal-recovery-supervisor.o"
CLANG_BIN="$(xcrun --find clang)"
[[ "$CLANG_BIN" == /* && -x "$CLANG_BIN" ]] || {
  print -u2 "The thermal recovery probe requires Apple's selected clang."
  exit 1
}
/bin/mkdir -m 0700 "$MODULE_CACHE"
env SDKROOT="$SDKROOT" "$CLANG_BIN" \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  -isysroot "$SDKROOT" \
  -c "$PROJECT_DIR/Tools/ThermalRecoveryProbe/supervisor.c" \
  -o "$SUPERVISOR_OBJECT"
env SDKROOT="$SDKROOT" swiftc \
  -swift-version 5 \
  -parse-as-library \
  -warnings-as-errors \
  -sdk "$SDKROOT" \
  -module-cache-path "$MODULE_CACHE" \
  "$PROJECT_DIR/Tools/ThermalRecoveryProbe/main.swift" \
  "$SUPERVISOR_OBJECT" \
  -o "$OUTPUT"
/bin/chmod 0700 "$OUTPUT"
[[ -f "$OUTPUT" && ! -L "$OUTPUT" && -x "$OUTPUT" \
   && "$(/usr/bin/stat -f '%u:%Lp:%l' "$OUTPUT")" == "$(/usr/bin/id -u):700:1" ]] || {
  print -u2 "The compiled thermal recovery probe is not private executable evidence."
  exit 1
}
