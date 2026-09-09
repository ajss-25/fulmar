#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/release-lock.zsh"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
INVENTORY_NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
MAXIMUM_STATUS_CYCLES=50
STATUS_TEMP_ROOT=""

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 4294967296 --rss-grace-seconds 5 \
    --emergency-rss-bytes 6442450944 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "Fulmar status-item qualification" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The status-item gate inherited an invalid root-watchdog attestation."
  exit 126
fi

cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$STATUS_TEMP_ROOT" && -d "$STATUS_TEMP_ROOT" ]]; then
    /bin/rm -rf -- "$STATUS_TEMP_ROOT"
  fi
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

COMPILE_ONLY=0
if [[ "$#" -eq 1 && "$1" == "--compile-only" ]]; then
  COMPILE_ONLY=1
elif [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  echo "Usage: /bin/zsh -f scripts/verify-status-item-live.sh --compile-only | /exact/path/Fulmar.app [cycles|--headless-handoff|--physical-background-handoff|--normal-actions]" >&2
  exit 64
elif [[ "$#" -eq 2 && "$2" != "--headless-handoff" && "$2" != "--physical-background-handoff" && "$2" != "--normal-actions" \
        && ( -z "$2" || "$2" == *[!0-9]* ) ]]; then
  echo "Usage: /bin/zsh -f scripts/verify-status-item-live.sh --compile-only | /exact/path/Fulmar.app [cycles|--headless-handoff|--physical-background-handoff|--normal-actions]" >&2
  exit 64
fi
if [[ "$#" -eq 2 && "$2" == <-> \
   && ( "$2" -lt 1 || "$2" -gt "$MAXIMUM_STATUS_CYCLES" ) ]]; then
  echo "Status-item cycle count must be between 1 and $MAXIMUM_STATUS_CYCLES." >&2
  exit 64
fi

if (( COMPILE_ONLY == 0 )); then
  APP_PATH="${1:A}"
  if [[ ! -d "$APP_PATH" || "$APP_PATH" != *.app ]]; then
    echo "Expected an exact path to an existing .app bundle, got: $1" >&2
    exit 64
  fi
fi

verify_current_candidate() {
  local candidate="$1"
  local app_name="$(/usr/bin/plutil -extract applicationBundleName raw -o - "$RELEASE_IDENTITY")"
  local archive_name="$(/usr/bin/plutil -extract releaseArchiveName raw -o - "$RELEASE_IDENTITY")"
  local symbols_name="$(/usr/bin/plutil -extract symbolsArchiveName raw -o - "$RELEASE_IDENTITY")"
  local archive="$PROJECT_DIR/build/$archive_name"
  local symbols="$PROJECT_DIR/build/$symbols_name"
  local manifest="$PROJECT_DIR/build/release-manifest.json"
  local source_inputs="$PROJECT_DIR/build/source-build-inputs.json"
  local static_security="$PROJECT_DIR/build/static-security-summary.json"
  local expected_node_sha="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
  local actual_node_sha="$(/usr/bin/shasum -a 256 "$INVENTORY_NODE" | /usr/bin/awk '{print $1}')"
  [[ "$actual_node_sha" == "$expected_node_sha" ]] || {
    print -u2 "The status-item gate's pinned Node verifier does not match ReleaseIdentity.json."
    return 1
  }
  for required in \
    "$archive" "$symbols" "$manifest" "$PROJECT_DIR/VendorRuntime.inventory.json" \
    "$PROJECT_DIR/build/runtime-unsigned-inventory.json" \
    "$PROJECT_DIR/build/runtime-signables.json" \
    "$PROJECT_DIR/build/runtime-release-inventory.json" \
    "$source_inputs" "$static_security" "$PROJECT_DIR/build/toolchain-inventory.json"; do
    [[ -f "$required" && -s "$required" && ! -L "$required" ]] || {
      print -u2 "The status-item gate is missing a frozen-candidate release input: $required"
      return 1
    }
  done
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/runtime-inventory.mjs" \
    verify "$PROJECT_DIR/VendorRuntime" "$PROJECT_DIR/VendorRuntime.inventory.json" VendorRuntime
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" \
    verify "$PROJECT_DIR/build/toolchain-inventory.json"
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/source-build-input-inventory.mjs" \
    verify "$PROJECT_DIR" "$source_inputs"
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-static-security-summary.mjs" \
    "$static_security" "$source_inputs" "$PROJECT_DIR/Config/SemgrepRules.json"
  /usr/bin/plutil -convert json -o "$STATUS_TEMP_ROOT/candidate-info.json" \
    "$candidate/Contents/Info.plist"
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-manifest.mjs" \
    "$manifest" "$archive" "$STATUS_TEMP_ROOT/candidate-info.json" "$symbols" \
    "$PROJECT_DIR/VendorRuntime.inventory.json" \
    "$PROJECT_DIR/build/runtime-unsigned-inventory.json" \
    "$PROJECT_DIR/build/runtime-signables.json" \
    "$PROJECT_DIR/build/runtime-release-inventory.json" \
    "$source_inputs" "$static_security" "$PROJECT_DIR/build/toolchain-inventory.json"
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$archive" "$candidate"
  /bin/mkdir -p "$STATUS_TEMP_ROOT/extracted"
  /usr/bin/ditto -x -k "$archive" "$STATUS_TEMP_ROOT/extracted"
  local extracted="$STATUS_TEMP_ROOT/extracted/$app_name"
  [[ -d "$extracted" ]] || {
    print -u2 "The current release archive did not extract to the reviewed application name."
    return 1
  }
  "$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$candidate" "$extracted"
  /usr/bin/codesign --verify --deep --strict "$candidate"
}

verify_exact_status_target() {
  STATUS_TEMP_ROOT="$(/usr/bin/mktemp -d "${TMPDIR%/}/fulmar-status-target.XXXXXX")"
  /bin/chmod 700 "$STATUS_TEMP_ROOT"
  local app_name="$(/usr/bin/plutil -extract applicationBundleName raw -o - "$RELEASE_IDENTITY")"
  local candidate="/private/tmp/LocalHarnessBuild/$app_name"
  local installed="/Applications/$app_name"
  candidate="${candidate:A}"
  installed="${installed:A}"
  if [[ "$APP_PATH" != "$candidate" && "$APP_PATH" != "$installed" ]]; then
    print -u2 "The live status-item gate accepts only the manifest-bound candidate or its exact installed copy. Got: $APP_PATH"
    return 1
  fi
  [[ -d "$candidate" && ! -L "$candidate" ]] || {
    print -u2 "The exact current candidate is missing; refusing to infer status evidence from a stale installed app."
    return 1
  }
  verify_current_candidate "$candidate"
  if [[ "$APP_PATH" == "$installed" ]]; then
    [[ -d "$installed" && ! -L "$installed" ]] || {
      print -u2 "The exact installed Fulmar application is missing."
      return 1
    }
    "$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$candidate" "$installed"
    /usr/bin/codesign --verify --deep --strict "$installed"
  fi
  local version="$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$APP_PATH/Contents/Info.plist")"
  local build="$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$APP_PATH/Contents/Info.plist")"
  print "Status-item target is bound to the current frozen candidate: Fulmar $version ($build)."
}

fulmar_acquire_release_lock "Fulmar status-item qualification"
if (( COMPILE_ONLY == 0 )); then
  verify_exact_status_target
else
  STATUS_TEMP_ROOT="$(/usr/bin/mktemp -d "${TMPDIR%/}/fulmar-status-compile.XXXXXX")"
  /bin/chmod 700 "$STATUS_TEMP_ROOT"
fi

source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"

BUILD_DIR="$STATUS_TEMP_ROOT/acceptance-build"
MODULE_CACHE="$STATUS_TEMP_ROOT/module-cache"
EXECUTABLE="$BUILD_DIR/fulmar-status-item-acceptance"
mkdir -p "$BUILD_DIR" "$MODULE_CACHE"

env SDKROOT="$SDKROOT" swiftc \
  -swift-version 5 \
  -warnings-as-errors \
  -sdk "$SDKROOT" \
  -module-cache-path "$MODULE_CACHE" \
  -framework AppKit \
  -framework ApplicationServices \
  -framework CoreGraphics \
  "$PROJECT_DIR/Sources/LocalHarness/StatusItemAcceptanceSupport.swift" \
  "$PROJECT_DIR/Sources/LocalHarness/StatusItemVisibilityGeometry.swift" \
  "$PROJECT_DIR/Tools/StatusItemAcceptance/main.swift" \
  -o "$EXECUTABLE"

if (( COMPILE_ONLY == 1 )); then
  echo "PASS: the status-item acceptance gate compiled with warnings treated as errors."
  exit 0
fi

# The helper was compiled from current source with the recorded compiler while
# the candidate lock was held. Recheck all three mutable inputs immediately
# before launch so a concurrent source/toolchain/runtime change cannot inherit
# evidence from the earlier candidate attestation.
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/runtime-inventory.mjs" \
  verify "$PROJECT_DIR/VendorRuntime" "$PROJECT_DIR/VendorRuntime.inventory.json" VendorRuntime
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" \
  verify "$PROJECT_DIR/build/toolchain-inventory.json"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/source-build-input-inventory.mjs" \
  verify "$PROJECT_DIR" "$PROJECT_DIR/build/source-build-inputs.json"

if [[ "$#" -eq 1 ]]; then
  "$EXECUTABLE" "$APP_PATH" 3
  exit $?
fi
"$EXECUTABLE" "$APP_PATH" "$2"
