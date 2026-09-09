#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/release-lock.zsh"
IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
APP_NAME="$(/usr/bin/plutil -extract applicationBundleName raw -o - "$IDENTITY")"
CANDIDATE="/private/tmp/LocalHarnessBuild/$APP_NAME"
INSTALLED="/Applications/$APP_NAME"
TARGET="${1:-$CANDIDATE}"
[[ "$TARGET" == /* ]] || { print -u2 "Frozen-candidate target must be an absolute path."; exit 64; }
[[ "$TARGET" == "$CANDIDATE" || "$TARGET" == "$INSTALLED" ]] || {
  print -u2 "Frozen-candidate verification accepts only the current build candidate or exact installed copy."
  exit 64
}

# Never canonicalize one of the fixed app names before rejecting links. zsh's
# :A expansion resolves a linked leaf and would otherwise erase the evidence
# that the caller supplied a substituted path.
for fixed_parent in "${CANDIDATE:h:h}" "${INSTALLED:h}"; do
  [[ -d "$fixed_parent" && ! -L "$fixed_parent" \
     && "${fixed_parent:A}" == "$fixed_parent" ]] || {
    print -u2 "Frozen-candidate verification rejected a linked or non-canonical parent."
    exit 1
  }
done
if [[ "$TARGET" == "$INSTALLED" ]]; then
  [[ -d "$INSTALLED" && ! -L "$INSTALLED" && "${INSTALLED:A}" == "$INSTALLED" ]] || {
    print -u2 "Frozen-candidate verification rejected the installed app path."
    exit 1
  }
fi
CANDIDATE_PRESENT=0
if [[ -e "$CANDIDATE" || -L "$CANDIDATE" ]]; then
  [[ -d "${CANDIDATE:h}" && ! -L "${CANDIDATE:h}" \
     && "${CANDIDATE:h:A}" == "${CANDIDATE:h}" \
     && -d "$CANDIDATE" && ! -L "$CANDIDATE" && "${CANDIDATE:A}" == "$CANDIDATE" ]] || {
    print -u2 "Frozen-candidate verification rejected the build candidate path."
    exit 1
  }
  CANDIDATE_PRESENT=1
elif [[ -e "${CANDIDATE:h}" || -L "${CANDIDATE:h}" ]]; then
  [[ -d "${CANDIDATE:h}" && ! -L "${CANDIDATE:h}" \
     && "${CANDIDATE:h:A}" == "${CANDIDATE:h}" ]] || {
    print -u2 "Frozen-candidate verification rejected the optional candidate parent."
    exit 1
  }
fi

# The installed bundle remains independently verifiable after an operator
# deliberately removes the disposable build candidate: the signed archive is
# the canonical byte source in that case. A linked or otherwise present-but-
# unsafe candidate never activates this fallback.
REFERENCE="$CANDIDATE"
if (( CANDIDATE_PRESENT == 0 )); then
  [[ "$TARGET" == "$INSTALLED" ]] || {
    print -u2 "Frozen-candidate verification is missing the exact build candidate."
    exit 1
  }
  REFERENCE="$INSTALLED"
fi

TEMP_ROOT=""
TEMP_ROOT_IDENTITY=""
cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$TEMP_ROOT" ]]; then
    [[ "$TEMP_ROOT" == /private/tmp/fulmar-frozen-candidate.* \
       && -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" \
       && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT" 2>/dev/null)" == "$TEMP_ROOT_IDENTITY" ]] || {
      print -u2 "Refusing to remove a changed frozen-candidate temporary root."
      return 126
    }
    /bin/rm -rf -- "$TEMP_ROOT" || return 126
    [[ ! -e "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]] || return 126
    TEMP_ROOT=""
  fi
  fulmar_release_release_lock || return 126
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
fulmar_acquire_release_lock "Fulmar frozen-candidate verification"

ARCHIVE="$PROJECT_DIR/build/$(/usr/bin/plutil -extract releaseArchiveName raw -o - "$IDENTITY")"
SYMBOLS="$PROJECT_DIR/build/$(/usr/bin/plutil -extract symbolsArchiveName raw -o - "$IDENTITY")"
MANIFEST="$PROJECT_DIR/build/release-manifest.json"
SOURCE_INPUTS="$PROJECT_DIR/build/source-build-inputs.json"
STATIC_SECURITY="$PROJECT_DIR/build/static-security-summary.json"
TOOLCHAIN="$PROJECT_DIR/build/toolchain-inventory.json"
VENDOR_INVENTORY="$PROJECT_DIR/VendorRuntime.inventory.json"
UNSIGNED_RUNTIME="$PROJECT_DIR/build/runtime-unsigned-inventory.json"
RUNTIME_SIGNABLES="$PROJECT_DIR/build/runtime-signables.json"
RUNTIME_INVENTORY="$PROJECT_DIR/build/runtime-release-inventory.json"

for required in "$IDENTITY" "$NODE" "$REFERENCE" "$TARGET" "$ARCHIVE" "$SYMBOLS" \
  "$MANIFEST" "$SOURCE_INPUTS" "$STATIC_SECURITY" "$TOOLCHAIN" "$VENDOR_INVENTORY" \
  "$UNSIGNED_RUNTIME" "$RUNTIME_SIGNABLES" "$RUNTIME_INVENTORY"; do
  [[ -e "$required" && ! -L "$required" ]] || {
    print -u2 "Frozen-candidate verification is missing an exact unlinked input: $required"
    exit 1
  }
done
EXPECTED_NODE_SHA="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$IDENTITY")"
[[ "$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')" == "$EXPECTED_NODE_SHA" ]] || {
  print -u2 "Frozen-candidate verification rejected its bootstrap runtime."
  exit 1
}

TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-frozen-candidate.XXXXXX)"
/bin/chmod 0700 "$TEMP_ROOT"
TEMP_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT")" || exit 126
[[ "$TEMP_ROOT_IDENTITY" == "$(/usr/bin/stat -f '%d:%i:%u:Directory:700' "$TEMP_ROOT")" ]] || exit 126
"$NODE" "$PROJECT_DIR/scripts/runtime-inventory.mjs" \
  verify "$PROJECT_DIR/VendorRuntime" "$VENDOR_INVENTORY" VendorRuntime
"$NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" verify "$TOOLCHAIN"
"$NODE" "$PROJECT_DIR/scripts/source-build-input-inventory.mjs" \
  verify "$PROJECT_DIR" "$SOURCE_INPUTS"
"$NODE" "$PROJECT_DIR/scripts/verify-static-security-summary.mjs" \
  "$STATIC_SECURITY" "$SOURCE_INPUTS" "$PROJECT_DIR/Config/SemgrepRules.json"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/candidate-info.json" "$REFERENCE/Contents/Info.plist"
"$NODE" "$PROJECT_DIR/scripts/verify-release-manifest.mjs" \
  "$MANIFEST" "$ARCHIVE" "$TEMP_ROOT/candidate-info.json" "$SYMBOLS" \
  "$VENDOR_INVENTORY" "$UNSIGNED_RUNTIME" "$RUNTIME_SIGNABLES" "$RUNTIME_INVENTORY" \
  "$SOURCE_INPUTS" "$STATIC_SECURITY" "$TOOLCHAIN"
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$ARCHIVE" "$REFERENCE"
/bin/mkdir -m 0700 "$TEMP_ROOT/extracted"
/usr/bin/ditto -x -k "$ARCHIVE" "$TEMP_ROOT/extracted"
EXTRACTED="$TEMP_ROOT/extracted/$APP_NAME"
[[ -d "$EXTRACTED" && ! -L "$EXTRACTED" \
   && "$(/usr/bin/find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] || {
  print -u2 "Frozen candidate archive did not extract to exactly one reviewed bundle."
  exit 1
}
"$NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$REFERENCE" "$EXTRACTED"
/usr/bin/codesign --verify --deep --strict "$REFERENCE"

if [[ "$TARGET" != "$REFERENCE" ]]; then
  "$NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$REFERENCE" "$TARGET"
  /usr/bin/codesign --verify --deep --strict "$INSTALLED"
fi

VERSION="$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$TARGET/Contents/Info.plist")"
BUILD="$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$TARGET/Contents/Info.plist")"
print "Frozen candidate preflight passed for Fulmar $VERSION ($BUILD): ${TARGET:t}."
