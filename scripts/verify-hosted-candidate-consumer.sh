#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
if (( $# != 8 )); then
  print -u2 "usage: verify-hosted-candidate-consumer.sh <download-root> <source-revision> <archive-upload-sha256> <manifest-upload-sha256> <evidence-upload-sha256> <signables-upload-sha256> <transport-upload-sha256> <verification-node>"
  exit 64
fi

DOWNLOAD_ROOT="$1"
SOURCE_REVISION="$2"
ARCHIVE_UPLOAD_SHA256="$3"
MANIFEST_UPLOAD_SHA256="$4"
EVIDENCE_UPLOAD_SHA256="$5"
SIGNABLES_UPLOAD_SHA256="$6"
TRANSPORT_UPLOAD_SHA256="$7"
VERIFY_NODE="$8"
IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
TRANSPORT_TOOL="$PROJECT_DIR/scripts/ci-candidate-transport.mjs"
ZIP_VERIFIER="$PROJECT_DIR/scripts/verify-zip-entries.mjs"
MACHO_VERIFIER="$PROJECT_DIR/scripts/verify-macho-compatibility.sh"

fail() {
  print -u2 -- "$1"
  exit 1
}

[[ "$DOWNLOAD_ROOT" == /* && -d "$DOWNLOAD_ROOT" && ! -L "$DOWNLOAD_ROOT" \
   && "${DOWNLOAD_ROOT:A}" == "$DOWNLOAD_ROOT" \
   && "$(/usr/bin/stat -f '%u' "$DOWNLOAD_ROOT")" == "$(/usr/bin/id -u)" ]] \
  || fail "Hosted candidate downloads require one owner-controlled absolute directory."
/bin/chmod 0700 "$DOWNLOAD_ROOT"
[[ "$(/usr/bin/stat -f '%u:%Lp' "$DOWNLOAD_ROOT")" == "$(/usr/bin/id -u):700" ]] \
  || fail "Hosted candidate download root is not private."

[[ "$VERIFY_NODE" == /* && -f "$VERIFY_NODE" && ! -L "$VERIFY_NODE" \
   && -x "$VERIFY_NODE" && "${VERIFY_NODE:A}" == "$VERIFY_NODE" \
   && "$(/usr/bin/stat -f '%u' "$VERIFY_NODE")" == "$(/usr/bin/id -u)" ]] \
  || fail "Hosted candidate verification Node is not one owner-controlled canonical executable."
[[ -f "$IDENTITY" && ! -L "$IDENTITY" && -f "$TRANSPORT_TOOL" \
   && -f "$ZIP_VERIFIER" && -x "$MACHO_VERIFIER" ]] \
  || fail "Hosted candidate consumer is missing a reviewed verifier input."
EXPECTED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$IDENTITY")"
EXPECTED_NODE_VERSION="$(/usr/bin/plutil -extract runtime.nodeVersion raw -o - "$IDENTITY")"
[[ "$(/usr/bin/shasum -a 256 "$VERIFY_NODE" | /usr/bin/awk '{ print $1 }')" == "$EXPECTED_NODE_SHA256" \
   && "$($VERIFY_NODE --version)" == "v$EXPECTED_NODE_VERSION" ]] \
  || fail "Hosted candidate verification Node does not match the reviewed executable."

ARCHIVE_NAME="$(/usr/bin/plutil -extract releaseArchiveName raw -o - "$IDENTITY")"
APP_NAME="$(/usr/bin/plutil -extract applicationBundleName raw -o - "$IDENTITY")"
MINIMUM_MACOS="$(/usr/bin/plutil -extract minimumMacOS raw -o - "$IDENTITY")"
ARCHIVE="$DOWNLOAD_ROOT/$ARCHIVE_NAME"
MANIFEST="$DOWNLOAD_ROOT/release-manifest.json"
EVIDENCE="$DOWNLOAD_ROOT/ci-evidence-summary.json"
SIGNABLES="$DOWNLOAD_ROOT/runtime-signables.json"
TRANSPORT="$DOWNLOAD_ROOT/ci-candidate-transport.json"

for input in "$ARCHIVE" "$MANIFEST" "$EVIDENCE" "$SIGNABLES" "$TRANSPORT"; do
  [[ -f "$input" && ! -L "$input" \
     && "$(/usr/bin/stat -f '%u:%l' "$input")" == "$(/usr/bin/id -u):1" ]] \
    || fail "Hosted candidate download is missing one exact unlinked artifact."
  /bin/chmod 0600 "$input"
done

"$VERIFY_NODE" "$TRANSPORT_TOOL" verify \
  "$IDENTITY" "$MANIFEST" "$ARCHIVE" "$EVIDENCE" "$SIGNABLES" "$TRANSPORT" \
  "$SOURCE_REVISION" "$ARCHIVE_UPLOAD_SHA256" "$MANIFEST_UPLOAD_SHA256" \
  "$EVIDENCE_UPLOAD_SHA256" "$SIGNABLES_UPLOAD_SHA256" "$TRANSPORT_UPLOAD_SHA256"
"$VERIFY_NODE" "$ZIP_VERIFIER" "$ARCHIVE" "" "$APP_NAME"

TEMP_ROOT=""
TEMP_ROOT_IDENTITY=""
cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$TEMP_ROOT" ]]; then
    [[ "$TEMP_ROOT" == /private/tmp/fulmar-hosted-candidate-consumer.* \
       && -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" \
       && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT" 2>/dev/null)" == "$TEMP_ROOT_IDENTITY" ]] \
      || return 126
    /bin/rm -rf -- "$TEMP_ROOT" || return 126
    [[ ! -e "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]] || return 126
    TEMP_ROOT=""
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

TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-hosted-candidate-consumer.XXXXXX)"
/bin/chmod 0700 "$TEMP_ROOT"
TEMP_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$TEMP_ROOT")" \
  || fail "Hosted candidate consumer could not attest its extraction root."
[[ "$TEMP_ROOT_IDENTITY" == "$(/usr/bin/stat -f '%d:%i:%u:Directory:700' "$TEMP_ROOT")" ]] \
  || fail "Hosted candidate extraction root is not private."
/bin/mkdir -m 0700 "$TEMP_ROOT/extracted"
/usr/bin/ditto -x -k "$ARCHIVE" "$TEMP_ROOT/extracted"
EXTRACTED_APP="$TEMP_ROOT/extracted/$APP_NAME"
[[ -d "$EXTRACTED_APP" && ! -L "$EXTRACTED_APP" \
   && "$(/usr/bin/find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 -print \
       | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] \
  || fail "Hosted candidate archive did not extract to exactly one reviewed app root."

/usr/bin/cmp -s "$IDENTITY" "$EXTRACTED_APP/Contents/Resources/ReleaseIdentity.json" \
  || fail "Transported app does not contain the exact reviewed release identity."
[[ "$(/usr/bin/plutil -extract CFBundleDisplayName raw -o - "$EXTRACTED_APP/Contents/Info.plist")" \
      == "$(/usr/bin/plutil -extract productDisplayName raw -o - "$IDENTITY")" \
   && "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$EXTRACTED_APP/Contents/Info.plist")" \
      == "$(/usr/bin/plutil -extract bundleIdentifier raw -o - "$IDENTITY")" \
   && "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$EXTRACTED_APP/Contents/Info.plist")" \
      == "$(/usr/bin/plutil -extract version raw -o - "$MANIFEST")" \
   && "$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$EXTRACTED_APP/Contents/Info.plist")" \
      == "$(/usr/bin/plutil -extract build raw -o - "$MANIFEST")" \
   && "$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - "$EXTRACTED_APP/Contents/Info.plist")" \
      == "$MINIMUM_MACOS" ]] \
  || fail "Transported app property-list identity does not match its manifest."

/usr/bin/codesign --verify --deep --strict "$EXTRACTED_APP"
/bin/zsh -f "$MACHO_VERIFIER" "$EXTRACTED_APP" "$SIGNABLES" "$MINIMUM_MACOS" "$VERIFY_NODE"

BUNDLED_NODE="$EXTRACTED_APP/Contents/Resources/Runtime/node"
[[ -f "$BUNDLED_NODE" && ! -L "$BUNDLED_NODE" && -x "$BUNDLED_NODE" ]] \
  || fail "Transported app is missing its candidate-bound headless runtime."
# Packaging signs this Mach-O, so its post-signing bytes intentionally differ
# from the unsigned upstream Node digest used to authenticate VERIFY_NODE.  The
# exact archive digest, enclosing deep signature, Runtime Mach-O inventory and
# this nested signature bind the executable without making that false byte
# comparison.
/usr/bin/codesign --verify --strict "$BUNDLED_NODE"
SMOKE_VERSION="$(/usr/bin/env -i HOME=/var/empty PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  LANG=en_US.UTF-8 LC_CTYPE=UTF-8 "$BUNDLED_NODE" --version)" \
  || fail "Transported app headless runtime did not execute on the declared minimum macOS."
[[ "$SMOKE_VERSION" == "v$EXPECTED_NODE_VERSION" ]] \
  || fail "Transported app headless runtime returned an unexpected version."

VERSION="$(/usr/bin/plutil -extract version raw -o - "$MANIFEST")"
BUILD="$(/usr/bin/plutil -extract build raw -o - "$MANIFEST")"
print "Minimum-macOS exact-candidate verification passed for Fulmar $VERSION ($BUILD): archive, manifest, signatures, every inventoried Mach-O minimum, and headless runtime smoke."
