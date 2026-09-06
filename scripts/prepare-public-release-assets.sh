#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
(( $# == 0 || $# == 6 )) || {
  print -u2 "Usage: prepare-public-release-assets.sh [archive manifest output expected-sha256 expected-version expected-build]"
  exit 64
}
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 4294967296 --rss-grace-seconds 5 \
    --emergency-rss-bytes 6442450944 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete public-asset preparation" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Public-asset preparation inherited an invalid root-watchdog capability."
  exit 1
fi
source "${0:A:h}/clean-release-environment.zsh"
fulmar_require_clean_release_environment public "$0" "$@"

source "$PROJECT_DIR/scripts/release-lock.zsh"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
ARCHIVE="${1:-$PROJECT_DIR/build/Fulmar.app.zip}"
MANIFEST="${2:-$PROJECT_DIR/build/release-manifest.json}"
OUTPUT="${3:-$PROJECT_DIR/build/public-release-assets}"
EXPECTED_CANDIDATE_SHA256="${4:-}"
EXPECTED_CANDIDATE_VERSION="${5:-}"
EXPECTED_CANDIDATE_BUILD="${6:-}"
SYMBOL_ARCHIVE="$PROJECT_DIR/build/Fulmar.dSYMs.zip"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
FIRST_PARTY_LICENSE_POLICY="$PROJECT_DIR/scripts/first-party-license-policy.mjs"
SOURCE_INPUT_INVENTORY="$PROJECT_DIR/build/source-build-inputs.json"
SOURCE_INPUT_TOOL="$PROJECT_DIR/scripts/source-build-input-inventory.mjs"
STATIC_SECURITY_SUMMARY="$PROJECT_DIR/build/static-security-summary.json"
STATIC_SECURITY_VERIFIER="$PROJECT_DIR/scripts/verify-static-security-summary.mjs"
AUDIT_SUMMARY="$PROJECT_DIR/build/dependency-audit-summary.json"
PACKAGE_LOCK="$PROJECT_DIR/VendorRuntime/package-lock.json"
ATOMIC_PUBLISHER_SOURCE="$PROJECT_DIR/Tools/PublicAssetPublisher/main.c"
PINNED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
MINIMUM_MACOS="$(/usr/bin/plutil -extract minimumMacOS raw -o - "$RELEASE_IDENTITY")"
TEMP_ROOT=""
ATOMIC_PUBLISHER=""
PUBLIC_STAGING=""
PUBLIC_STAGING_IDENTITY=""
OUTPUT_PARENT=""
OUTPUT_NAME=""
verify_expected_candidate_binding() {
  local manifest_path="$1"
  local archive_path="$2"
  local actual_sha256 actual_version actual_build archive_sha256
  actual_sha256="$(/usr/bin/plutil -extract sha256 raw -o - "$manifest_path")" || return 1
  actual_version="$(/usr/bin/plutil -extract version raw -o - "$manifest_path")" || return 1
  actual_build="$(/usr/bin/plutil -extract build raw -o - "$manifest_path")" || return 1
  archive_sha256="$(/usr/bin/shasum -a 256 "$archive_path" | /usr/bin/awk '{print $1}')" || return 1
  [[ "$actual_sha256" == "$EXPECTED_CANDIDATE_SHA256" \
     && "$actual_version" == "$EXPECTED_CANDIDATE_VERSION" \
     && "$actual_build" == "$EXPECTED_CANDIDATE_BUILD" \
     && "$archive_sha256" == "$EXPECTED_CANDIDATE_SHA256" ]] || {
    print -u2 "Public asset preparation rejected candidate drift from the operator-bound SHA, version, or build."
    return 1
  }
}
cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$PUBLIC_STAGING" && -n "$PUBLIC_STAGING_IDENTITY" \
     && -x "$ATOMIC_PUBLISHER" ]]; then
    if ! "$ATOMIC_PUBLISHER" cleanup "$OUTPUT_PARENT" "${PUBLIC_STAGING:t}" \
      "${PUBLIC_STAGING_IDENTITY%%:*}" "${PUBLIC_STAGING_IDENTITY##*:}"; then
      print -u2 "Private public-asset staging could not be retired safely: $PUBLIC_STAGING"
    fi
  fi
  if [[ -n "$TEMP_ROOT" && "$TEMP_ROOT" == /private/tmp/fulmar-public-assets.* \
     && -d "$TEMP_ROOT" ]]; then
    /bin/rm -rf -- "$TEMP_ROOT"
  fi
  fulmar_release_release_lock
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
fulmar_acquire_release_lock "Fulmar public-asset preparation"

[[ -x "$NODE" && "$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')" == "$PINNED_NODE_SHA256" ]] || {
  echo "Public asset preparation requires the exact reviewed Node bootstrap." >&2; exit 1
}
"$NODE" "$FIRST_PARTY_LICENSE_POLICY" state "$PROJECT_DIR" --require-selected >/dev/null
[[ "${#EXPECTED_CANDIDATE_SHA256}" == 64 \
   && "$EXPECTED_CANDIDATE_SHA256" != *[^a-f0-9]* \
   && "$EXPECTED_CANDIDATE_VERSION" =~ '^[0-9]+(\.[0-9]+){2}$' \
   && "$EXPECTED_CANDIDATE_BUILD" =~ '^[1-9][0-9]*$' ]] || {
  print -u2 "Public asset preparation requires one explicit expected candidate SHA, version, and build."
  exit 64
}
"$NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" "$AUDIT_SUMMARY" "$PACKAGE_LOCK"
"$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
  "$RELEASE_IDENTITY" "$MANIFEST" "$PROJECT_DIR/build"
"$NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" \
  verify "$PROJECT_DIR/build/toolchain-inventory.json"

[[ "${ARCHIVE:A}" == "$PROJECT_DIR/build/Fulmar.app.zip" && -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || {
  echo "Public assets require the exact current build/Fulmar.app.zip." >&2; exit 1
}
[[ "${MANIFEST:A}" == "$PROJECT_DIR/build/release-manifest.json" && -f "$MANIFEST" && ! -L "$MANIFEST" ]] || {
  echo "Public assets require the exact current build/release-manifest.json." >&2; exit 1
}
[[ "${SYMBOL_ARCHIVE:A}" == "$PROJECT_DIR/build/Fulmar.dSYMs.zip" && -f "$SYMBOL_ARCHIVE" && ! -L "$SYMBOL_ARCHIVE" ]] || {
  echo "Public assets require the exact current build/Fulmar.dSYMs.zip." >&2; exit 1
}
OUTPUT_PARENT="${OUTPUT:h}"
OUTPUT_NAME="${OUTPUT:t}"
[[ "$OUTPUT" == /* && "$OUTPUT_NAME" != "" && "$OUTPUT_NAME" != "." \
   && "$OUTPUT_NAME" != ".." && "$OUTPUT_NAME" != */* \
   && -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" \
   && "${OUTPUT_PARENT:A}" == "$OUTPUT_PARENT" \
   && "$(/usr/bin/stat -f %u "$OUTPUT_PARENT")" == "$EUID" \
   && ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || {
  echo "Public asset destination must be a new absolute path." >&2; exit 1
}

umask 077
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-public-assets.XXXXXX)"
ATOMIC_PUBLISHER="$TEMP_ROOT/fulmar-public-asset-publisher"
/usr/bin/xcrun --sdk macosx clang \
  -std=c17 -Os -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wformat=2 \
  "$ATOMIC_PUBLISHER_SOURCE" -o "$ATOMIC_PUBLISHER"
/bin/chmod 0700 "$ATOMIC_PUBLISHER"
/usr/bin/codesign --force --sign - --timestamp=none "$ATOMIC_PUBLISHER" >/dev/null
/usr/bin/codesign --verify --strict "$ATOMIC_PUBLISHER"
ARCHIVE_SNAPSHOT="$TEMP_ROOT/Fulmar.app.zip"
MANIFEST_SNAPSHOT="$TEMP_ROOT/release-manifest.json"
SYMBOL_SNAPSHOT="$TEMP_ROOT/Fulmar.dSYMs.zip"
STATIC_SECURITY_SNAPSHOT="$TEMP_ROOT/static-security-summary.json"
verify_expected_candidate_binding "$MANIFEST" "$ARCHIVE"
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$ARCHIVE" "$ARCHIVE_SNAPSHOT" >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$MANIFEST" "$MANIFEST_SNAPSHOT" 1048576 >/dev/null
verify_expected_candidate_binding "$MANIFEST_SNAPSHOT" "$ARCHIVE_SNAPSHOT"
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$SYMBOL_ARCHIVE" "$SYMBOL_SNAPSHOT" 268435456 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" \
  "$STATIC_SECURITY_SUMMARY" "$STATIC_SECURITY_SNAPSHOT" 524288 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$ARCHIVE_SNAPSHOT" >/dev/null
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$SYMBOL_SNAPSHOT" "" "Fulmar.dSYMs" >/dev/null
/usr/bin/ditto -x -k --noqtn "$ARCHIVE_SNAPSHOT" "$TEMP_ROOT/extracted"
/usr/bin/ditto -x -k --noqtn "$SYMBOL_SNAPSHOT" "$TEMP_ROOT/symbols"
APP="$TEMP_ROOT/extracted/Fulmar.app"
SYMBOL_ROOT="$TEMP_ROOT/symbols/Fulmar.dSYMs"
[[ -d "$APP" && "$(/usr/bin/find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] || exit 1
[[ -d "$SYMBOL_ROOT" && "$(/usr/bin/find "$TEMP_ROOT/symbols" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] || exit 1
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$ARCHIVE_SNAPSHOT" "$APP" >/dev/null
/usr/bin/plutil -convert json -o "$TEMP_ROOT/info.json" "$APP/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/migration-xpc-info.json" \
  "$APP/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/broker-xpc-info.json" \
  "$APP/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/Info.plist"
"$NODE" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$TEMP_ROOT/migration-xpc-info.json" "$TEMP_ROOT/broker-xpc-info.json"

"$NODE" "$PROJECT_DIR/scripts/verify-release-manifest.mjs" \
  "$MANIFEST_SNAPSHOT" "$ARCHIVE_SNAPSHOT" "$TEMP_ROOT/info.json" \
  "$SYMBOL_SNAPSHOT" \
  "$PROJECT_DIR/VendorRuntime.inventory.json" \
  "$PROJECT_DIR/build/runtime-unsigned-inventory.json" \
  "$PROJECT_DIR/build/runtime-signables.json" \
  "$PROJECT_DIR/build/runtime-release-inventory.json" \
  "$PROJECT_DIR/build/source-build-inputs.json" \
  "$STATIC_SECURITY_SNAPSHOT" \
  "$PROJECT_DIR/build/toolchain-inventory.json" >/dev/null
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SNAPSHOT" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json" >/dev/null
/bin/zsh -f "$PROJECT_DIR/scripts/verify-macho-compatibility.sh" \
  "$APP" "$PROJECT_DIR/build/runtime-signables.json" "$MINIMUM_MACOS"

SBOM="$APP/Contents/Resources/LocalHarness.sbom.cdx.json"
NOTICES="$APP/Contents/Resources/THIRD_PARTY_NOTICES.md"
BUNDLED_LICENSE="$APP/Contents/Resources/LICENSE"
[[ -f "$SBOM" && ! -L "$SBOM" && -f "$NOTICES" && ! -L "$NOTICES" ]] || exit 1
"$NODE" "$FIRST_PARTY_LICENSE_POLICY" verify-bundle \
  "$PROJECT_DIR" "$BUNDLED_LICENSE" --require-selected >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" \
  "$BUNDLED_LICENSE" "$TEMP_ROOT/LICENSE" 1048576 >/dev/null
/usr/bin/cmp -s "$PROJECT_DIR/LICENSE" "$TEMP_ROOT/LICENSE"
RUNTIME="$APP/Contents/Resources/Runtime"
LOCAL="$RUNTIME/dsh/node_modules/@local-harness"
"$NODE" "$PROJECT_DIR/scripts/verify-sbom.mjs" \
  "$SBOM" "$RUNTIME" "$PROJECT_DIR" \
  "dsh/node_modules/@local-harness/dsh-credentials-keychain/package.json" \
  "dsh/node_modules/@local-harness/dsh-fs-confined/package.json" \
  "dsh/node_modules/@local-harness/dsh-mcp-guarded/package.json" \
  "dsh/node_modules/@local-harness/dsh-client-security-bridge/package.json" \
  "dsh/node_modules/@local-harness/dsh-performance-profile/package.json" \
  "dsh/node_modules/@local-harness/dsh-web-fetch-safe/package.json" >/dev/null
"$NODE" "$PROJECT_DIR/scripts/generate-third-party-notices.mjs" \
  "$PROJECT_DIR/Resources/THIRD_PARTY_NOTICES.md" "$RUNTIME" \
  "$PROJECT_DIR/Config/ThirdPartyLicenseOverrides.json" "$TEMP_ROOT/notices.md"
/usr/bin/cmp -s "$TEMP_ROOT/notices.md" "$NOTICES"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" "$APP" "$SYMBOL_ROOT"

PUBLIC_STAGING="$(/usr/bin/mktemp -d "$OUTPUT_PARENT/.${OUTPUT_NAME}.staging.XXXXXX")"
[[ "${PUBLIC_STAGING:h}" == "$OUTPUT_PARENT" && -d "$PUBLIC_STAGING" \
   && ! -L "$PUBLIC_STAGING" ]] || {
  echo "Private sibling public-asset staging could not be created safely." >&2; exit 1
}
/bin/chmod 0700 "$PUBLIC_STAGING"
PUBLIC_STAGING_IDENTITY="$(/usr/bin/stat -f '%d:%i' "$PUBLIC_STAGING")"
[[ "$PUBLIC_STAGING_IDENTITY" == <->:<-> ]] || exit 1
/bin/cp "$ARCHIVE_SNAPSHOT" "$PUBLIC_STAGING/Fulmar.app.zip"
/bin/cp "$SYMBOL_SNAPSHOT" "$PUBLIC_STAGING/Fulmar.dSYMs.zip"
/bin/cp "$MANIFEST_SNAPSHOT" "$PUBLIC_STAGING/release-manifest.json"
/bin/cp "$STATIC_SECURITY_SNAPSHOT" "$PUBLIC_STAGING/static-security-summary.json"
/bin/cp "$SBOM" "$PUBLIC_STAGING/LocalHarness.sbom.cdx.json"
/bin/cp "$NOTICES" "$PUBLIC_STAGING/THIRD_PARTY_NOTICES.md"
/bin/cp "$TEMP_ROOT/LICENSE" "$PUBLIC_STAGING/LICENSE"
(
  cd "$PUBLIC_STAGING"
  LC_ALL=C /usr/bin/shasum -a 256 Fulmar.app.zip > Fulmar.app.zip.sha256
)
/bin/chmod 0644 "$PUBLIC_STAGING"/*
(
  cd "$PUBLIC_STAGING"
  LC_ALL=C /usr/bin/shasum -a 256 \
    Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE LocalHarness.sbom.cdx.json THIRD_PARTY_NOTICES.md release-manifest.json static-security-summary.json \
    > SHA256SUMS.txt
)
/bin/chmod 0644 "$PUBLIC_STAGING/SHA256SUMS.txt"
[[ "$(/usr/bin/find "$PUBLIC_STAGING" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 9 ]] || {
  echo "Prepared public package did not contain exactly nine assets." >&2; exit 1
}
for name in Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE release-manifest.json static-security-summary.json LocalHarness.sbom.cdx.json THIRD_PARTY_NOTICES.md SHA256SUMS.txt; do
  [[ -f "$PUBLIC_STAGING/$name" && ! -L "$PUBLIC_STAGING/$name" \
     && "$(/usr/bin/stat -f %l "$PUBLIC_STAGING/$name")" == 1 \
     && "$(/usr/bin/stat -f %Lp "$PUBLIC_STAGING/$name")" == 644 ]] || {
    echo "Prepared public package contains an unsafe asset: $name" >&2; exit 1
  }
done
"$NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE" "$PROJECT_DIR/scripts/runtime-inventory.mjs" \
  verify "$PROJECT_DIR/VendorRuntime" "$PROJECT_DIR/VendorRuntime.inventory.json" VendorRuntime
"$NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" \
  verify "$PROJECT_DIR/build/toolchain-inventory.json"
"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" "$AUDIT_SUMMARY" "$PACKAGE_LOCK"
"$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
  "$RELEASE_IDENTITY" "$MANIFEST" "$PROJECT_DIR/build"
verify_expected_candidate_binding "$MANIFEST" "$ARCHIVE"
"$ATOMIC_PUBLISHER" publish "$OUTPUT_PARENT" "${PUBLIC_STAGING:t}" "$OUTPUT_NAME"
PUBLIC_STAGING=""
PUBLIC_STAGING_IDENTITY=""
echo "Prepared the exact nine manifest-, static-scan-, and licence-bound public release assets. This does not qualify them for distribution."
