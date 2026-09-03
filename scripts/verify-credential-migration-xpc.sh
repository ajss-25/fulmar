#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-}"
[[ -n "$APP_DIR" ]] || {
  print -u2 "usage: verify-credential-migration-xpc.sh <Fulmar.app>"
  exit 1
}
SERVICE="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc"
SERVICE_INFO="$SERVICE/Contents/Info.plist"
SERVICE_EXECUTABLE="$SERVICE/Contents/MacOS/LocalHarnessCredentialMigrationService"
HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
APP_INFO="$APP_DIR/Contents/Info.plist"
BROKER_INFO="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/Info.plist"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
TEMP_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/private/tmp}/fulmar-credential-xpc-verify.XXXXXX")"
trap '/bin/rm -rf -- "$TEMP_ROOT"' EXIT
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 129' HUP
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 130' INT
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 143' TERM

[[ -d "$APP_DIR" && ! -L "$APP_DIR" && "${APP_DIR:A}" == "$APP_DIR" \
   && -d "$SERVICE" && ! -L "$SERVICE" \
   && -f "$SERVICE_INFO" && ! -L "$SERVICE_INFO" \
   && -f "$SERVICE_EXECUTABLE" && ! -L "$SERVICE_EXECUTABLE" -x "$SERVICE_EXECUTABLE" \
   && -f "$HELPER" && ! -L "$HELPER" -x "$HELPER" ]] || {
  print -u2 "Credential migration XPC verification requires one canonical packaged candidate."
  exit 1
}
plutil -lint "$SERVICE_INFO" >/dev/null
BUNDLED_NODE_SHA256="$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')"
PINNED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
[[ -x "$NODE" && "$BUNDLED_NODE_SHA256" == "$PINNED_NODE_SHA256" ]] || exit 1
/usr/bin/plutil -convert json -o "$TEMP_ROOT/migration-xpc-info.json" "$SERVICE_INFO"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/broker-xpc-info.json" "$BROKER_INFO"
"$NODE" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$TEMP_ROOT/migration-xpc-info.json" "$TEMP_ROOT/broker-xpc-info.json" >/dev/null
BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$APP_INFO")"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$SERVICE_INFO")" == "$BUNDLE_ID.credential-helper" \
   && "$(plutil -extract CFBundleExecutable raw -o - "$SERVICE_INFO")" == "LocalHarnessCredentialMigrationService" \
   && "$(plutil -extract CFBundlePackageType raw -o - "$SERVICE_INFO")" == "XPC!" ]] || {
  print -u2 "The credential migration XPC Info.plist does not match its fixed private identity."
  exit 1
}
/usr/bin/codesign --verify --strict "$SERVICE"
/usr/bin/codesign --verify --strict "$SERVICE_EXECUTABLE"
ACTUAL_ENTITLEMENTS="$TEMP_ROOT/actual-entitlements.plist"
ENTITLEMENTS_STDERR="$TEMP_ROOT/entitlements.stderr"
set +e
/usr/bin/codesign -d --xml --entitlements - "$SERVICE" \
  >"$ACTUAL_ENTITLEMENTS" 2>"$ENTITLEMENTS_STDERR"
ENTITLEMENTS_STATUS=$?
set -e
UNEXPECTED_ENTITLEMENTS_STDERR="$(/usr/bin/sed -E \
  '/^Executable=/d; /^[[:space:]]*$/d' "$ENTITLEMENTS_STDERR")"
(( ENTITLEMENTS_STATUS == 0 )) \
  && [[ -z "$UNEXPECTED_ENTITLEMENTS_STDERR" && -s "$ACTUAL_ENTITLEMENTS" ]] || {
  print -u2 "Credential migration XPC entitlements could not be read cleanly."
  /bin/cat "$ENTITLEMENTS_STDERR" >&2
  exit 1
}
/usr/bin/plutil -lint "$ACTUAL_ENTITLEMENTS" >/dev/null
/usr/bin/plutil -convert json -o "$TEMP_ROOT/actual-entitlements.json" "$ACTUAL_ENTITLEMENTS"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/expected-entitlements.json" \
  "$PROJECT_DIR/Resources/CredentialMigrationService.entitlements"
/usr/bin/cmp -s "$TEMP_ROOT/actual-entitlements.json" \
  "$TEMP_ROOT/expected-entitlements.json" || {
  print -u2 "Credential migration XPC embedded sandbox entitlements are not exact."
  exit 1
}
SERVICE_DETAILS="$(/usr/bin/codesign -dvv "$SERVICE" 2>&1)"
[[ "$SERVICE_DETAILS" == *"Identifier=$BUNDLE_ID.credential-helper"* \
   && "$SERVICE_DETAILS" == *flags=*runtime* ]] || {
  print -u2 "The credential migration XPC service has the wrong signed identity."
  exit 1
}
HELPER_REQUIREMENT="$(/usr/bin/codesign -d -r- "$HELPER" 2>&1 \
  | /usr/bin/sed -n 's/^designated => //p')"
SERVICE_REQUIREMENT="$(/usr/bin/codesign -d -r- "$SERVICE" 2>&1 \
  | /usr/bin/sed -n 's/^designated => //p')"
[[ -n "$HELPER_REQUIREMENT" && "$SERVICE_REQUIREMENT" == "$HELPER_REQUIREMENT" ]] || {
  print -u2 "The migration service cannot preserve the credential helper Keychain ACL requirement."
  exit 1
}

UNDEFINED_SYMBOLS="$(/usr/bin/nm -u "$SERVICE_EXECUTABLE")"
for forbidden in _posix_spawn _posix_spawnp _execve _execl _execv _system _popen; do
  [[ "$UNDEFINED_SYMBOLS" != *"$forbidden"* ]] || {
    print -u2 "The credential migration XPC service imports a forbidden pathname launcher: $forbidden"
    exit 1
  }
done
/usr/bin/otool -L "$SERVICE_EXECUTABLE" \
  | /usr/bin/grep -F '/JavaScriptCore.framework/' >/dev/null || {
  print -u2 "The credential migration XPC service is not linked to JavaScriptCore."
  exit 1
}
SERVICE_STRINGS="$(/usr/bin/strings "$SERVICE_EXECUTABLE")"
[[ "$SERVICE_STRINGS" == *"LocalHarnessCredentialMigrationXPCProtocol"* \
   && "$SERVICE_STRINGS" == *"fulmar-yaml-graph"* \
   && "$SERVICE_STRINGS" != *"MigrateCredentials.mjs"* \
   && "$SERVICE_STRINGS" != *"Runtime/node"* ]] || {
  print -u2 "The credential migration XPC executable does not expose the reviewed no-Node boundary."
  exit 1
}

print "Credential migration XPC verification passed: exact service signature, helper-compatible designated requirement, embedded minimal App Sandbox entitlement, JavaScriptCore graph evaluator, and no process-launch imports."
