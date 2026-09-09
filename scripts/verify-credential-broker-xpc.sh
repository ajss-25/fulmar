#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-}"
[[ -n "$APP_DIR" ]] || {
  print -u2 "usage: verify-credential-broker-xpc.sh <Fulmar.app>"
  exit 1
}
SERVICE="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc"
INFO="$SERVICE/Contents/Info.plist"
EXECUTABLE="$SERVICE/Contents/MacOS/LocalHarnessCredentialBrokerService"
HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
APP_INFO="$APP_DIR/Contents/Info.plist"
MIGRATION_INFO="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/Info.plist"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-credential-broker-verify.XXXXXX)"
trap '/bin/rm -rf -- "$TEMP_ROOT"' EXIT
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 129' HUP
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 130' INT
trap '/bin/rm -rf -- "$TEMP_ROOT" >/dev/null 2>&1 || true; exit 143' TERM

[[ -d "$APP_DIR" && ! -L "$APP_DIR" && "${APP_DIR:A}" == "$APP_DIR" \
   && -d "$SERVICE" && ! -L "$SERVICE" \
   && -f "$INFO" && ! -L "$INFO" \
   && -f "$EXECUTABLE" && ! -L "$EXECUTABLE" && -x "$EXECUTABLE" \
   && -f "$HELPER" && ! -L "$HELPER" && -x "$HELPER" ]] || {
  print -u2 "Credential broker verification requires one canonical packaged app."
  exit 1
}
plutil -lint "$INFO" >/dev/null
BUNDLED_NODE_SHA256="$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')"
PINNED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
[[ -x "$NODE" && "$BUNDLED_NODE_SHA256" == "$PINNED_NODE_SHA256" ]] || exit 1
/usr/bin/plutil -convert json -o "$TEMP_ROOT/migration-xpc-info.json" "$MIGRATION_INFO"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/broker-xpc-info.json" "$INFO"
"$NODE" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$TEMP_ROOT/migration-xpc-info.json" "$TEMP_ROOT/broker-xpc-info.json" >/dev/null
BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$APP_INFO")"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$INFO")" == "$BUNDLE_ID.credential-broker" \
   && "$(plutil -extract CFBundleExecutable raw -o - "$INFO")" == "LocalHarnessCredentialBrokerService" \
   && "$(plutil -extract CFBundlePackageType raw -o - "$INFO")" == "XPC!" ]] || exit 1
/usr/bin/codesign --verify --strict "$SERVICE"
/usr/bin/codesign --verify --strict "$EXECUTABLE"

ACTUAL="$TEMP_ROOT/actual.plist"
/usr/bin/codesign -d --xml --entitlements - "$SERVICE" >"$ACTUAL" 2>"$TEMP_ROOT/entitlements.stderr"
UNEXPECTED="$(/usr/bin/sed -E '/^Executable=/d; /^[[:space:]]*$/d' "$TEMP_ROOT/entitlements.stderr")"
[[ -s "$ACTUAL" && -z "$UNEXPECTED" ]] || exit 1
/usr/bin/plutil -convert json -o "$TEMP_ROOT/actual.json" "$ACTUAL"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/expected.json" \
  "$PROJECT_DIR/Resources/CredentialBrokerService.entitlements"
/usr/bin/python3 - "$TEMP_ROOT/actual.json" "$TEMP_ROOT/expected.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as actual, open(sys.argv[2], encoding="utf-8") as expected:
    if json.load(actual) != json.load(expected): raise SystemExit(1)
PY

DETAILS="$(/usr/bin/codesign -dvv "$SERVICE" 2>&1)"
[[ "$DETAILS" == *"Identifier=$BUNDLE_ID.credential-helper"* \
   && "$DETAILS" == *flags=*runtime* ]] || exit 1
HELPER_DR="$(/usr/bin/codesign -d -r- "$HELPER" 2>&1 | /usr/bin/sed -n 's/^designated => //p')"
SERVICE_DR="$(/usr/bin/codesign -d -r- "$SERVICE" 2>&1 | /usr/bin/sed -n 's/^designated => //p')"
[[ -n "$HELPER_DR" && "$SERVICE_DR" == "$HELPER_DR" ]] || exit 1

UNDEFINED="$(/usr/bin/nm -u "$EXECUTABLE")"
for forbidden in _posix_spawn _posix_spawnp _execve _execl _execv _system _popen; do
  [[ "$UNDEFINED" != *"$forbidden"* ]] || exit 1
done
LIBRARIES="$(/usr/bin/otool -L "$EXECUTABLE")"
[[ "$LIBRARIES" != *'/JavaScriptCore.framework/'* \
   && "$LIBRARIES" != *'/Network.framework/'* \
   && "$LIBRARIES" != *'/WebKit.framework/'* ]] || exit 1
STRINGS="$(/usr/bin/strings "$EXECUTABLE")"
[[ "$STRINGS" == *"LocalHarnessCredentialBrokerXPCProtocol"* \
   && "$STRINGS" == *"credential-broker-acceptance"* \
   && "$STRINGS" != *"Runtime/node"* ]] || exit 1

print "Credential broker XPC verification passed: exact helper-compatible identity, minimal sandbox, no process launcher/network/web runtime, and bounded protocol surface."
