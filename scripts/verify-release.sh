#!/bin/zsh -f
set -euo pipefail

source "${0:A:h}/clean-release-environment.zsh"
fulmar_require_clean_release_environment verify "$0" "$@"

if [[ "${1:-}" != "--signing-profile" || "${2:-}" != "private-stable" ]]; then
  print -u2 "Release verification requires the explicit reviewed signing profile: --signing-profile private-stable"
  exit 64
fi
SIGNING_PROFILE="$2"
shift 2
[[ "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-0}" == "1" ]] || {
  print -u2 "The private-stable verification profile requires LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1."
  exit 64
}

VERIFICATION_PROFILE="full-hardware"
if [[ "${1:-}" == "--deterministic-ci" ]]; then
  VERIFICATION_PROFILE="deterministic-ci"
  shift
elif [[ "${1:-}" == --* ]]; then
  print -u2 "Unsupported Fulmar release-verification option: $1"
  exit 64
fi
(( $# <= 2 )) || { print -u2 "Too many release-verification operands."; exit 64; }

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/release-lock.zsh"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
[[ -f "$RELEASE_IDENTITY" ]] || { print -u2 "Missing release identity."; exit 1; }
APP_BUNDLE_NAME="$(plutil -extract applicationBundleName raw -o - "$RELEASE_IDENTITY")"
ARCHIVE_NAME="$(plutil -extract releaseArchiveName raw -o - "$RELEASE_IDENTITY")"
SYMBOL_ARCHIVE_NAME="$(plutil -extract symbolsArchiveName raw -o - "$RELEASE_IDENTITY")"
SOURCE_APP_DIR="${1:-/private/tmp/LocalHarnessBuild/$APP_BUNDLE_NAME}"
ARCHIVE="$PROJECT_DIR/build/$ARCHIVE_NAME"
SYMBOL_ARCHIVE="$PROJECT_DIR/build/$SYMBOL_ARCHIVE_NAME"
MANIFEST="$PROJECT_DIR/build/release-manifest.json"
AUDIT_SUMMARY="$PROJECT_DIR/build/dependency-audit-summary.json"
VENDOR_ROOT="$PROJECT_DIR/VendorRuntime"
VENDOR_INVENTORY="$PROJECT_DIR/VendorRuntime.inventory.json"
UNSIGNED_RUNTIME_INVENTORY="$PROJECT_DIR/build/runtime-unsigned-inventory.json"
RUNTIME_SIGNABLES="$PROJECT_DIR/build/runtime-signables.json"
FINAL_RUNTIME_INVENTORY="$PROJECT_DIR/build/runtime-release-inventory.json"
SOURCE_INPUT_INVENTORY="$PROJECT_DIR/build/source-build-inputs.json"
SOURCE_INPUT_TOOL="$PROJECT_DIR/scripts/source-build-input-inventory.mjs"
STATIC_SECURITY_SUMMARY="$PROJECT_DIR/build/static-security-summary.json"
STATIC_SECURITY_VERIFIER="$PROJECT_DIR/scripts/verify-static-security-summary.mjs"
FIRST_PARTY_LICENSE_POLICY="$PROJECT_DIR/scripts/first-party-license-policy.mjs"
TOOLCHAIN_INVENTORY="$PROJECT_DIR/build/toolchain-inventory.json"
TOOLCHAIN_TOOL="$PROJECT_DIR/scripts/toolchain-inventory.mjs"
CI_EVIDENCE_SUMMARY="${2:-$PROJECT_DIR/build/ci-evidence-summary.json}"
if [[ "$CI_EVIDENCE_SUMMARY" != "$PROJECT_DIR/build/ci-evidence-summary.json" ]]; then
  [[ "${CI_EVIDENCE_SUMMARY:h}" == "$PROJECT_DIR/build"/.release-verify-*-set.* \
     && "${CI_EVIDENCE_SUMMARY:t}" == ".ci-evidence-input.json" \
     && -d "${CI_EVIDENCE_SUMMARY:h}" && ! -L "${CI_EVIDENCE_SUMMARY:h}" \
     && ! -e "$CI_EVIDENCE_SUMMARY" && ! -L "$CI_EVIDENCE_SUMMARY" ]] || {
    print -u2 "The private CI evidence destination is unsafe."
    exit 64
  }
fi
INVENTORY_TOOL="$PROJECT_DIR/scripts/runtime-inventory.mjs"
INVENTORY_NODE="$VENDOR_ROOT/node-v22.23.1-darwin-arm64/bin/node"
PRODUCT_DISPLAY_NAME="$(plutil -extract productDisplayName raw -o - "$RELEASE_IDENTITY")"
PRODUCT_BUNDLE_ID="$(plutil -extract bundleIdentifier raw -o - "$RELEASE_IDENTITY")"
PRODUCT_VERSION="$(plutil -extract appVersion raw -o - "$RELEASE_IDENTITY")"
PRODUCT_BUILD="$(plutil -extract appBuild raw -o - "$RELEASE_IDENTITY")"
MINIMUM_MACOS="$(plutil -extract minimumMacOS raw -o - "$RELEASE_IDENTITY")"
PINNED_NODE_VERSION="$(plutil -extract runtime.nodeVersion raw -o - "$RELEASE_IDENTITY")"
PINNED_NODE_SHA256="$(plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
PINNED_DSH_VERSION="$(plutil -extract runtime.deepseekHarnessVersion raw -o - "$RELEASE_IDENTITY")"
PINNED_DSH_MCP_CLIENT_VERSION="$(plutil -extract runtime.deepseekMCPClientVersion raw -o - "$RELEASE_IDENTITY")"
TEMP_ROOT="$(mktemp -d /private/tmp/local-harness-release-verification.XXXXXX)"

cleanup() {
  local exit_code="${1:-$?}"
  rm -rf "$TEMP_ROOT"
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

fulmar_acquire_release_lock "Fulmar release verification" || exit

[[ -d "$SOURCE_APP_DIR" && ! -L "$SOURCE_APP_DIR" && "${SOURCE_APP_DIR:A}" == "$SOURCE_APP_DIR" ]] || {
  print -u2 "Missing or non-canonical source application bundle: $SOURCE_APP_DIR"; exit 1
}
for required in \
  "$ARCHIVE" "$SYMBOL_ARCHIVE" "$MANIFEST" "$AUDIT_SUMMARY" "$VENDOR_INVENTORY" \
  "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_SIGNABLES" "$FINAL_RUNTIME_INVENTORY" \
  "$SOURCE_INPUT_INVENTORY" "$STATIC_SECURITY_SUMMARY" "$TOOLCHAIN_INVENTORY"; do
  [[ -f "$required" && -s "$required" ]] || { print -u2 "Missing release input: $required"; exit 1; }
done

[[ -x "$INVENTORY_NODE" ]] || { print -u2 "Missing vendored inventory bootstrap runtime."; exit 1; }
ACTUAL_NODE_SHA256="$(/usr/bin/shasum -a 256 "$INVENTORY_NODE" | /usr/bin/awk '{print $1}')"
[[ "$ACTUAL_NODE_SHA256" == "$PINNED_NODE_SHA256" ]] || {
  print -u2 "The vendored Node bootstrap digest is not the reviewed value."
  exit 1
}
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-source-product-contract.mjs" "$PROJECT_DIR"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-deepseek-runtime-contract.mjs" "$PROJECT_DIR"
"$INVENTORY_NODE" "$FIRST_PARTY_LICENSE_POLICY" state "$PROJECT_DIR" >/dev/null
"$INVENTORY_NODE" "$INVENTORY_TOOL" verify "$VENDOR_ROOT" "$VENDOR_INVENTORY" VendorRuntime
"$INVENTORY_NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$INVENTORY_NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"

SOURCE_NODE="$SOURCE_APP_DIR/Contents/Resources/Runtime/node"
[[ -x "$SOURCE_NODE" ]] || { print -u2 "The source bundle has no executable pinned Node runtime."; exit 1; }
plutil -convert json -o "$TEMP_ROOT/source-info.json" "$SOURCE_APP_DIR/Contents/Info.plist"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-manifest.mjs" \
  "$MANIFEST" "$ARCHIVE" "$TEMP_ROOT/source-info.json" \
  "$SYMBOL_ARCHIVE" \
  "$VENDOR_INVENTORY" "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_SIGNABLES" "$FINAL_RUNTIME_INVENTORY" \
  "$SOURCE_INPUT_INVENTORY" "$STATIC_SECURITY_SUMMARY" "$TOOLCHAIN_INVENTORY"
"$INVENTORY_NODE" "$TOOLCHAIN_TOOL" verify "$TOOLCHAIN_INVENTORY"
# Do not execute a runtime from the candidate bundle until the candidate has
# been matched to the reviewed source/runtime inventories. The independently
# pinned bootstrap is the only interpreter trusted during pre-extraction
# structural comparison.
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$ARCHIVE" "$SOURCE_APP_DIR"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" \
  "$SYMBOL_ARCHIVE" "" "Fulmar.dSYMs"
mkdir -p "$TEMP_ROOT/extracted"
ditto -x -k "$ARCHIVE" "$TEMP_ROOT/extracted"
mkdir -p "$TEMP_ROOT/symbols"
ditto -x -k "$SYMBOL_ARCHIVE" "$TEMP_ROOT/symbols"
APP_DIR="$TEMP_ROOT/extracted/$APP_BUNDLE_NAME"
SYMBOL_ROOT="$TEMP_ROOT/symbols/Fulmar.dSYMs"
[[ -d "$APP_DIR" ]]
[[ -d "$SYMBOL_ROOT" ]]
[[ "$(find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "1" ]]
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$SOURCE_APP_DIR" "$APP_DIR"

# Every remaining gate runs against the archive extraction, not the build-tree
# copy. Passing therefore qualifies the bytes that would actually be installed.
INFO="$APP_DIR/Contents/Info.plist"
MIGRATION_XPC="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc"
MIGRATION_XPC_INFO="$MIGRATION_XPC/Contents/Info.plist"
MIGRATION_XPC_EXECUTABLE="$MIGRATION_XPC/Contents/MacOS/LocalHarnessCredentialMigrationService"
BROKER_XPC="$APP_DIR/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc"
BROKER_XPC_INFO="$BROKER_XPC/Contents/Info.plist"
BROKER_XPC_EXECUTABLE="$BROKER_XPC/Contents/MacOS/LocalHarnessCredentialBrokerService"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime"
DSH_ROOT="$RUNTIME_ROOT/dsh"
DSH_PACKAGE="$DSH_ROOT/package.json"
LOCKFILE="$RUNTIME_ROOT/package-lock.json"
SBOM="$APP_DIR/Contents/Resources/LocalHarness.sbom.cdx.json"
NOTICES="$APP_DIR/Contents/Resources/THIRD_PARTY_NOTICES.md"
NODE_LICENSE="$RUNTIME_ROOT/NODE_LICENSE"
LOCAL_ROOT="$DSH_ROOT/node_modules/@local-harness"
CREDENTIAL_PLUGIN="$LOCAL_ROOT/dsh-credentials-keychain"
FS_PLUGIN="$LOCAL_ROOT/dsh-fs-confined"
MCP_GUARD="$LOCAL_ROOT/dsh-mcp-guarded"
MCP_CLIENT="$DSH_ROOT/node_modules/@deepseek-ai/dsh-mcp-client/package.json"
CLIENT_SECURITY_BRIDGE="$LOCAL_ROOT/dsh-client-security-bridge"
PERFORMANCE_PROFILE="$LOCAL_ROOT/dsh-performance-profile"
WEB_FETCH_SAFE="$LOCAL_ROOT/dsh-web-fetch-safe"
"$INVENTORY_NODE" "$FIRST_PARTY_LICENSE_POLICY" verify-bundle \
  "$PROJECT_DIR" "$APP_DIR/Contents/Resources/LICENSE" >/dev/null

# Re-derive the complete unsigned assembly from the reviewed VendorRuntime and
# current six plugin sources, then scan the extracted archive Runtime against
# the exact final-byte inventory. Only the independently enumerated Mach-O paths
# may differ between those two manifests, and type/mode/path remain immutable.
"$INVENTORY_NODE" "$INVENTORY_TOOL" verify-derived \
  "$VENDOR_ROOT" "$VENDOR_INVENTORY" "$PROJECT_DIR" "$UNSIGNED_RUNTIME_INVENTORY"
"$INVENTORY_NODE" "$INVENTORY_TOOL" verify-signed-runtime \
  "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_ROOT" "$RUNTIME_SIGNABLES" "$FINAL_RUNTIME_INVENTORY"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-macho-compatibility.sh" \
  "$APP_DIR" "$RUNTIME_SIGNABLES" "$MINIMUM_MACOS"

verify_code_signature() {
  local target="$1"
  shift
  if [[ "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-0}" == "1" ]]; then
    LOCAL_HARNESS_ALLOW_PRIVATE_ROOT=1 /bin/zsh -f "$PROJECT_DIR/scripts/verify-code-signature.sh" "$target" "$@"
  else
    codesign --verify "$@" "$target"
  fi
}
verify_code_signature "$APP_DIR" --deep --strict
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" "$APP_DIR" "$SYMBOL_ROOT"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy-adversarial.sh" "$APP_DIR" "$SYMBOL_ROOT"
plutil -lint "$INFO" "$MIGRATION_XPC_INFO" "$BROKER_XPC_INFO" \
  "$APP_DIR/Contents/Library/LaunchAgents/com.angadjairath.localharness.scheduler.plist" >/dev/null
/usr/bin/plutil -convert json -o "$TEMP_ROOT/migration-xpc-info.json" "$MIGRATION_XPC_INFO"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/broker-xpc-info.json" "$BROKER_XPC_INFO"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$TEMP_ROOT/migration-xpc-info.json" "$TEMP_ROOT/broker-xpc-info.json"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$INFO")" == "$PRODUCT_BUNDLE_ID" ]]
[[ "$(plutil -extract CFBundleDisplayName raw -o - "$INFO")" == "$PRODUCT_DISPLAY_NAME" ]]
[[ "$(plutil -extract CFBundleName raw -o - "$INFO")" == "$PRODUCT_DISPLAY_NAME" ]]
[[ "$(plutil -extract CFBundleShortVersionString raw -o - "$INFO")" == "$PRODUCT_VERSION" ]]
[[ "$(plutil -extract CFBundleVersion raw -o - "$INFO")" == "$PRODUCT_BUILD" ]]
[[ "$(plutil -extract LSMinimumSystemVersion raw -o - "$INFO")" == "$MINIMUM_MACOS" ]]
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$MIGRATION_XPC_INFO")" == "$PRODUCT_BUNDLE_ID.credential-helper" \
   && "$(plutil -extract CFBundleExecutable raw -o - "$MIGRATION_XPC_INFO")" == "LocalHarnessCredentialMigrationService" \
   && "$(plutil -extract CFBundlePackageType raw -o - "$MIGRATION_XPC_INFO")" == "XPC!" \
   && "$(plutil -extract CFBundleShortVersionString raw -o - "$MIGRATION_XPC_INFO")" == "$PRODUCT_VERSION" \
   && "$(plutil -extract CFBundleVersion raw -o - "$MIGRATION_XPC_INFO")" == "$PRODUCT_BUILD" \
   && "$(plutil -extract LSMinimumSystemVersion raw -o - "$MIGRATION_XPC_INFO")" == "$MINIMUM_MACOS" ]]
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$BROKER_XPC_INFO")" == "$PRODUCT_BUNDLE_ID.credential-broker" \
   && "$(plutil -extract CFBundleExecutable raw -o - "$BROKER_XPC_INFO")" == "LocalHarnessCredentialBrokerService" \
   && "$(plutil -extract CFBundlePackageType raw -o - "$BROKER_XPC_INFO")" == "XPC!" \
   && "$(plutil -extract CFBundleShortVersionString raw -o - "$BROKER_XPC_INFO")" == "$PRODUCT_VERSION" \
   && "$(plutil -extract CFBundleVersion raw -o - "$BROKER_XPC_INFO")" == "$PRODUCT_BUILD" \
   && "$(plutil -extract LSMinimumSystemVersion raw -o - "$BROKER_XPC_INFO")" == "$MINIMUM_MACOS" ]]
[[ "$("$NODE" --version)" == "v$PINNED_NODE_VERSION" ]]
[[ "$("$NODE" -p "require('$DSH_PACKAGE').version")" == "$PINNED_DSH_VERSION" ]]
"$NODE" -e '
  const manifest = require(process.argv[1]);
  const expected = {
    "@local-harness/dsh-client-security-bridge": "1.2.1",
    "@local-harness/dsh-credentials-keychain": "1.0.8",
    "@local-harness/dsh-fs-confined": "1.0.0",
    "@local-harness/dsh-mcp-guarded": "1.0.0",
    "@local-harness/dsh-performance-profile": "1.2.0",
    "@local-harness/dsh-web-fetch-safe": "1.0.0"
  };
  const actual = Object.fromEntries(Object.entries(manifest.dependencies ?? {})
    .filter(([name]) => name.startsWith("@local-harness/")));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) process.exit(1);
' "$DSH_PACKAGE"
cmp -s "$PROJECT_DIR/VendorRuntime/package-lock.json" "$LOCKFILE"
cmp -s "$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/LICENSE" "$NODE_LICENSE"

for resource in Info.plist RuntimeSecurityPreload.mjs LocalHarness.patch.yml StrictLocal.sb MigrateCredentials.mjs ReleaseIdentity.json; do
  if [[ "$resource" == "Info.plist" ]]; then
    cmp -s "$PROJECT_DIR/Resources/$resource" "$APP_DIR/Contents/$resource"
  elif [[ "$resource" == "ReleaseIdentity.json" ]]; then
    cmp -s "$RELEASE_IDENTITY" "$APP_DIR/Contents/Resources/$resource"
  else
    cmp -s "$PROJECT_DIR/Resources/$resource" "$APP_DIR/Contents/Resources/$resource"
  fi
done
cmp -s "$PROJECT_DIR/Resources/com.angadjairath.localharness.scheduler.plist" "$APP_DIR/Contents/Library/LaunchAgents/com.angadjairath.localharness.scheduler.plist"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-app-icon.mjs" \
  "$APP_DIR/Contents/Resources/AppIcon.icns" "$PROJECT_DIR/Resources/FulmarAppIcon.png"

verify_entitlements() {
  local executable="$1"
  local expected="$2"
  local label="$3"
  local actual_plist="$TEMP_ROOT/${label}.entitlements.plist"
  local actual_stderr="$TEMP_ROOT/${label}.entitlements.stderr"
  local actual_json="$TEMP_ROOT/${label}.entitlements.json"
  local expected_json="$TEMP_ROOT/${label}.expected-entitlements.json"
  set +e
  codesign -d --xml --entitlements - "$executable" >"$actual_plist" 2>"$actual_stderr"
  local codesign_exit=$?
  set -e
  local unexpected_stderr
  unexpected_stderr="$(/usr/bin/sed -E '/^Executable=/d; /^[[:space:]]*$/d' "$actual_stderr")"
  if (( codesign_exit != 0 )) || [[ -n "$unexpected_stderr" || ! -s "$actual_plist" ]]; then
    print -u2 "Entitlement extraction was empty, failed, or emitted a warning: $label"
    /bin/cat "$actual_stderr" >&2
    return 1
  fi
  plutil -lint "$actual_plist" >/dev/null
  plutil -convert json -o "$actual_json" "$actual_plist"
  plutil -convert json -o "$expected_json" "$expected"
  "$NODE" -e '
    const fs=require("node:fs");
    const sort=(value)=>Array.isArray(value)?value.map(sort):value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map((key)=>[key,sort(value[key])])):value;
    const [actual,expected]=process.argv.slice(1).map((path)=>sort(JSON.parse(fs.readFileSync(path,"utf8"))));
    if(JSON.stringify(actual)!==JSON.stringify(expected)) process.exit(1);
  ' "$actual_json" "$expected_json"
}
verify_entitlements "$APP_DIR" "$PROJECT_DIR/Resources/LocalHarness.entitlements" app
verify_entitlements "$NODE" "$PROJECT_DIR/Resources/NodeRuntime.entitlements" node
verify_entitlements "$MIGRATION_XPC" \
  "$PROJECT_DIR/Resources/CredentialMigrationService.entitlements" migration-xpc
verify_entitlements "$BROKER_XPC" \
  "$PROJECT_DIR/Resources/CredentialBrokerService.entitlements" broker-xpc
APP_SIGNATURE_DETAILS="$(codesign -dvv "$APP_DIR" 2>&1)"
NODE_SIGNATURE_DETAILS="$(codesign -dvv "$NODE" 2>&1)"
[[ "$APP_SIGNATURE_DETAILS" == *flags=*runtime* ]]
[[ "$NODE_SIGNATURE_DETAILS" == *flags=*runtime* ]]

for helper in LocalHarnessCredentialHelper LocalHarnessSchedulerHelper LocalHarnessUpdateHelper LocalHarnessSandboxRunner LocalHarnessRuntimeLease; do
  verify_code_signature "$APP_DIR/Contents/MacOS/$helper" --strict
done
verify_code_signature "$MIGRATION_XPC" --strict
verify_code_signature "$MIGRATION_XPC_EXECUTABLE" --strict
verify_code_signature "$BROKER_XPC" --strict
verify_code_signature "$BROKER_XPC_EXECUTABLE" --strict
MIGRATION_XPC_SIGNATURE_DETAILS="$(codesign -dvv "$MIGRATION_XPC" 2>&1)"
[[ "$MIGRATION_XPC_SIGNATURE_DETAILS" == *"Identifier=$PRODUCT_BUNDLE_ID.credential-helper"* \
   && "$MIGRATION_XPC_SIGNATURE_DETAILS" == *flags=*runtime* ]]
BROKER_XPC_SIGNATURE_DETAILS="$(codesign -dvv "$BROKER_XPC" 2>&1)"
[[ "$BROKER_XPC_SIGNATURE_DETAILS" == *"Identifier=$PRODUCT_BUNDLE_ID.credential-helper"* \
   && "$BROKER_XPC_SIGNATURE_DETAILS" == *flags=*runtime* ]]
HELPER_DESIGNATED_REQUIREMENT="$(codesign -d -r- "$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper" 2>&1 \
  | sed -n 's/^designated => //p')"
SERVICE_DESIGNATED_REQUIREMENT="$(codesign -d -r- "$MIGRATION_XPC" 2>&1 \
  | sed -n 's/^designated => //p')"
BROKER_DESIGNATED_REQUIREMENT="$(codesign -d -r- "$BROKER_XPC" 2>&1 \
  | sed -n 's/^designated => //p')"
[[ -n "$HELPER_DESIGNATED_REQUIREMENT" \
   && "$SERVICE_DESIGNATED_REQUIREMENT" == "$HELPER_DESIGNATED_REQUIREMENT" \
   && "$BROKER_DESIGNATED_REQUIREMENT" == "$HELPER_DESIGNATED_REQUIREMENT" ]] || {
  print -u2 "The credential XPC services do not preserve the credential helper designated requirement."
  exit 1
}
if [[ "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-0}" == "1" ]]; then
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-stable-signing.sh" "$APP_DIR"
fi
verify_code_signature "$NODE" --strict
SIGNABLE_CANDIDATES="$TEMP_ROOT/signable-candidates.txt"
set +e
find "$APP_DIR/Contents" -type f \( -perm -111 -o -name '*.node' -o -name '*.dylib' \) \
  | sort > "$SIGNABLE_CANDIDATES"
SIGNABLE_PIPE_STATUS=("${pipestatus[@]}")
set -e
[[ "${SIGNABLE_PIPE_STATUS[1]}" == "0" && "${SIGNABLE_PIPE_STATUS[2]}" == "0" \
   && -f "$SIGNABLE_CANDIDATES" && ! -L "$SIGNABLE_CANDIDATES" \
   && "$(/usr/bin/stat -f '%z' "$SIGNABLE_CANDIDATES")" -ge 1 \
   && "$(/usr/bin/stat -f '%z' "$SIGNABLE_CANDIDATES")" -le 1048576 ]] || {
  print -u2 "Candidate executable inventory could not be materialized safely."
  exit 1
}
while IFS= read -r candidate; do
  FILE_KIND="$TEMP_ROOT/candidate-file-kind.txt"
  /usr/bin/file "$candidate" > "$FILE_KIND"
  set +e
  /usr/bin/grep -q 'Mach-O' "$FILE_KIND"
  MACHO_STATUS=$?
  set -e
  if (( MACHO_STATUS == 0 )); then
    verify_code_signature "$candidate" --strict
  elif (( MACHO_STATUS != 1 )); then
    print -u2 "Candidate executable type evidence could not be scanned safely."
    exit 1
  fi
done < "$SIGNABLE_CANDIDATES"

for directory in "$CREDENTIAL_PLUGIN" "$FS_PLUGIN" "$MCP_GUARD" "$CLIENT_SECURITY_BRIDGE" "$PERFORMANCE_PROFILE" "$WEB_FETCH_SAFE"; do
  [[ -d "$directory" && -f "$directory/package.json" ]]
done
[[ "$(find "$LOCAL_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" == "6" ]]
[[ "$(find "$LOCAL_ROOT" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "6" ]]
for expected in dsh-credentials-keychain dsh-fs-confined dsh-mcp-guarded dsh-client-security-bridge dsh-performance-profile dsh-web-fetch-safe; do [[ -d "$LOCAL_ROOT/$expected" ]]; done

for source in package.json index.mjs; do
  [[ -f "$CREDENTIAL_PLUGIN/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/credentials-keychain/$source" "$CREDENTIAL_PLUGIN/$source"
done
[[ "$(find "$CREDENTIAL_PLUGIN" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]]
[[ "$(find "$CREDENTIAL_PLUGIN" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "2" ]]
for source in package.json index.mjs; do
  [[ -f "$FS_PLUGIN/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/fs-confined/$source" "$FS_PLUGIN/$source"
done
[[ "$(find "$FS_PLUGIN" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]]
[[ "$(find "$FS_PLUGIN" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "2" ]]

[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$MCP_GUARD/package.json" 2>/dev/null)" == "@local-harness/dsh-mcp-guarded@1.0.0" ]]
[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$MCP_CLIENT" 2>/dev/null)" == "@deepseek-ai/dsh-mcp-client@$PINNED_DSH_MCP_CLIENT_VERSION" ]]
for source in package.json index.mjs catalog-core.mjs guarded-runtime.mjs wire-guard.mjs stdio-guard-runner.mjs; do
  [[ -f "$MCP_GUARD/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/mcp-guarded/$source" "$MCP_GUARD/$source"
done
[[ "$(find "$MCP_GUARD" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "6" ]]
[[ "$(find "$MCP_GUARD" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "6" ]]
[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$CLIENT_SECURITY_BRIDGE/package.json" 2>/dev/null)" == "@local-harness/dsh-client-security-bridge@1.2.1" ]]
for source in package.json index.mjs client.js; do
  [[ -f "$CLIENT_SECURITY_BRIDGE/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/client-security-bridge/$source" "$CLIENT_SECURITY_BRIDGE/$source"
  [[ "$source" == "package.json" ]] || "$NODE" --check "$CLIENT_SECURITY_BRIDGE/$source" >/dev/null
done
[[ "$(find "$CLIENT_SECURITY_BRIDGE" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "3" ]]
[[ "$(find "$CLIENT_SECURITY_BRIDGE" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "3" ]]
[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$PERFORMANCE_PROFILE/package.json" 2>/dev/null)" == "@local-harness/dsh-performance-profile@1.2.0" ]]
for source in package.json index.mjs; do
  [[ -f "$PERFORMANCE_PROFILE/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/performance-profile/$source" "$PERFORMANCE_PROFILE/$source"
  [[ "$source" == "package.json" ]] || "$NODE" --check "$PERFORMANCE_PROFILE/$source" >/dev/null
done
[[ "$(find "$PERFORMANCE_PROFILE" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]]
[[ "$(find "$PERFORMANCE_PROFILE" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "2" ]]

[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$WEB_FETCH_SAFE/package.json" 2>/dev/null)" == "@local-harness/dsh-web-fetch-safe@1.0.0" ]]
for source in package.json index.mjs; do
  [[ -f "$WEB_FETCH_SAFE/$source" ]]
  cmp -s "$PROJECT_DIR/Resources/DSHPlugins/web-fetch-safe/$source" "$WEB_FETCH_SAFE/$source"
  [[ "$source" == "package.json" ]] || "$NODE" --check "$WEB_FETCH_SAFE/$source" >/dev/null
done
[[ "$(find "$WEB_FETCH_SAFE" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]]
[[ "$(find "$WEB_FETCH_SAFE" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == "2" ]]

"$NODE" "$PROJECT_DIR/scripts/verify-sbom.mjs" \
  "$SBOM" "$RUNTIME_ROOT" "$PROJECT_DIR" \
  "dsh/node_modules/@local-harness/dsh-credentials-keychain/package.json" \
  "dsh/node_modules/@local-harness/dsh-fs-confined/package.json" \
  "dsh/node_modules/@local-harness/dsh-mcp-guarded/package.json" \
  "dsh/node_modules/@local-harness/dsh-client-security-bridge/package.json" \
  "dsh/node_modules/@local-harness/dsh-performance-profile/package.json" \
  "dsh/node_modules/@local-harness/dsh-web-fetch-safe/package.json"
"$NODE" "$PROJECT_DIR/scripts/generate-third-party-notices.mjs" \
  "$PROJECT_DIR/Resources/THIRD_PARTY_NOTICES.md" "$RUNTIME_ROOT" \
  "$PROJECT_DIR/Config/ThirdPartyLicenseOverrides.json" "$TEMP_ROOT/expected-notices.md"
cmp -s "$TEMP_ROOT/expected-notices.md" "$NOTICES"
"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" "$AUDIT_SUMMARY" "$LOCKFILE"

"$NODE" "$PROJECT_DIR/scripts/verify-sanitized-agent-presets.mjs" "$DSH_ROOT"
"$NODE" "$PROJECT_DIR/scripts/verify-packaged-policy.mjs" \
  "$APP_DIR/Contents/Resources/LocalHarness.patch.yml" \
  "$DSH_ROOT/config/agent-presets/standard/agent.cordis.yml" "$NOTICES"

for script in "$PROJECT_DIR"/Resources/*.mjs "$PROJECT_DIR"/Resources/DSHPlugins/*/*.mjs "$PROJECT_DIR"/scripts/*.mjs "$PROJECT_DIR"/Tests/JS/*.mjs; do
  /bin/zsh -f "$PROJECT_DIR/scripts/run-js-tests.sh" --check "$script" >/dev/null
done

# The live status-item acceptance tool is intentionally separate from the app
# package target. Compile it here with warnings promoted to errors so syntax or
# SDK regressions cannot pass the normal native suite unnoticed.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-status-item-live.sh" --compile-only

# Compile and execute the complete native suite with warnings promoted to
# failures. Dock/Apple-event interaction remains a separate manual row because
# it requires an interactive user session and cannot be inferred headlessly.
env \
  LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH="$ARCHIVE" \
  LOCAL_HARNESS_TEST_APP_PATH="$APP_DIR" \
  /bin/zsh -f "$PROJECT_DIR/scripts/run-swift-tests.sh"
"$INVENTORY_NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"

# Two JavaScript deployment-target tests inspect the exact SwiftPM product and
# test bundle produced above. Keep the complete JavaScript gate after native
# qualification so a clean checkout cannot borrow stale build products.
FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS=1 \
  /bin/zsh -f "$PROJECT_DIR/scripts/run-js-tests.sh" --test "$PROJECT_DIR"/Tests/JS/*.mjs
"$INVENTORY_NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"

# Kill only a separately compiled test probe at each coordinator checkpoint.
# The probe uses a private /tmp file-backed value store and never touches the
# real Keychain or the installed app. This is process-crash evidence, not a
# claim that SIGKILL reproduces physical power loss.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-transaction-crash.sh"

/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-helper.sh" "$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration.sh" "$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration-xpc.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-migration-xpc-live.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-broker-xpc.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-credential-broker-xpc-live.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-runtime-security.sh" "$APP_DIR"
# `verify-runtime-security.sh` already invokes the dedicated MCP runtime
# security matrix. Keep the independent, real Seatbelt/process-group matrix as
# an explicit extracted-candidate release gate as well.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-sandbox-runner.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-runtime-lease.sh" "$APP_DIR/Contents/MacOS/LocalHarnessRuntimeLease"
if [[ "$VERIFICATION_PROFILE" == "full-hardware" ]]; then
  THERMAL_RECOVERY_PROBE="$TEMP_ROOT/thermal-recovery-probe"
  /bin/zsh -f "$PROJECT_DIR/scripts/compile-thermal-recovery-probe.sh" "$THERMAL_RECOVERY_PROBE"
  # Exercise the exact app-owned Ollama supervisor from the extracted candidate,
  # including its random listener, signed-process checks, Seatbelt profile, one
  # real bounded generation, and Metal/MLX residency. The helper emits only
  # content-free evidence and stops the exact child before returning.
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-app-owned-ollama-generation.sh" "$APP_DIR"
  /usr/bin/env -u FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1 \
    /bin/bash -p "$PROJECT_DIR/scripts/wait-for-thermal-recovery.sh" \
      --live "$THERMAL_RECOVERY_PROBE" app-owned-generation
else
  print "Deterministic CI profile: the mandatory 48 GB physical-Qwen generation gate is explicitly not run."
fi
# macOS normally installs applications below a root-owned, admin-group-writable
# `/Applications` directory. Reproduce that otherwise easy-to-miss ancestor
# topology with a byte-identical copy. This caught a former canary fixture that
# incorrectly tried to approve the bundle's Node binary as a generic MCP command.
SIMULATED_APPLICATIONS="$TEMP_ROOT/Applications"
INSTALLED_LAYOUT_APP="$SIMULATED_APPLICATIONS/$APP_BUNDLE_NAME"
mkdir -p "$SIMULATED_APPLICATIONS"
chmod 0775 "$SIMULATED_APPLICATIONS"
cp -Rp "$APP_DIR" "$INSTALLED_LAYOUT_APP"
"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$APP_DIR" "$INSTALLED_LAYOUT_APP"
verify_code_signature "$INSTALLED_LAYOUT_APP" --deep --strict
"$INSTALLED_LAYOUT_APP/Contents/Resources/Runtime/node" \
  "$PROJECT_DIR/scripts/verify-dsh-web-rpc-canary.mjs" "$INSTALLED_LAYOUT_APP"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-cloned-state-security.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-simulated-provider-contract.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-simulated-provider-matrix.sh" "$APP_DIR"
if [[ "$VERIFICATION_PROFILE" == "full-hardware" ]]; then
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-dsh-qwen-route.sh" "$APP_DIR" bash
  /usr/bin/env -u FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1 \
    /bin/bash -p "$PROJECT_DIR/scripts/wait-for-thermal-recovery.sh" \
      --live "$THERMAL_RECOVERY_PROBE" bash
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-dsh-qwen-route.sh" "$APP_DIR" filesystem
  /usr/bin/env -u FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1 \
    /bin/bash -p "$PROJECT_DIR/scripts/wait-for-thermal-recovery.sh" \
      --live "$THERMAL_RECOVERY_PROBE" filesystem
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-dsh-qwen-route.sh" "$APP_DIR" project
  /usr/bin/env -u FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1 \
    /bin/bash -p "$PROJECT_DIR/scripts/wait-for-thermal-recovery.sh" \
      --live "$THERMAL_RECOVERY_PROBE" project
else
  print "Deterministic CI profile: the mandatory 48 GB physical-Qwen tool matrix is explicitly not run."
fi
# The former realistic Qwen stress canary repeatedly drove the 27B model for
# several minutes outside the native app, bypassing its adaptive thermal
# controller. Release qualification now proves the long workflow against the
# deterministic provider and limits real Qwen to the bounded tool matrix.

TEAM="$(codesign -dvv "$APP_DIR" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
if [[ -n "$TEAM" && "$TEAM" != "not set" ]]; then
  spctl --assess --type execute --verbose=2 "$APP_DIR"
fi

"$INVENTORY_NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$INVENTORY_NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"

"$INVENTORY_NODE" "$PROJECT_DIR/scripts/generate-ci-evidence-summary.mjs" \
  "$VERIFICATION_PROFILE" "$RELEASE_IDENTITY" "$MANIFEST" "$AUDIT_SUMMARY" "$CI_EVIDENCE_SUMMARY"

if [[ "$VERIFICATION_PROFILE" == "full-hardware" ]]; then
  echo "Release verification passed against the extracted archive: manifest-bound unchanged native source/test/build inputs, reviewed VendorRuntime inventory, independently derived unsigned assembly, exact signed Runtime byte inventory and Mach-O-only signing transition, bounded pre-extraction inventory, exact manifest/tree, signatures/entitlements, runtime/package graph, artifact-derived SBOM and notice-material inventory, a verified candidate-bound zero-vulnerability production dependency audit artifact, complete JavaScript and warning-clean native suites including deterministic adaptive-Eco and emergency thermal matrices, credential transactions, empty/cloned authenticated runtime confinement with sandbox/MCP checks, real Seatbelt/process-group isolation including bounded stderr and deadline cleanup, a real content-free app-owned Ollama generation with exact signed PID/listener checks and Metal/MLX residency, byte-identical group-writable-/Applications-layout authenticated typed web/RPC and WebSocket compatibility from clean isolated DSH homes including non-empty reviewed stdio MCP deny/allow-once/output/disposal and content-free bounded performance-telemetry evidence, simulated connected-provider contract and long-workflow coverage, credential-free candidate protocol matrix for DeepSeek chat completions, OpenAI Responses, Anthropic Messages, and a custom OpenAI-compatible route, and a thermally bounded real Qwen tool matrix. Interactive Dock quit/relaunch, legal clearance, and live cloud routes remain separate qualification rows."
else
  echo "Deterministic candidate verification passed against the extracted archive, including all credential-free packaged, archive, inventory, signature, entitlement, symbol, runtime, sandbox, MCP, credential-transaction, installed-layout, JavaScript, native, and simulated-provider/protocol gates. This is not final release qualification: the mandatory physical 48 GB Qwen/Ollama/Metal/thermal generation and tool gates were explicitly not run, and Developer ID/notarization, minimum-OS clean installation, interactive UX/permissions, live cloud providers, full Git history, and legal clearance remain external gates."
fi
