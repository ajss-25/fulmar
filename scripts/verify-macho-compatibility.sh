#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
if (( $# != 3 && $# != 4 )); then
  print -u2 "usage: verify-macho-compatibility.sh <app> <runtime-signables> <minimum-macos> [reviewed-node]"
  exit 1
fi
APP_DIR="$1"
SIGNABLES="$2"
DECLARED_MINIMUM="$3"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
BOOTSTRAP_NODE="${4:-$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node}"
INVENTORY_TOOL="$PROJECT_DIR/scripts/runtime-inventory.mjs"

fail() {
  print -u2 -- "$1"
  exit 1
}

version_code() {
  local value="$1"
  print -r -- "$value" | /usr/bin/awk -F. '
    NF != 2 && NF != 3 { exit 1 }
    {
      for (component_index = 1; component_index <= NF; component_index += 1) {
        if ($component_index !~ /^[0-9]+$/ || $component_index > 999) exit 1
      }
      patch = NF == 3 ? $3 : 0
      printf "%.0f\n", ($1 * 1000000) + ($2 * 1000) + patch
    }
  '
}

extract_macos_minimum() {
  local candidate="$1"
  local architecture="$2"
  local metadata result
  metadata="$(/usr/bin/vtool -arch "$architecture" -show "$candidate")" || return 1
  result="$(print -r -- "$metadata" | /usr/bin/awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" {
      count += 1; kind = "build"; next
    }
    $1 == "cmd" && $2 == "LC_VERSION_MIN_MACOSX" {
      count += 1; kind = "legacy"; platform = "MACOS"; next
    }
    kind == "build" && $1 == "platform" { platform = $2; next }
    kind == "build" && $1 == "minos" { version = $2; kind = ""; next }
    kind == "legacy" && $1 == "version" { version = $2; kind = ""; next }
    END {
      if (count != 1 || platform == "" || version == "") exit 2
      printf "%s|%s\n", platform, version
    }
  ')" || return 1
  print -r -- "$result"
}

verify_binary() {
  local candidate="$1"
  local label="$2"
  local expected_architecture="$3"
  [[ -f "$candidate" && ! -L "$candidate" ]] || fail "Mach-O compatibility target is missing or linked: $label"
  /usr/bin/file "$candidate" | /usr/bin/grep -q 'Mach-O' || fail "Compatibility target is not Mach-O: $label"

  local architectures
  architectures="$(/usr/bin/lipo -archs "$candidate")" || fail "Could not read Mach-O architectures: $label"
  [[ "$architectures" == "$expected_architecture" ]] || {
    fail "Unexpected Mach-O architecture for $label: expected $expected_architecture, found $architectures"
  }

  local metadata platform minimum minimum_code
  metadata="$(extract_macos_minimum "$candidate" "$expected_architecture")" || {
    fail "Mach-O target has missing, duplicate, or unsupported minimum-system metadata: $label"
  }
  IFS='|' read -r platform minimum <<< "$metadata"
  [[ "$platform" == "MACOS" ]] || fail "Mach-O target is not built for macOS: $label"
  minimum_code="$(version_code "$minimum")" || fail "Mach-O target has an invalid minimum-system version: $label"
  (( minimum_code <= declared_minimum_code )) || {
    fail "$label requires macOS $minimum, which exceeds Fulmar's declared minimum macOS $DECLARED_MINIMUM"
  }
  print -r -- "$label\t$expected_architecture\tmacOS $minimum"
}

[[ -d "$APP_DIR" && ! -L "$APP_DIR" ]] || fail "Missing canonical application bundle for Mach-O compatibility verification."
[[ -f "$SIGNABLES" && ! -L "$SIGNABLES" ]] || fail "Missing Runtime Mach-O inventory."
[[ -f "$RELEASE_IDENTITY" && "$BOOTSTRAP_NODE" == /* \
   && -f "$BOOTSTRAP_NODE" && ! -L "$BOOTSTRAP_NODE" && -x "$BOOTSTRAP_NODE" \
   && "${BOOTSTRAP_NODE:A}" == "$BOOTSTRAP_NODE" && -f "$INVENTORY_TOOL" ]] \
  || fail "Missing reviewed compatibility-verifier inputs."
identity_minimum="$(plutil -extract minimumMacOS raw -o - "$RELEASE_IDENTITY")"
[[ "$identity_minimum" == "$DECLARED_MINIMUM" ]] || fail "Compatibility verifier minimum does not match ReleaseIdentity.json."
declared_minimum_code="$(version_code "$DECLARED_MINIMUM")" || fail "ReleaseIdentity.json has an invalid minimum macOS version."
pinned_node_sha="$(plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
actual_node_sha="$(/usr/bin/shasum -a 256 "$BOOTSTRAP_NODE" | /usr/bin/awk '{print $1}')"
[[ "$actual_node_sha" == "$pinned_node_sha" ]] || fail "The compatibility verifier's bootstrap Node is not the reviewed executable."

typeset -a native_products runtime_paths
native_products=(
  LocalHarness
  LocalHarnessCredentialHelper
  LocalHarnessRuntimeLease
  LocalHarnessSandboxRunner
  LocalHarnessSchedulerHelper
  LocalHarnessUpdateHelper
)
runtime_output="$($BOOTSTRAP_NODE "$INVENTORY_TOOL" emit-signables "$SIGNABLES")" \
  || fail "Runtime Mach-O inventory could not be decoded."
runtime_paths=()
while IFS= read -r relative_path; do
  [[ -n "$relative_path" ]] && runtime_paths+=("$relative_path")
done < <(print -r -- "$runtime_output")
(( ${#runtime_paths} > 0 )) || fail "Runtime Mach-O inventory is empty."

native_entry_count="$(/usr/bin/find "$APP_DIR/Contents/MacOS" -mindepth 1 -maxdepth 1 -print \
  | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
(( native_entry_count == ${#native_products} )) || fail "Contents/MacOS does not contain exactly the six reviewed native products."
for product in "${native_products[@]}"; do
  verify_binary "$APP_DIR/Contents/MacOS/$product" "Contents/MacOS/$product" arm64
done
verify_binary \
  "$APP_DIR/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService" \
  "Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService" \
  arm64
verify_binary \
  "$APP_DIR/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/MacOS/LocalHarnessCredentialBrokerService" \
  "Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/MacOS/LocalHarnessCredentialBrokerService" \
  arm64

documented_x86_runtime() {
  case "$1" in
    dsh/node_modules/node-pty/prebuilds/darwin-x64/pty.node|\
    dsh/node_modules/node-pty/prebuilds/darwin-x64/spawn-helper) return 0 ;;
    *) return 1 ;;
  esac
}
for relative_path in "${runtime_paths[@]}"; do
  expected_architecture=arm64
  documented_x86_runtime "$relative_path" && expected_architecture=x86_64
  verify_binary \
    "$APP_DIR/Contents/Resources/Runtime/$relative_path" \
    "Contents/Resources/Runtime/$relative_path" \
    "$expected_architecture"
done

print "Verified ${#native_products} top-level native products, two private XPC services, and ${#runtime_paths} inventoried Runtime Mach-O files: exact architectures and every embedded minimum-system version are compatible with declared macOS $DECLARED_MINIMUM."
