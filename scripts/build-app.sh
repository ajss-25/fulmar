#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
BUILD_MODE="production"
UNSIGNED_REPRODUCIBILITY_ROOT=""
if (( $# != 0 )); then
  if (( $# == 2 )) && [[ "$1" == "--unsigned-reproducibility-root" && -n "$2" ]]; then
    BUILD_MODE="unsigned-reproducibility"
    UNSIGNED_REPRODUCIBILITY_ROOT="$2"
  else
    print -u2 "usage: build-app.sh [--unsigned-reproducibility-root /private/tmp/fulmar-two-root-repro.XXXXXX/capture-a|capture-b]"
    exit 64
  fi
fi
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 7200 --max-rss-bytes 34359738368 --rss-grace-seconds 15 \
    --emergency-rss-bytes 42949672960 \
    --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete Fulmar build" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The Fulmar build inherited an invalid root-watchdog capability."
  exit 1
fi

SAFE_RELEASE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
if [[ "${LOCAL_HARNESS_CLEAN_RELEASE_ENVIRONMENT:-0}" != "1" ]]; then
  release_home="${HOME:-}"
  release_user="$(/usr/bin/id -un)"
  [[ "$release_home" == /* && -d "$release_home" && ! -L "$release_home" \
     && "$release_home" != *$'\n'* && "$release_home" != *$'\r'* ]] || {
    print -u2 "Release builds require one real absolute user home for Keychain access."
    exit 1
  }
  typeset -a clean_environment
  clean_environment=(
    "HOME=$release_home"
    "CFFIXED_USER_HOME=$release_home"
    "TMPDIR=/private/tmp/"
    "PATH=$SAFE_RELEASE_PATH"
    "USER=$release_user"
    "LOGNAME=$release_user"
    "LANG=en_US.UTF-8"
    "LC_CTYPE=UTF-8"
    "LOCAL_HARNESS_CLEAN_RELEASE_ENVIRONMENT=1"
    "FULMAR_INTERNAL_WATCHDOG_DEPTH=$FULMAR_INTERNAL_WATCHDOG_DEPTH"
    "FULMAR_ROOT_WATCHDOG_PGID_V1=$FULMAR_ROOT_WATCHDOG_PGID_V1"
    "FULMAR_ROOT_WATCHDOG_PID_V1=$FULMAR_ROOT_WATCHDOG_PID_V1"
    "FULMAR_ROOT_WATCHDOG_CAPABILITY_V1=$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1"
    "FULMAR_ROOT_WATCHDOG_NONCE_V1=$FULMAR_ROOT_WATCHDOG_NONCE_V1"
    "FULMAR_ROOT_WATCHDOG_FD_V1=$FULMAR_ROOT_WATCHDOG_FD_V1"
  )
  for forwarded_name in \
    LOCAL_HARNESS_REQUIRE_STABLE_SIGNING \
    LOCAL_HARNESS_SIGN_IDENTITY \
    LOCAL_HARNESS_SIGNING_KEYCHAIN \
    LOCAL_HARNESS_SIGN_TIMESTAMP \
    LOCAL_HARNESS_NOTARY_PROFILE; do
    case "$forwarded_name" in
      LOCAL_HARNESS_REQUIRE_STABLE_SIGNING) forwarded_value="${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-}" ;;
      LOCAL_HARNESS_SIGN_IDENTITY) forwarded_value="${LOCAL_HARNESS_SIGN_IDENTITY:-}" ;;
      LOCAL_HARNESS_SIGNING_KEYCHAIN) forwarded_value="${LOCAL_HARNESS_SIGNING_KEYCHAIN:-}" ;;
      LOCAL_HARNESS_SIGN_TIMESTAMP) forwarded_value="${LOCAL_HARNESS_SIGN_TIMESTAMP:-}" ;;
      LOCAL_HARNESS_NOTARY_PROFILE) forwarded_value="${LOCAL_HARNESS_NOTARY_PROFILE:-}" ;;
      *) print -u2 "Unreviewed release-build option: $forwarded_name"; exit 1 ;;
    esac
    if [[ -n "$forwarded_value" ]]; then
      [[ "${#forwarded_value}" -le 512 \
         && "$forwarded_value" != *$'\n'* && "$forwarded_value" != *$'\r'* ]] || {
        print -u2 "Unsafe release-build option: $forwarded_name"
        exit 1
      }
      clean_environment+=("$forwarded_name=$forwarded_value")
    fi
  done
  exec /usr/bin/env -i "${clean_environment[@]}" /bin/zsh -f "${0:A}" "$@"
fi
[[ "$PATH" == "$SAFE_RELEASE_PATH" && "$TMPDIR" == "/private/tmp/" \
   && -z "${DEVELOPER_DIR:-}" && -z "${SDKROOT:-}" ]] || {
  print -u2 "The production build did not start inside the exact clean release environment."
  exit 1
}
if [[ "$BUILD_MODE" == "unsigned-reproducibility" \
   && ( -n "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-}" \
     || -n "${LOCAL_HARNESS_SIGN_IDENTITY:-}" \
     || -n "${LOCAL_HARNESS_SIGNING_KEYCHAIN:-}" \
     || -n "${LOCAL_HARNESS_SIGN_TIMESTAMP:-}" \
     || -n "${LOCAL_HARNESS_NOTARY_PROFILE:-}" ) ]]; then
  print -u2 "Unsigned reproducibility builds reject every signing, Keychain, timestamp, and notarization option."
  exit 64
fi
umask 077
unexpected_environment="$(/usr/bin/env \
  | /usr/bin/sed -E \
    '/^(CFFIXED_USER_HOME|FULMAR_INTERNAL_WATCHDOG_DEPTH|FULMAR_ROOT_WATCHDOG_CAPABILITY_V1|FULMAR_ROOT_WATCHDOG_FD_V1|FULMAR_ROOT_WATCHDOG_NONCE_V1|FULMAR_ROOT_WATCHDOG_PGID_V1|FULMAR_ROOT_WATCHDOG_PID_V1|HOME|LANG|LC_CTYPE|LOCAL_HARNESS_CLEAN_RELEASE_ENVIRONMENT|LOCAL_HARNESS_NOTARY_PROFILE|LOCAL_HARNESS_REQUIRE_STABLE_SIGNING|LOCAL_HARNESS_SIGN_IDENTITY|LOCAL_HARNESS_SIGNING_KEYCHAIN|LOCAL_HARNESS_SIGN_TIMESTAMP|LOGNAME|OLDPWD|PATH|PWD|SHLVL|TMPDIR|USER|_)=/d; s/=.*$//')"
[[ -z "$unexpected_environment" ]] || {
  print -u2 "The production build inherited an unreviewed environment variable: ${unexpected_environment%%$'\n'*}"
  exit 1
}

fulmar_root_watchdog_state || {
  print -u2 "The production build lost its root-watchdog capability."
  exit 1
}
source "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh"
source "$PROJECT_DIR/scripts/release-command-gate.zsh"
source "$PROJECT_DIR/scripts/release-lock.zsh"
source "$PROJECT_DIR/scripts/build-scratch-root.zsh"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
[[ -f "$RELEASE_IDENTITY" ]] || { echo "Missing release identity." >&2; exit 1; }
if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]; then
  OUTPUT_ROOT="$UNSIGNED_REPRODUCIBILITY_ROOT"
  BUILD_OUTPUT_DIR="$OUTPUT_ROOT/BuildEvidence"
else
  OUTPUT_ROOT="/private/tmp/LocalHarnessBuild"
  BUILD_OUTPUT_DIR="$PROJECT_DIR/build"
fi
APP_BUNDLE_NAME="$(plutil -extract applicationBundleName raw -o - "$RELEASE_IDENTITY")"
ARCHIVE_NAME="$(plutil -extract releaseArchiveName raw -o - "$RELEASE_IDENTITY")"
SYMBOL_ARCHIVE_NAME="$(plutil -extract symbolsArchiveName raw -o - "$RELEASE_IDENTITY")"
APP_DIR="$OUTPUT_ROOT/$APP_BUNDLE_NAME"
ARCHIVE_PATH="$BUILD_OUTPUT_DIR/$ARCHIVE_NAME"
SYMBOL_ROOT="$OUTPUT_ROOT/Fulmar.dSYMs"
SYMBOL_ARCHIVE_PATH="$BUILD_OUTPUT_DIR/$SYMBOL_ARCHIVE_NAME"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
SBOM_PATH="$RESOURCES_DIR/LocalHarness.sbom.cdx.json"
LAUNCH_AGENTS_DIR="$CONTENTS_DIR/Library/LaunchAgents"
XPC_SERVICES_DIR="$CONTENTS_DIR/XPCServices"
MIGRATION_XPC_DIR="$XPC_SERVICES_DIR/LocalHarnessCredentialMigrationService.xpc"
MIGRATION_XPC_MACOS_DIR="$MIGRATION_XPC_DIR/Contents/MacOS"
BROKER_XPC_DIR="$XPC_SERVICES_DIR/LocalHarnessCredentialBrokerService.xpc"
BROKER_XPC_MACOS_DIR="$BROKER_XPC_DIR/Contents/MacOS"
RUNTIME_DIR="$RESOURCES_DIR/Runtime"
ICONSET_DIR=""
RENDERED_ICON="$PROJECT_DIR/Resources/FulmarAppIcon.png"
SWIFTPM_CACHE_DIR=""
SWIFTPM_CONFIG_DIR=""
SWIFTPM_SECURITY_DIR=""
CLANG_CACHE_DIR=""
SWIFT_SOURCE_ROOT=""
BUILD_SCRATCH=""
BUILD_SCRATCH_IDENTITY=""
HOST_TEMP_ROOT="${TMPDIR:-/private/tmp}"
HOST_TEMP_ROOT="${HOST_TEMP_ROOT%/}"
VENDOR_ROOT="$PROJECT_DIR/VendorRuntime"
VENDOR_INVENTORY="$PROJECT_DIR/VendorRuntime.inventory.json"
NODE_BIN="$VENDOR_ROOT/node-v22.23.1-darwin-arm64/bin/node"
DSH_DIR="$VENDOR_ROOT/node_modules/@deepseek-ai/dsh"
INVENTORY_TOOL="$PROJECT_DIR/scripts/runtime-inventory.mjs"
UNSIGNED_RUNTIME_INVENTORY="$BUILD_OUTPUT_DIR/runtime-unsigned-inventory.json"
RUNTIME_SIGNABLES="$BUILD_OUTPUT_DIR/runtime-signables.json"
FINAL_RUNTIME_INVENTORY="$BUILD_OUTPUT_DIR/runtime-release-inventory.json"
SOURCE_INPUT_INVENTORY="$BUILD_OUTPUT_DIR/source-build-inputs.json"
SOURCE_INPUT_TOOL="$PROJECT_DIR/scripts/source-build-input-inventory.mjs"
if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]; then
  # The root checkout's complete static gate produces this source-bound summary
  # before either clean clone is compiled. Each clone is then re-inventoried and
  # the summary is independently rebound to those exact bytes below.
  STATIC_SECURITY_SUMMARY="$PROJECT_DIR/build/static-security-summary.json"
else
  STATIC_SECURITY_SUMMARY="$BUILD_OUTPUT_DIR/static-security-summary.json"
fi
STATIC_SECURITY_VERIFIER="$PROJECT_DIR/scripts/verify-static-security-summary.mjs"
FIRST_PARTY_LICENSE_POLICY="$PROJECT_DIR/scripts/first-party-license-policy.mjs"
TOOLCHAIN_INVENTORY="$BUILD_OUTPUT_DIR/toolchain-inventory.json"
TOOLCHAIN_TOOL="$PROJECT_DIR/scripts/toolchain-inventory.mjs"
CI_EVIDENCE_SUMMARY="$BUILD_OUTPUT_DIR/ci-evidence-summary.json"
NOTARY_SUBMISSION_EVIDENCE="$BUILD_OUTPUT_DIR/notarization-submission.json"
NOTARY_LOG_EVIDENCE="$BUILD_OUTPUT_DIR/notarization-log.json"
UNSIGNED_REPRODUCIBILITY_INVENTORY="$BUILD_OUTPUT_DIR/unsigned-reproducibility-inventory.json"
UNSIGNED_REPRODUCIBILITY_TOOL="$PROJECT_DIR/scripts/unsigned-reproducibility-inventory.mjs"
PRODUCT_DISPLAY_NAME="$(plutil -extract productDisplayName raw -o - "$RELEASE_IDENTITY")"
PRODUCT_BUNDLE_ID="$(plutil -extract bundleIdentifier raw -o - "$RELEASE_IDENTITY")"
PRODUCT_VERSION="$(plutil -extract appVersion raw -o - "$RELEASE_IDENTITY")"
PRODUCT_BUILD="$(plutil -extract appBuild raw -o - "$RELEASE_IDENTITY")"
MINIMUM_MACOS="$(plutil -extract minimumMacOS raw -o - "$RELEASE_IDENTITY")"
PINNED_NODE_VERSION="$(plutil -extract runtime.nodeVersion raw -o - "$RELEASE_IDENTITY")"
PINNED_NODE_SHA256="$(plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
PINNED_DSH_VERSION="$(plutil -extract runtime.deepseekHarnessVersion raw -o - "$RELEASE_IDENTITY")"

fulmar_acquire_release_lock "Fulmar build" || exit
cleanup_lock() {
  local exit_code="${1:-$?}"
  local cleanup_status=0
  if [[ -n "$BUILD_SCRATCH" ]]; then
    if fulmar_remove_current_build_scratch_root \
      "$BUILD_SCRATCH" "/private/tmp" "$FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX" "$BUILD_SCRATCH_IDENTITY"; then
      BUILD_SCRATCH=""
      BUILD_SCRATCH_IDENTITY=""
    else
      print -u2 "The build could not safely remove its exact attested scratch root."
      cleanup_status=126
    fi
  fi
  fulmar_release_release_lock
  (( cleanup_status == 0 )) || return "$cleanup_status"
  return "$exit_code"
}
on_signal() {
  local exit_code="$1"
  trap - EXIT HUP INT TERM
  cleanup_lock "$exit_code" || true
  exit "$exit_code"
}
trap cleanup_lock EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# The authenticated outer watchdog owns the release lock, so no legitimate
# build can still be creating or using this namespace while recovery runs.
# Unmarked legacy roots are retained for manual review; only an exact attested
# inode with a dead birth identity and expired watchdog capability is removed.
fulmar_recover_stale_build_scratch_roots \
  "/private/tmp" "$FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX" || exit

if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]; then
  capture_parent="${OUTPUT_ROOT:h}"
  capture_parent_name="${capture_parent:t}"
  capture_nonce="${capture_parent_name#fulmar-two-root-repro.}"
  capture_leaf="${OUTPUT_ROOT:t}"
  [[ "${capture_parent:h}" == "/private/tmp" \
     && "$capture_parent_name" == "fulmar-two-root-repro.$capture_nonce" \
     && "${#capture_nonce}" == 6 && "$capture_nonce" != *[^A-Za-z0-9]* \
     && ( "$capture_leaf" == "capture-a" || "$capture_leaf" == "capture-b" ) \
     && "$OUTPUT_ROOT" == "$capture_parent/$capture_leaf" \
     && -d "$capture_parent" && ! -L "$capture_parent" \
     && -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" \
     && "${capture_parent:A}" == "$capture_parent" \
     && "${OUTPUT_ROOT:A}" == "$OUTPUT_ROOT" \
     && "$(/usr/bin/stat -f '%u:%Lp' "$capture_parent")" == "$(/usr/bin/id -u):700" \
     && "$(/usr/bin/stat -f '%u:%Lp' "$OUTPUT_ROOT")" == "$(/usr/bin/id -u):700" ]] || {
    print -u2 "The unsigned reproducibility output is not an exact private capture root."
    exit 64
  }
fi

if [[ -e "$OUTPUT_ROOT" || -L "$OUTPUT_ROOT" ]]; then
  [[ -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" \
     && "$(/usr/bin/stat -f '%u' "$OUTPUT_ROOT")" == "$(/usr/bin/id -u)" \
     && "${OUTPUT_ROOT:A}" == "$OUTPUT_ROOT" ]] || {
    echo "The fixed Fulmar output root is not an owner-controlled real directory." >&2
    exit 1
  }
  /bin/chmod 0700 "$OUTPUT_ROOT"
else
  /bin/mkdir -m 0700 "$OUTPUT_ROOT"
fi
[[ "$(/usr/bin/stat -f '%u:%Lp' "$OUTPUT_ROOT")" == "$(/usr/bin/id -u):700" ]] || {
  echo "The Fulmar output root is not private." >&2
  exit 1
}

if [[ -e "$BUILD_OUTPUT_DIR" || -L "$BUILD_OUTPUT_DIR" ]]; then
  [[ -d "$BUILD_OUTPUT_DIR" && ! -L "$BUILD_OUTPUT_DIR" \
     && "${BUILD_OUTPUT_DIR:A}" == "$BUILD_OUTPUT_DIR" \
     && "$(/usr/bin/stat -f '%u' "$BUILD_OUTPUT_DIR")" == "$(/usr/bin/id -u)" ]] || {
    echo "The release-artifact root is not an owner-controlled real directory." >&2
    exit 1
  }
  /bin/chmod 0700 "$BUILD_OUTPUT_DIR"
else
  /bin/mkdir -m 0700 "$BUILD_OUTPUT_DIR"
fi
[[ "$(/usr/bin/stat -f '%u:%Lp' "$BUILD_OUTPUT_DIR")" == "$(/usr/bin/id -u):700" ]] || {
  echo "The release-artifact root is not private." >&2
  exit 1
}
typeset -a generated_release_outputs
generated_release_outputs=(
  "$ARCHIVE_PATH"
  "$SYMBOL_ARCHIVE_PATH"
  "$BUILD_OUTPUT_DIR/release-manifest.json"
  "$UNSIGNED_RUNTIME_INVENTORY"
  "$RUNTIME_SIGNABLES"
  "$FINAL_RUNTIME_INVENTORY"
  "$SOURCE_INPUT_INVENTORY"
  "$TOOLCHAIN_INVENTORY"
  "$CI_EVIDENCE_SUMMARY"
  "$NOTARY_SUBMISSION_EVIDENCE"
  "$NOTARY_LOG_EVIDENCE"
)
if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]; then
  generated_release_outputs+=("$UNSIGNED_REPRODUCIBILITY_INVENTORY")
fi
for generated_output in "${generated_release_outputs[@]}"; do
  if [[ -e "$generated_output" || -L "$generated_output" ]]; then
    [[ -f "$generated_output" && ! -L "$generated_output" \
       && "$(/usr/bin/stat -f '%u:%l' "$generated_output")" == "$(/usr/bin/id -u):1" ]] || {
      echo "Refusing an unsafe pre-existing release output: ${generated_output:t}" >&2
      exit 1
    }
    /bin/rm -f -- "$generated_output"
  fi
done

# Bootstrap the verifier with a system SHA-256 check of the exact reviewed Node
# executable. The executable cannot be allowed to attest to itself before this
# independent digest matches. Production assembly never accepts ambient runtime
# overrides.
if [[ -n "${LOCAL_HARNESS_NODE_BIN:-}" || -n "${LOCAL_HARNESS_DSH_DIR:-}" ]]; then
  echo "Runtime overrides are not permitted for a production Fulmar bundle." >&2
  exit 1
fi
[[ -x "$NODE_BIN" && -f "$DSH_DIR/lib/bin.js" && -f "$VENDOR_INVENTORY" ]] || {
  echo "The complete pinned and inventoried VendorRuntime is required." >&2
  exit 1
}
ACTUAL_NODE_SHA256="$(/usr/bin/shasum -a 256 "$NODE_BIN" | /usr/bin/awk '{print $1}')"
if [[ "$ACTUAL_NODE_SHA256" != "$PINNED_NODE_SHA256" ]]; then
  echo "The vendored Node bootstrap digest is not the reviewed value." >&2
  exit 1
fi
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-source-product-contract.mjs" "$PROJECT_DIR"
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-deepseek-runtime-contract.mjs" "$PROJECT_DIR"
"$NODE_BIN" "$FIRST_PARTY_LICENSE_POLICY" state "$PROJECT_DIR" >/dev/null
"$NODE_BIN" "$INVENTORY_TOOL" verify "$VENDOR_ROOT" "$VENDOR_INVENTORY" VendorRuntime

# Bind every native source, test, resource, and release-script input before the
# compiler runs. The same inventory is rechecked after compilation and before
# publication so a later source tree can never qualify an older executable.
"$NODE_BIN" "$SOURCE_INPUT_TOOL" create "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
[[ -f "$STATIC_SECURITY_SUMMARY" && -s "$STATIC_SECURITY_SUMMARY" && ! -L "$STATIC_SECURITY_SUMMARY" ]] || {
  echo "A fresh passing static-security summary is mandatory before candidate assembly." >&2
  exit 1
}
"$NODE_BIN" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
BUILD_OWNER_STARTED="$(/bin/ps -p $$ -o lstart=)" || exit 126
BUILD_CREATED_EPOCH="$(/bin/date +%s)" || exit 126
BUILD_SCRATCH="$(mktemp -d /private/tmp/local-harness-swift-build.XXXXXX)"
BUILD_SCRATCH_IDENTITY="$(fulmar_build_scratch_root_identity "$BUILD_SCRATCH")" || {
  print -u2 "The fresh Swift build root identity could not be captured."
  exit 126
}
[[ -d "$BUILD_SCRATCH" && ! -L "$BUILD_SCRATCH" \
   && "$BUILD_SCRATCH_IDENTITY" == *":$(/usr/bin/id -u):Directory:700" \
   && "$(fulmar_build_scratch_root_identity "$BUILD_SCRATCH")" == "$BUILD_SCRATCH_IDENTITY" ]] || {
  echo "The fresh Swift build root is not private." >&2
  exit 1
}
PUBLISHED_BUILD_SCRATCH_IDENTITY="$(fulmar_attest_new_build_scratch_root \
  "$BUILD_SCRATCH" "/private/tmp" "$FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX" \
  "$BUILD_SCRATCH_IDENTITY" "$$" "$BUILD_OWNER_STARTED" "$BUILD_CREATED_EPOCH" \
  "$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1" "$FULMAR_ROOT_WATCHDOG_NONCE_V1" \
  "$FULMAR_ROOT_WATCHDOG_PID_V1")" || {
  print -u2 "The fresh Swift build root could not be bound to its exact owner and inode."
  exit 126
}
[[ "$PUBLISHED_BUILD_SCRATCH_IDENTITY" == "$BUILD_SCRATCH_IDENTITY" ]] || exit 126
SWIFT_SOURCE_ROOT="$BUILD_SCRATCH/canonical-source"
SWIFTPM_CACHE_DIR="$BUILD_SCRATCH/swiftpm-cache"
SWIFTPM_CONFIG_DIR="$BUILD_SCRATCH/swiftpm-config"
SWIFTPM_SECURITY_DIR="$BUILD_SCRATCH/swiftpm-security"
CLANG_CACHE_DIR="$BUILD_SCRATCH/clang-module-cache"
ICONSET_DIR="$BUILD_SCRATCH/AppIcon.iconset"
"$NODE_BIN" "$TOOLCHAIN_TOOL" create "$TOOLCHAIN_INVENTORY"

/bin/mkdir -m 0700 "$SWIFT_SOURCE_ROOT" "$SWIFTPM_CACHE_DIR" "$SWIFTPM_CONFIG_DIR" \
  "$SWIFTPM_SECURITY_DIR" "$CLANG_CACHE_DIR"

# Swift 6.3.3's non-escaping closure diagnostics remap the source-path bytes but
# retain the pre-remap absolute-path length in generated machine code. Compile
# from this private, inventory-identical location under the fixed-length scratch
# namespace so a checkout's spelling cannot change the executable. Keeping the
# runtime diagnostics enabled is intentional; the source snapshot removes the
# nondeterministic input instead of weakening Swift's safety checks.
typeset -a source_snapshot_roots
source_snapshot_roots=(
  Package.swift
  Makefile
  .gitattributes
  .gitignore
  .github
  LICENSE
  README.md
  CHANGELOG.md
  CONTRIBUTING.md
  SECURITY.md
  SUPPORT.md
  docs
  Config
  Sources
  Tools
  Tests
  scripts
  Resources
  VendorRuntime.inventory.json
  VendorRuntime/package.json
  VendorRuntime/package-lock.json
)
/bin/mkdir -m 0755 "$SWIFT_SOURCE_ROOT/VendorRuntime"
for source_root in "${source_snapshot_roots[@]}"; do
  if [[ ! -e "$PROJECT_DIR/$source_root" ]]; then
    [[ "$source_root" == "LICENSE" ]] && continue
    print -u2 "A required source-snapshot root disappeared: $source_root"
    exit 1
  fi
  /usr/bin/ditto --norsrc --noextattr --noacl --noqtn \
    "$PROJECT_DIR/$source_root" "$SWIFT_SOURCE_ROOT/$source_root"
done
"$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$SWIFT_SOURCE_ROOT" "$SOURCE_INPUT_INVENTORY"

export CLANG_MODULE_CACHE_PATH="$CLANG_CACHE_DIR"
typeset -a swift_release_command
swift_release_command=(swift build \
  --package-path "$SWIFT_SOURCE_ROOT" \
  --disable-sandbox \
  --scratch-path "$BUILD_SCRATCH" \
  --cache-path "$SWIFTPM_CACHE_DIR" \
  --config-path "$SWIFTPM_CONFIG_DIR" \
  --security-path "$SWIFTPM_SECURITY_DIR" \
  --jobs 1 \
  -c release \
  -debug-info-format none \
  -Xswiftc -warnings-as-errors \
  -Xswiftc -prefix-serialized-debugging-options \
  -Xswiftc -file-prefix-map \
  -Xswiftc "$SWIFT_SOURCE_ROOT=/Fulmar/Sources" \
  -Xswiftc -debug-prefix-map \
  -Xswiftc "$SWIFT_SOURCE_ROOT=/Fulmar/Sources" \
  -Xswiftc -file-prefix-map \
  -Xswiftc "$PROJECT_DIR=/Fulmar/Sources" \
  -Xswiftc -debug-prefix-map \
  -Xswiftc "$PROJECT_DIR=/Fulmar/Sources" \
  -Xswiftc -file-prefix-map \
  -Xswiftc "$BUILD_SCRATCH=/Fulmar/Build" \
  -Xswiftc -debug-prefix-map \
  -Xswiftc "$BUILD_SCRATCH=/Fulmar/Build" \
  -Xswiftc -file-prefix-map \
  -Xswiftc "$HOST_TEMP_ROOT=/Fulmar/Generated" \
  -Xswiftc -debug-prefix-map \
  -Xswiftc "$HOST_TEMP_ROOT=/Fulmar/Generated" \
  -Xswiftc -file-compilation-dir \
  -Xswiftc /Fulmar/Compilation \
  -Xswiftc -Xfrontend \
  -Xswiftc -g \
  -Xlinker -oso_prefix \
  -Xlinker "$BUILD_SCRATCH" \
  -Xlinker -reproducible)
run_release_command_without_warnings \
  "Swift production build" "$BUILD_SCRATCH/swift-build.log" \
  "${swift_release_command[@]}"
"$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$SWIFT_SOURCE_ROOT" "$SOURCE_INPUT_INVENTORY"
automatic_dsym="$(/usr/bin/find "$BUILD_SCRATCH" -type d -name '*.dSYM' -print -quit)"
[[ -z "$automatic_dsym" ]] || {
  echo "SwiftPM unexpectedly created an uncontrolled dSYM bundle." >&2
  exit 1
}
"$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE_BIN" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE_BIN" "$TOOLCHAIN_TOOL" verify "$TOOLCHAIN_INVENTORY"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$RUNTIME_DIR" "$LAUNCH_AGENTS_DIR" \
  "$MIGRATION_XPC_MACOS_DIR" "$BROKER_XPC_MACOS_DIR" "$ICONSET_DIR"

typeset -a native_products
native_products=(
  LocalHarness
  LocalHarnessCredentialHelper
  LocalHarnessCredentialBrokerService
  LocalHarnessCredentialMigrationService
  LocalHarnessRuntimeLease
  LocalHarnessSandboxRunner
  LocalHarnessSchedulerHelper
  LocalHarnessUpdateHelper
)
rm -rf "$SYMBOL_ROOT"
mkdir -m 0700 "$SYMBOL_ROOT"
scratch_leaf="${BUILD_SCRATCH:t}"
for product in "${native_products[@]}"; do
  compiled="$BUILD_SCRATCH/release/$product"
  [[ -f "$compiled" && ! -L "$compiled" && -x "$compiled" ]] || {
    echo "Missing reviewed native release product: $product" >&2
    exit 1
  }
  # Pass the input to dsymutil relative to the private build directory. Newer
  # dsymutil releases retain that spelling in Relocations metadata, so an
  # absolute random scratch path must never enter the public symbol bundle.
  # The linker removes the random scratch prefix from N_OSO records. The
  # explicit dSYM pass prepends the attested scratch root again for relative
  # object records, while the empty prefix-map replacements prevent that root
  # from being prepended twice to compiler-remapped PCM references.
  (
    cd "$BUILD_SCRATCH/release"
    run_release_command_without_warnings \
      "dSYM generation for $product" "$BUILD_SCRATCH/$product.dsymutil.log" \
      /usr/bin/xcrun dsymutil --verify-dwarf=output \
        --oso-prepend-path "$BUILD_SCRATCH" \
        --object-prefix-map "/Fulmar/Build=" \
        --object-prefix-map "/Fulmar/Generated/$scratch_leaf=" \
        -o "$SYMBOL_ROOT/$product.dSYM" "$product"
  )
  destination="$MACOS_DIR/$product"
  if [[ "$product" == "LocalHarnessCredentialMigrationService" ]]; then
    destination="$MIGRATION_XPC_MACOS_DIR/$product"
  elif [[ "$product" == "LocalHarnessCredentialBrokerService" ]]; then
    destination="$BROKER_XPC_MACOS_DIR/$product"
  fi
  cp "$compiled" "$destination"
  /usr/bin/strip -S -x "$destination"
  chmod 755 "$destination"
done
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" \
  "$APP_DIR" "$SYMBOL_ROOT" "$PROJECT_DIR" "$BUILD_SCRATCH"
cp "$PROJECT_DIR/Resources/com.angadjairath.localharness.scheduler.plist" "$LAUNCH_AGENTS_DIR/com.angadjairath.localharness.scheduler.plist"
cp "$PROJECT_DIR/Resources/Info.plist" "$CONTENTS_DIR/Info.plist"
cp "$PROJECT_DIR/Resources/CredentialMigrationService-Info.plist" \
  "$MIGRATION_XPC_DIR/Contents/Info.plist"
cp "$PROJECT_DIR/Resources/CredentialBrokerService-Info.plist" \
  "$BROKER_XPC_DIR/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$PRODUCT_VERSION" \
  "$MIGRATION_XPC_DIR/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$PRODUCT_BUILD" \
  "$MIGRATION_XPC_DIR/Contents/Info.plist"
plutil -replace LSMinimumSystemVersion -string "$MINIMUM_MACOS" \
  "$MIGRATION_XPC_DIR/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$PRODUCT_VERSION" \
  "$BROKER_XPC_DIR/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$PRODUCT_BUILD" \
  "$BROKER_XPC_DIR/Contents/Info.plist"
plutil -replace LSMinimumSystemVersion -string "$MINIMUM_MACOS" \
  "$BROKER_XPC_DIR/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$BUILD_SCRATCH/migration-xpc-info.json" \
  "$MIGRATION_XPC_DIR/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$BUILD_SCRATCH/broker-xpc-info.json" \
  "$BROKER_XPC_DIR/Contents/Info.plist"
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$BUILD_SCRATCH/migration-xpc-info.json" \
  "$BUILD_SCRATCH/broker-xpc-info.json"
cp "$PROJECT_DIR/Resources/THIRD_PARTY_NOTICES.md" "$RESOURCES_DIR/THIRD_PARTY_NOTICES.md"
cp "$PROJECT_DIR/Resources/RuntimeSecurityPreload.mjs" "$RESOURCES_DIR/RuntimeSecurityPreload.mjs"
cp "$PROJECT_DIR/Resources/LocalHarness.patch.yml" "$RESOURCES_DIR/LocalHarness.patch.yml"
cp "$PROJECT_DIR/Resources/StrictLocal.sb" "$RESOURCES_DIR/StrictLocal.sb"
cp "$PROJECT_DIR/Resources/MigrateCredentials.mjs" "$RESOURCES_DIR/MigrateCredentials.mjs"
cp "$RELEASE_IDENTITY" "$RESOURCES_DIR/ReleaseIdentity.json"
"$NODE_BIN" "$FIRST_PARTY_LICENSE_POLICY" bundle \
  "$PROJECT_DIR" "$RESOURCES_DIR/LICENSE" >/dev/null

[[ "$(plutil -extract CFBundleDisplayName raw -o - "$CONTENTS_DIR/Info.plist")" == "$PRODUCT_DISPLAY_NAME" \
   && "$(plutil -extract CFBundleName raw -o - "$CONTENTS_DIR/Info.plist")" == "$PRODUCT_DISPLAY_NAME" \
   && "$(plutil -extract CFBundleIdentifier raw -o - "$CONTENTS_DIR/Info.plist")" == "$PRODUCT_BUNDLE_ID" \
   && "$(plutil -extract CFBundleShortVersionString raw -o - "$CONTENTS_DIR/Info.plist")" == "$PRODUCT_VERSION" \
   && "$(plutil -extract CFBundleVersion raw -o - "$CONTENTS_DIR/Info.plist")" == "$PRODUCT_BUILD" \
   && "$(plutil -extract LSMinimumSystemVersion raw -o - "$CONTENTS_DIR/Info.plist")" == "$MINIMUM_MACOS" ]] || {
  echo "Info.plist does not match Config/ReleaseIdentity.json." >&2
  exit 1
}
[[ "$($NODE_BIN --version)" == "v$PINNED_NODE_VERSION" ]] || {
  echo "The vendored Node version does not match the release identity." >&2
  exit 1
}

DSH_VERSION="$("$NODE_BIN" -p "require('$DSH_DIR/package.json').version")"
if [[ "$DSH_VERSION" != "$PINNED_DSH_VERSION" ]]; then
  echo "Expected @deepseek-ai/dsh $PINNED_DSH_VERSION, found $DSH_VERSION. Refusing an unreviewed runtime." >&2
  exit 1
fi
# The output root remains owner-only while Runtime is assembled, but the final
# app resources must retain the exact reviewed 0755/0644 modes encoded by the
# independent runtime inventory. A process-wide 077 umask would silently turn
# copied directories/files into 0700/0600 and make a fresh build differ from
# its source inventory. Narrow the umask only inside this private ancestor,
# then restore it before any verification or release evidence is written.
umask 022
cp "$NODE_BIN" "$RUNTIME_DIR/node"
chmod 755 "$RUNTIME_DIR/node"
cp "$VENDOR_ROOT/node-v22.23.1-darwin-arm64/LICENSE" "$RUNTIME_DIR/NODE_LICENSE"
cp -R "$DSH_DIR"/. "$RUNTIME_DIR/dsh"
cp -R "$VENDOR_ROOT/node_modules"/. "$RUNTIME_DIR/dsh/node_modules"
# The complete npm tree contains the root DSH package itself. The authoritative
# package has already been copied to Runtime/dsh above; retaining this exact
# nested self-copy would expose a second CLI, composition, and preset discovery
# root. Validate its identity before deleting only that generated copy.
NESTED_DSH_DIR="$RUNTIME_DIR/dsh/node_modules/@deepseek-ai/dsh"
[[ -f "$NESTED_DSH_DIR/package.json" && -f "$NESTED_DSH_DIR/lib/bin.js" ]] || {
  echo "The complete npm tree is missing its expected nested DSH self-package." >&2
  exit 1
}
NESTED_DSH_IDENTITY="$("$NODE_BIN" -p "const p=require('$NESTED_DSH_DIR/package.json'); p.name + '@' + p.version")"
if [[ "$NESTED_DSH_IDENTITY" != "@deepseek-ai/dsh@$PINNED_DSH_VERSION" ]]; then
  echo "The nested DSH self-package identity changed; refusing an ambiguous deletion." >&2
  exit 1
fi
rm -rf "$NESTED_DSH_DIR"
[[ ! -e "$NESTED_DSH_DIR" ]] || {
  echo "The nested DSH self-package could not be removed from the generated Runtime." >&2
  exit 1
}
NESTED_DSH_BIN_LINK="$RUNTIME_DIR/dsh/node_modules/.bin/dsh"
[[ -L "$NESTED_DSH_BIN_LINK" && "$(readlink "$NESTED_DSH_BIN_LINK")" == "../@deepseek-ai/dsh/lib/bin.js" ]] || {
  echo "The nested DSH executable link changed; refusing an ambiguous deletion." >&2
  exit 1
}
rm "$NESTED_DSH_BIN_LINK"
# Local Harness exposes only a composition whose model-facing file and process tools
# use the reviewed host sandbox. Upstream Minimal mounts a bare filesystem, Cordis
# evaluates model-authored JavaScript against the live runtime, and the upstream Code
# and Workflow workers explicitly document themselves as non-security boundaries.
PRESET_ROOT="$RUNTIME_DIR/dsh/config/agent-presets"
[[ -d "$PRESET_ROOT" ]] || {
  echo "The authoritative packaged DSH is missing its preset root." >&2
  exit 1
}
"$NODE_BIN" "$PROJECT_DIR/scripts/sanitize-agent-presets.mjs" "$PRESET_ROOT"
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-sanitized-agent-presets.mjs" "$RUNTIME_DIR/dsh"
mkdir -p "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-credentials-keychain"
cp "$PROJECT_DIR/Resources/DSHPlugins/credentials-keychain/index.mjs" "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-credentials-keychain/index.mjs"
cp "$PROJECT_DIR/Resources/DSHPlugins/credentials-keychain/package.json" "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-credentials-keychain/package.json"
mkdir -p "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-fs-confined"
cp "$PROJECT_DIR/Resources/DSHPlugins/fs-confined/index.mjs" "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-fs-confined/index.mjs"
cp "$PROJECT_DIR/Resources/DSHPlugins/fs-confined/package.json" "$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-fs-confined/package.json"
MCP_GUARD_PACKAGE="$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-mcp-guarded"
mkdir -p "$MCP_GUARD_PACKAGE"
for source in package.json index.mjs catalog-core.mjs guarded-runtime.mjs wire-guard.mjs stdio-guard-runner.mjs; do
  cp "$PROJECT_DIR/Resources/DSHPlugins/mcp-guarded/$source" "$MCP_GUARD_PACKAGE/$source"
done
CLIENT_SECURITY_PACKAGE="$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-client-security-bridge"
mkdir -p "$CLIENT_SECURITY_PACKAGE"
for source in package.json index.mjs client.js; do
  cp "$PROJECT_DIR/Resources/DSHPlugins/client-security-bridge/$source" "$CLIENT_SECURITY_PACKAGE/$source"
done
PERFORMANCE_PROFILE_PACKAGE="$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-performance-profile"
mkdir -p "$PERFORMANCE_PROFILE_PACKAGE"
for source in package.json index.mjs; do
  cp "$PROJECT_DIR/Resources/DSHPlugins/performance-profile/$source" "$PERFORMANCE_PROFILE_PACKAGE/$source"
done
WEB_FETCH_SAFE_PACKAGE="$RUNTIME_DIR/dsh/node_modules/@local-harness/dsh-web-fetch-safe"
mkdir -p "$WEB_FETCH_SAFE_PACKAGE"
for source in package.json index.mjs; do
  cp "$PROJECT_DIR/Resources/DSHPlugins/web-fetch-safe/$source" "$WEB_FETCH_SAFE_PACKAGE/$source"
done
# DSH resolves browser and typert submodules with createRequire from the
# profile. Declare the exact six signed local packages in the copied app
# manifest so its own fallback manager creates only in-bundle symlinks; bare
# ESM roots remain independently pinned by RuntimeSecurityPreload.
"$NODE_BIN" "$PROJECT_DIR/scripts/materialize-local-plugin-dependencies.mjs" \
  "$RUNTIME_DIR/dsh/package.json" "$PROJECT_DIR"
cp "$VENDOR_ROOT/package-lock.json" "$RUNTIME_DIR/package-lock.json"
umask 077

# Re-attest every source byte after copying, then derive and compare the exact
# assembled layout. This catches a source mutation during cp as well as any
# omitted, injected, mode-changed, re-targeted, or incorrectly transformed item.
"$NODE_BIN" "$INVENTORY_TOOL" verify-assembled \
  "$VENDOR_ROOT" "$VENDOR_INVENTORY" "$RUNTIME_DIR" "$PROJECT_DIR" "$UNSIGNED_RUNTIME_INVENTORY"
"$NODE_BIN" "$INVENTORY_TOOL" create-signables "$RUNTIME_DIR" "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_SIGNABLES"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-macho-compatibility.sh" \
  "$APP_DIR" "$RUNTIME_SIGNABLES" "$MINIMUM_MACOS"

"$NODE_BIN" "$PROJECT_DIR/scripts/generate-third-party-notices.mjs" \
  "$PROJECT_DIR/Resources/THIRD_PARTY_NOTICES.md" \
  "$RUNTIME_DIR" \
  "$PROJECT_DIR/Config/ThirdPartyLicenseOverrides.json" \
  "$RESOURCES_DIR/THIRD_PARTY_NOTICES.md"

[[ -f "$RENDERED_ICON" ]] || { echo "Missing the reviewed Fulmar icon master." >&2; exit 1; }
MASTER_ICON="$RENDERED_ICON"

for spec in \
  "16 icon_16x16.png" \
  "32 icon_16x16@2x.png" \
  "32 icon_32x32.png" \
  "64 icon_32x32@2x.png" \
  "128 icon_128x128.png" \
  "256 icon_128x128@2x.png" \
  "256 icon_256x256.png" \
  "512 icon_256x256@2x.png" \
  "512 icon_512x512.png" \
  "1024 icon_512x512@2x.png"; do
  size="${spec%% *}"
  name="${spec#* }"
  sips -z "$size" "$size" "$MASTER_ICON" --out "$ICONSET_DIR/$name" >/dev/null
done

"$BUILD_SCRATCH/release/IconPacker" "$ICONSET_DIR" "$RESOURCES_DIR/AppIcon.icns"
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-app-icon.mjs" \
  "$RESOURCES_DIR/AppIcon.icns" "$MASTER_ICON"
xattr -cr "$APP_DIR"

if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]; then
  # Stop at the exact production boundary immediately before Fulmar performs
  # any signing or reads a Keychain. Preserve the linker outputs separately
  # from their stripped app copies so the two-root gate compares both forms.
  COMPILER_PRODUCTS_ROOT="$OUTPUT_ROOT/CompilerProducts"
  [[ ! -e "$COMPILER_PRODUCTS_ROOT" && ! -L "$COMPILER_PRODUCTS_ROOT" ]] || {
    print -u2 "The unsigned compiler-product capture already exists."
    exit 1
  }
  /bin/mkdir -m 0700 "$COMPILER_PRODUCTS_ROOT"
  for product in "${native_products[@]}"; do
    compiled="$BUILD_SCRATCH/release/$product"
    [[ -f "$compiled" && ! -L "$compiled" && -x "$compiled" \
       && "$(/usr/bin/stat -f '%l' "$compiled")" == "1" ]] || {
      print -u2 "The exact pre-strip compiler output is unavailable: $product"
      exit 1
    }
    /bin/cp -p "$compiled" "$COMPILER_PRODUCTS_ROOT/$product"
    [[ -f "$COMPILER_PRODUCTS_ROOT/$product" \
       && ! -L "$COMPILER_PRODUCTS_ROOT/$product" \
       && -x "$COMPILER_PRODUCTS_ROOT/$product" \
       && "$(/usr/bin/stat -f '%l' "$COMPILER_PRODUCTS_ROOT/$product")" == "1" ]] || {
      print -u2 "The compiler-product capture is unsafe: $product"
      exit 1
    }
  done
  compiler_entry_count="$(/usr/bin/find "$COMPILER_PRODUCTS_ROOT" -mindepth 1 -maxdepth 1 -print \
    | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  [[ "$compiler_entry_count" == "${#native_products}" ]] || {
    print -u2 "The compiler-product capture does not contain exactly eight native products."
    exit 1
  }
  SCRATCH_LEAF_EVIDENCE="$BUILD_OUTPUT_DIR/scratch-leaf.txt"
  [[ ! -e "$SCRATCH_LEAF_EVIDENCE" && ! -L "$SCRATCH_LEAF_EVIDENCE" \
     && "${#scratch_leaf}" -eq 32 \
     && "$scratch_leaf" == "$FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX"?????? ]] || {
    print -u2 "The private scratch-root differentiation evidence is unsafe."
    exit 1
  }
  setopt localoptions noclobber
  print -r -- "$scratch_leaf" > "$SCRATCH_LEAF_EVIDENCE"
  /bin/chmod 0600 "$SCRATCH_LEAF_EVIDENCE"
  [[ "$(/usr/bin/stat -f '%u:%Lp:%l:%z' "$SCRATCH_LEAF_EVIDENCE")" \
       == "$(/usr/bin/id -u):600:1:33" ]] || {
    print -u2 "The private scratch-root differentiation evidence could not be bound."
    exit 1
  }
  "$NODE_BIN" "$UNSIGNED_REPRODUCIBILITY_TOOL" create \
    "$OUTPUT_ROOT" "$UNSIGNED_REPRODUCIBILITY_INVENTORY"
  "$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
  "$NODE_BIN" "$STATIC_SECURITY_VERIFIER" \
    "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
  "$NODE_BIN" "$TOOLCHAIN_TOOL" verify "$TOOLCHAIN_INVENTORY"
  print -r -- "$OUTPUT_ROOT"
  exit 0
fi

LOCAL_SIGNING_IDENTITY_NAME="Fulmar Local Signing"
SIGNING_KEYCHAIN="${LOCAL_HARNESS_SIGNING_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"
[[ "$SIGNING_KEYCHAIN" == /* && "$SIGNING_KEYCHAIN" != *$'\n'* \
   && "$SIGNING_KEYCHAIN" != *$'\r'* && -f "$SIGNING_KEYCHAIN" \
   && ! -L "$SIGNING_KEYCHAIN" && "${SIGNING_KEYCHAIN:A}" == "$SIGNING_KEYCHAIN" \
   && "$(/usr/bin/stat -f '%u' "$SIGNING_KEYCHAIN")" == "$(/usr/bin/id -u)" ]] || {
  echo "The signing Keychain must be one owner-controlled absolute regular file." >&2
  exit 1
}
SIGN_IDENTITY="${LOCAL_HARNESS_SIGN_IDENTITY:-}"
if [[ -z "$SIGN_IDENTITY" ]]; then
  # Private development releases should retain one designated requirement
  # across updates. Prefer the explicitly named, owner-created local identity
  # when it exists; CI and clean source builds remain ad-hoc until that identity
  # is deliberately provisioned.
  SIGN_IDENTITY="$(security find-certificate -a -c "$LOCAL_SIGNING_IDENTITY_NAME" -Z \
    "$SIGNING_KEYCHAIN" 2>/dev/null \
    | sed -n 's/^SHA-1 hash: //p' \
    | sed -n '1p')"
fi
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
if [[ "${LOCAL_HARNESS_REQUIRE_STABLE_SIGNING:-0}" == "1" && "$SIGN_IDENTITY" == "-" ]]; then
  echo "A stable Fulmar code-signing identity is required for this release." >&2
  echo "Run scripts/create-local-signing-identity.sh for private builds or provide a Developer ID identity." >&2
  exit 1
fi
if [[ -n "${LOCAL_HARNESS_NOTARY_PROFILE:-}" && "$SIGN_IDENTITY" == "-" ]]; then
  echo "Notarization requires LOCAL_HARNESS_SIGN_IDENTITY to select a Developer ID Application certificate." >&2
  exit 1
fi
SIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
if [[ "$SIGN_IDENTITY" != "-" ]]; then
  SIGN_ARGS+=(--keychain "$SIGNING_KEYCHAIN")
fi
SIGN_TIMESTAMP="${LOCAL_HARNESS_SIGN_TIMESTAMP:-auto}"
[[ "$SIGN_TIMESTAMP" == "0" || "$SIGN_TIMESTAMP" == "1" || "$SIGN_TIMESTAMP" == "auto" ]] || {
  echo "LOCAL_HARNESS_SIGN_TIMESTAMP must be 0, 1, or auto." >&2
  exit 1
}
if [[ -n "${LOCAL_HARNESS_NOTARY_PROFILE:-}" && "$SIGN_TIMESTAMP" == "0" ]]; then
  echo "Notarized Developer ID builds cannot disable the required secure timestamp." >&2
  exit 1
fi
if [[ -n "${LOCAL_HARNESS_NOTARY_PROFILE:-}" || "$SIGN_TIMESTAMP" == "1" \
   || ( "$SIGN_TIMESTAMP" == "auto" && "$SIGN_IDENTITY" == Developer\ ID\ Application:* ) ]]; then
  SIGN_ARGS+=(--timestamp)
fi

SIGNABLE_CANDIDATES="$BUILD_SCRATCH/signable-candidates.txt"
set +e
find "$CONTENTS_DIR" -type f \( -name '*.node' -o -name '*.dylib' -o -perm -111 \) \
  | sort > "$SIGNABLE_CANDIDATES"
SIGNABLE_PIPE_STATUS=("${pipestatus[@]}")
set -e
[[ "${SIGNABLE_PIPE_STATUS[1]}" == "0" && "${SIGNABLE_PIPE_STATUS[2]}" == "0" \
   && -f "$SIGNABLE_CANDIDATES" && ! -L "$SIGNABLE_CANDIDATES" \
   && "$(/usr/bin/stat -f '%z' "$SIGNABLE_CANDIDATES")" -ge 1 \
   && "$(/usr/bin/stat -f '%z' "$SIGNABLE_CANDIDATES")" -le 1048576 ]] || {
  echo "Build executable inventory could not be materialized safely." >&2
  exit 1
}
while IFS= read -r candidate; do
  [[ "$candidate" == "$MACOS_DIR/LocalHarness" \
     || "$candidate" == "$MIGRATION_XPC_MACOS_DIR/LocalHarnessCredentialMigrationService" \
     || "$candidate" == "$BROKER_XPC_MACOS_DIR/LocalHarnessCredentialBrokerService" \
     || "$candidate" == "$RUNTIME_DIR"/* ]] && continue
  FILE_KIND="$BUILD_SCRATCH/signable-file-kind.txt"
  /usr/bin/file "$candidate" > "$FILE_KIND"
  set +e
  /usr/bin/grep -q 'Mach-O' "$FILE_KIND"
  MACHO_STATUS=$?
  set -e
  if (( MACHO_STATUS == 0 )); then
    case "$candidate" in
      "$MACOS_DIR/LocalHarnessCredentialHelper")
        codesign "${SIGN_ARGS[@]}" --identifier "$PRODUCT_BUNDLE_ID.credential-helper" "$candidate" >/dev/null
        ;;
      "$MACOS_DIR/LocalHarnessSchedulerHelper")
        codesign "${SIGN_ARGS[@]}" --identifier "$PRODUCT_BUNDLE_ID.scheduler-helper" "$candidate" >/dev/null
        ;;
      "$MACOS_DIR/LocalHarnessUpdateHelper")
        codesign "${SIGN_ARGS[@]}" --identifier "$PRODUCT_BUNDLE_ID.update-helper" "$candidate" >/dev/null
        ;;
      "$MACOS_DIR/LocalHarnessSandboxRunner")
        codesign "${SIGN_ARGS[@]}" --identifier "$PRODUCT_BUNDLE_ID.sandbox-runner" "$candidate" >/dev/null
        ;;
      "$MACOS_DIR/LocalHarnessRuntimeLease")
        codesign "${SIGN_ARGS[@]}" --identifier "$PRODUCT_BUNDLE_ID.runtime-lease" "$candidate" >/dev/null
        ;;
      *)
        codesign "${SIGN_ARGS[@]}" "$candidate" >/dev/null
        ;;
    esac
  elif (( MACHO_STATUS != 1 )); then
    echo "Build executable type evidence could not be scanned safely." >&2
    exit 1
  fi
done < "$SIGNABLE_CANDIDATES"

# The XPC executable intentionally carries the credential helper's designated
# code identifier. That preserves access to existing login-Keychain items and
# makes new migrated items readable by the ordinary helper without ever
# launching a mutable helper pathname. The parent pins this service's exact
# CDHash on every connection, so the shared designated requirement does not
# weaken the XPC execution boundary.
codesign "${SIGN_ARGS[@]}" \
  --identifier "$PRODUCT_BUNDLE_ID.credential-helper" \
  --entitlements "$PROJECT_DIR/Resources/CredentialMigrationService.entitlements" \
  "$MIGRATION_XPC_DIR" >/dev/null
codesign "${SIGN_ARGS[@]}" \
  --identifier "$PRODUCT_BUNDLE_ID.credential-helper" \
  --entitlements "$PROJECT_DIR/Resources/CredentialBrokerService.entitlements" \
  "$BROKER_XPC_DIR" >/dev/null

runtime_signables=()
while IFS= read -r relative_path; do
  runtime_signables+=("$relative_path")
done < <("$NODE_BIN" "$INVENTORY_TOOL" emit-signables "$RUNTIME_SIGNABLES")
for relative_path in "${runtime_signables[@]}"; do
  [[ "$relative_path" == "node" ]] && continue
  codesign "${SIGN_ARGS[@]}" "$RUNTIME_DIR/$relative_path" >/dev/null
done
codesign "${SIGN_ARGS[@]}" --entitlements "$PROJECT_DIR/Resources/NodeRuntime.entitlements" "$RUNTIME_DIR/node" >/dev/null
"$NODE_BIN" "$INVENTORY_TOOL" verify-signing-transition \
  "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_DIR" "$RUNTIME_SIGNABLES" "$FINAL_RUNTIME_INVENTORY"

# A component hash in the shipped SBOM must identify the exact distributed
# executable, including its code signature. Generate it only after the Runtime
# signing transition is sealed, and before the enclosing app signature binds
# the SBOM itself.
APP_VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$CONTENTS_DIR/Info.plist")"
"$NODE_BIN" "$PROJECT_DIR/scripts/generate-sbom.mjs" \
  "$RUNTIME_DIR" "$SBOM_PATH" "$APP_VERSION" "$PROJECT_DIR" \
  "dsh/node_modules/@local-harness/dsh-credentials-keychain/package.json" \
  "dsh/node_modules/@local-harness/dsh-fs-confined/package.json" \
  "dsh/node_modules/@local-harness/dsh-mcp-guarded/package.json" \
  "dsh/node_modules/@local-harness/dsh-client-security-bridge/package.json" \
  "dsh/node_modules/@local-harness/dsh-performance-profile/package.json" \
  "dsh/node_modules/@local-harness/dsh-web-fetch-safe/package.json"
codesign "${SIGN_ARGS[@]}" --entitlements "$PROJECT_DIR/Resources/LocalHarness.entitlements" "$APP_DIR" >/dev/null
if [[ "$SIGN_IDENTITY" == "-" || "$SIGN_IDENTITY" == Developer\ ID\ Application:* ]]; then
  codesign --verify --deep --strict "$APP_DIR"
else
  LOCAL_HARNESS_ALLOW_PRIVATE_ROOT=1 /bin/zsh -f "$PROJECT_DIR/scripts/verify-code-signature.sh" "$APP_DIR" --deep --strict
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-stable-signing.sh" "$APP_DIR"
fi

"$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"

rm -f "$SYMBOL_ARCHIVE_PATH"
xattr -cr "$SYMBOL_ROOT"
[[ -z "$(xattr -lr "$SYMBOL_ROOT")" ]] || {
  echo "The dSYM tree still contains extended attributes after normalization." >&2
  exit 1
}
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" \
  "$APP_DIR" "$SYMBOL_ROOT" "$PROJECT_DIR" "$BUILD_SCRATCH"
ditto -c -k --keepParent "$SYMBOL_ROOT" "$SYMBOL_ARCHIVE_PATH"
"$NODE_BIN" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" \
  "$SYMBOL_ARCHIVE_PATH" "$SYMBOL_ROOT" "${SYMBOL_ROOT:t}"

rm -f "$ARCHIVE_PATH"
ditto -c -k --keepParent "$APP_DIR" "$ARCHIVE_PATH"

if [[ -n "${LOCAL_HARNESS_NOTARY_PROFILE:-}" ]]; then
  # Keep Apple's machine-readable receipt and completed issue log as private
  # release evidence. A zero process exit alone is not sufficient: the exact
  # submission must be Accepted, identify one UUID, and have no unresolved
  # notary issues before the ticket is stapled to the distributed app.
  xcrun notarytool submit "$ARCHIVE_PATH" \
    --keychain-profile "$LOCAL_HARNESS_NOTARY_PROFILE" \
    --wait --timeout 2h --no-progress --output-format json > "$NOTARY_SUBMISSION_EVIDENCE"
  /bin/chmod 0600 "$NOTARY_SUBMISSION_EVIDENCE"
  NOTARY_SUBMISSION_ID="$("$NODE_BIN" -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (value.status !== "Accepted" || typeof value.id !== "string"
        || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iu.test(value.id)) {
      process.exit(1);
    }
    process.stdout.write(value.id);
  ' "$NOTARY_SUBMISSION_EVIDENCE")" || {
    echo "Apple notarization did not return one valid Accepted submission receipt." >&2
    exit 1
  }
  xcrun notarytool log "$NOTARY_SUBMISSION_ID" \
    --keychain-profile "$LOCAL_HARNESS_NOTARY_PROFILE" \
    "$NOTARY_LOG_EVIDENCE"
  /bin/chmod 0600 "$NOTARY_LOG_EVIDENCE"
  "$NODE_BIN" -e '
    const fs = require("node:fs");
    const [path, expectedID] = process.argv.slice(1);
    const value = JSON.parse(fs.readFileSync(path, "utf8"));
    const issueFree = value.issues === null
      || (Array.isArray(value.issues) && value.issues.length === 0);
    if (value.jobId !== expectedID || value.status !== "Accepted" || !issueFree) {
      process.exit(1);
    }
  ' "$NOTARY_LOG_EVIDENCE" "$NOTARY_SUBMISSION_ID" || {
    echo "Apple notarization evidence is mismatched, not Accepted, or contains unresolved issues." >&2
    exit 1
  }
  "$NODE_BIN" "$PROJECT_DIR/scripts/verify-notarization-evidence.mjs" \
    "$NOTARY_SUBMISSION_EVIDENCE" "$NOTARY_LOG_EVIDENCE"
  xcrun stapler staple "$APP_DIR"
  codesign --verify --deep --strict "$APP_DIR"
  spctl --assess --type execute --verbose=2 "$APP_DIR"
  rm -f "$ARCHIVE_PATH"
  ditto -c -k --keepParent "$APP_DIR" "$ARCHIVE_PATH"
fi

"$NODE_BIN" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE_BIN" "$TOOLCHAIN_TOOL" verify "$TOOLCHAIN_INVENTORY"
plutil -convert json -o "$OUTPUT_ROOT/Info.json" "$CONTENTS_DIR/Info.plist"
"$NODE_BIN" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE_BIN" "$PROJECT_DIR/scripts/generate-release-manifest.mjs" \
  "$ARCHIVE_PATH" "$OUTPUT_ROOT/Info.json" "$BUILD_OUTPUT_DIR/release-manifest.json" \
  "$SYMBOL_ARCHIVE_PATH" \
  "$VENDOR_INVENTORY" "$UNSIGNED_RUNTIME_INVENTORY" "$RUNTIME_SIGNABLES" "$FINAL_RUNTIME_INVENTORY" \
  "$SOURCE_INPUT_INVENTORY" "$STATIC_SECURITY_SUMMARY" "$TOOLCHAIN_INVENTORY"

echo "$APP_DIR"
