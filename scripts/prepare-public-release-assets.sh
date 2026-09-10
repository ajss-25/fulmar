#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
# Operands: the six positional candidate operands (or none), an optional explicit
# `--profile stable|beta`, and — for the beta profile only — the three material
# operands naming the operator's private verified material package, the expected
# material archive SHA-256 taken from the independently reviewed release record,
# and this checkout's exact source commit. Shape, duplicates and missing operands
# are rejected here, before the watchdog re-execution, the clean environment,
# the release lock or any expensive work. The profile is never read from the
# environment. The original argument vector is forwarded unchanged.
typeset -a ORIGINAL_ARGUMENTS
ORIGINAL_ARGUMENTS=("$@")
usage() {
  print -u2 "Usage: prepare-public-release-assets.sh [archive manifest output expected-sha256 expected-version expected-build] [--profile stable | --profile beta --material-package /absolute/package --material-sha256 <sha256> --source-commit <commit>]"
  exit 64
}
RELEASE_PROFILE="stable"
PROFILE_SELECTED=0
MATERIAL_PACKAGE=""
MATERIAL_PACKAGE_SELECTED=0
MATERIAL_SHA256=""
MATERIAL_SHA256_SELECTED=0
SOURCE_COMMIT_OPERAND=""
SOURCE_COMMIT_SELECTED=0
typeset -a POSITIONAL_OPERANDS
POSITIONAL_OPERANDS=()
while (( $# > 0 )); do
  case "$1" in
    --profile)
      (( $# >= 2 && PROFILE_SELECTED == 0 )) || usage
      case "$2" in
        stable|beta) RELEASE_PROFILE="$2" ;;
        *)
          print -u2 "prepare-public-release-assets.sh accepts only the exact release profiles stable or beta."
          exit 64
          ;;
      esac
      PROFILE_SELECTED=1
      shift 2
      ;;
    --material-package)
      (( $# >= 2 && MATERIAL_PACKAGE_SELECTED == 0 )) || usage
      MATERIAL_PACKAGE="$2"
      MATERIAL_PACKAGE_SELECTED=1
      shift 2
      ;;
    --material-sha256)
      (( $# >= 2 && MATERIAL_SHA256_SELECTED == 0 )) || usage
      MATERIAL_SHA256="$2"
      MATERIAL_SHA256_SELECTED=1
      shift 2
      ;;
    --source-commit)
      (( $# >= 2 && SOURCE_COMMIT_SELECTED == 0 )) || usage
      SOURCE_COMMIT_OPERAND="$2"
      SOURCE_COMMIT_SELECTED=1
      shift 2
      ;;
    --*)
      usage
      ;;
    *)
      POSITIONAL_OPERANDS+=("$1")
      shift
      ;;
  esac
done
(( ${#POSITIONAL_OPERANDS[@]} == 0 || ${#POSITIONAL_OPERANDS[@]} == 6 )) || usage
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  (( MATERIAL_PACKAGE_SELECTED == 1 && MATERIAL_SHA256_SELECTED == 1 && SOURCE_COMMIT_SELECTED == 1 )) || {
    print -u2 "The beta profile requires --material-package, --material-sha256 and --source-commit: the private verified material package, its expected archive SHA-256 from the reviewed release record, and this checkout's exact source commit."
    exit 64
  }
  [[ "$MATERIAL_PACKAGE" == /* && "$MATERIAL_PACKAGE" != *$'\n'* && "$MATERIAL_PACKAGE" != *$'\r'* \
     && "${#MATERIAL_SHA256}" == 64 && "$MATERIAL_SHA256" != *[^a-f0-9]* \
     && "${#SOURCE_COMMIT_OPERAND}" == 40 && "$SOURCE_COMMIT_OPERAND" != *[^a-f0-9]* ]] || {
    print -u2 "Beta material operands must be one absolute package directory, one lowercase SHA-256 and one full 40-hex source commit."
    exit 64
  }
else
  (( MATERIAL_PACKAGE_SELECTED == 0 && MATERIAL_SHA256_SELECTED == 0 && SOURCE_COMMIT_SELECTED == 0 )) || {
    print -u2 "Material operands are accepted only with --profile beta; the stable package carries no material assets."
    exit 64
  }
fi
unset PROFILE_SELECTED MATERIAL_PACKAGE_SELECTED MATERIAL_SHA256_SELECTED SOURCE_COMMIT_SELECTED
set -- "${ORIGINAL_ARGUMENTS[@]}"
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
# Only the six positional candidate operands remain positional from here on.
set -- "${POSITIONAL_OPERANDS[@]}"
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
# The private checkout-local notice-material cache prepared by
# scripts/bootstrap-source-checkout.sh; verified here, never acquired.
RUST_CRATE_MATERIALS="$PROJECT_DIR/build/third-party-notice-materials/sharp-libvips-1.3.3-rust-crate-materials"
NOTICE_MATERIALS_TOOL="$PROJECT_DIR/scripts/prepare-third-party-notice-materials.mjs"
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
# Exact asset policy per profile (scripts/public-release-asset-policy.mjs). The
# stable package is the unchanged nine assets with eight SHA256SUMS.txt entries.
# The beta package adds the verified material archive, its sidecar and its
# binding, named only from the tracked provenance record, for twelve assets and
# eleven entries. Names are in C-locale byte order, the SHA256SUMS.txt order.
ASSET_POLICY="$PROJECT_DIR/scripts/public-release-asset-policy.mjs"
PROVENANCE_RECORD="$PROJECT_DIR/Config/ThirdPartyBinaryProvenance.json"
typeset -a STABLE_PACKAGE_ASSET_NAMES
STABLE_PACKAGE_ASSET_NAMES=(Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE LocalHarness.sbom.cdx.json SHA256SUMS.txt THIRD_PARTY_NOTICES.md release-manifest.json static-security-summary.json)
typeset -a PACKAGE_ASSET_NAMES
PACKAGE_ASSET_NAMES=("${STABLE_PACKAGE_ASSET_NAMES[@]}")
typeset -a CHECKSUM_ENTRY_NAMES
CHECKSUM_ENTRY_NAMES=(Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE LocalHarness.sbom.cdx.json THIRD_PARTY_NOTICES.md release-manifest.json static-security-summary.json)
typeset -a MATERIAL_ASSET_NAMES
MATERIAL_ASSET_NAMES=()
EXPECTED_ASSET_COUNT=9
MATERIAL_ADMISSION=""
verify_source_commit_operand() {
  local expected="$1" toplevel head tracked_status
  toplevel="$(/usr/bin/git -C "$PROJECT_DIR" rev-parse --show-toplevel 2>/dev/null)" && [[ "$toplevel" == "$PROJECT_DIR" ]] || {
    print -u2 "Beta material binding requires this checkout to be the exact Git worktree root."
    return 1
  }
  head="$(/usr/bin/git -C "$PROJECT_DIR" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || {
    print -u2 "Beta material binding could not read this checkout's HEAD commit."
    return 1
  }
  [[ "$head" == "$expected" ]] || {
    print -u2 "The supplied --source-commit $expected is not this checkout's HEAD $head; the material binding must name the exact source revision being released."
    return 1
  }
  tracked_status="$(/usr/bin/git -C "$PROJECT_DIR" status --porcelain=v1 --untracked-files=no 2>/dev/null)" || {
    print -u2 "Beta material binding could not read this checkout's status."
    return 1
  }
  [[ -z "$tracked_status" ]] || {
    print -u2 "Beta material binding requires a clean committed source tree (no modified tracked files)."
    return 1
  }
}
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  verify_source_commit_operand "$SOURCE_COMMIT_OPERAND"
  [[ "$MATERIAL_SHA256" != "$EXPECTED_CANDIDATE_SHA256" ]] || {
    print -u2 "The expected material digest equals the app candidate digest; the material archive and Fulmar.app.zip are different artefacts with different digests."
    exit 64
  }
  [[ -d "$MATERIAL_PACKAGE" && ! -L "$MATERIAL_PACKAGE" && "${MATERIAL_PACKAGE:A}" == "$MATERIAL_PACKAGE" ]] || {
    print -u2 "The beta material package must be one existing canonical directory: $MATERIAL_PACKAGE"
    exit 1
  }
  PACKAGE_ASSET_NAMES=("${(@f)$("$NODE" "$ASSET_POLICY" names beta "$PROVENANCE_RECORD")}") || exit 1
  CHECKSUM_ENTRY_NAMES=("${(@f)$("$NODE" "$ASSET_POLICY" checksum-names beta "$PROVENANCE_RECORD")}") || exit 1
  # The material assets are exactly the beta names that are not stable names.
  MATERIAL_ASSET_NAMES=("${(@)PACKAGE_ASSET_NAMES:|STABLE_PACKAGE_ASSET_NAMES}")
  (( ${#PACKAGE_ASSET_NAMES[@]} == 12 && ${#CHECKSUM_ENTRY_NAMES[@]} == 11 && ${#MATERIAL_ASSET_NAMES[@]} == 3 )) || {
    print -u2 "The beta asset policy did not yield exactly twelve assets, eleven checksum entries and three material assets."
    exit 1
  }
  EXPECTED_ASSET_COUNT=12
fi
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
"$NODE" "$NOTICE_MATERIALS_TOOL" verify "$PROJECT_DIR" "$RUST_CRATE_MATERIALS"
"$NODE" "$PROJECT_DIR/scripts/generate-third-party-notices.mjs" \
  "$PROJECT_DIR/Resources/THIRD_PARTY_NOTICES.md" "$RUNTIME" \
  "$PROJECT_DIR/Config/ThirdPartyLicenseOverrides.json" "$TEMP_ROOT/notices.md" \
  --rust-crate-materials "$RUST_CRATE_MATERIALS"
/usr/bin/cmp -s "$TEMP_ROOT/notices.md" "$NOTICES"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" "$APP" "$SYMBOL_ROOT"

if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  # Beta material admission: the three material files are snapshotted from the
  # operator's private package through attested descriptors into this
  # invocation's private staging, the existing verify-archive runs on those
  # snapshots with the operator-supplied expected digest and source commit, and
  # only HTTPS-authoritative acquisition is accepted. The snapshots are the bytes
  # copied into the package below; the external package path is never reopened.
  MATERIAL_ADMISSION="$TEMP_ROOT/materials"
  /bin/mkdir -m 0700 "$MATERIAL_ADMISSION"
  "$NODE" "$ASSET_POLICY" admit-materials "$PROVENANCE_RECORD" "$MATERIAL_PACKAGE" \
    "$MATERIAL_SHA256" "$SOURCE_COMMIT_OPERAND" "$MATERIAL_ADMISSION" "$TEMP_ROOT" \
    > "$TEMP_ROOT/material-admission.json"
  for name in "${MATERIAL_ASSET_NAMES[@]}"; do
    [[ -f "$MATERIAL_ADMISSION/$name" && ! -L "$MATERIAL_ADMISSION/$name" \
       && "$(/usr/bin/stat -f %l "$MATERIAL_ADMISSION/$name")" == 1 ]] || {
      echo "Beta material admission did not produce the exact snapshot: $name" >&2; exit 1
    }
  done
  typeset -a MATERIAL_ARCHIVE_NAMES
  MATERIAL_ARCHIVE_NAMES=("${(@M)MATERIAL_ASSET_NAMES:#*.tar}")
  (( ${#MATERIAL_ARCHIVE_NAMES[@]} == 1 )) || {
    echo "Beta material assets must contain exactly one material archive." >&2; exit 1
  }
  [[ "$(LC_ALL=C /usr/bin/shasum -a 256 "$MATERIAL_ADMISSION/${MATERIAL_ARCHIVE_NAMES[1]}" | /usr/bin/awk '{print $1}')" == "$MATERIAL_SHA256" ]] || {
    echo "Beta material admission snapshot does not carry the expected material archive digest." >&2; exit 1
  }
fi

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
# Beta only: the admitted material snapshots, exactly as verified above.
for name in "${MATERIAL_ASSET_NAMES[@]}"; do
  /bin/cp "$MATERIAL_ADMISSION/$name" "$PUBLIC_STAGING/$name"
done
(
  cd "$PUBLIC_STAGING"
  LC_ALL=C /usr/bin/shasum -a 256 Fulmar.app.zip > Fulmar.app.zip.sha256
)
/bin/chmod 0644 "$PUBLIC_STAGING"/*
(
  cd "$PUBLIC_STAGING"
  LC_ALL=C /usr/bin/shasum -a 256 "${CHECKSUM_ENTRY_NAMES[@]}" > SHA256SUMS.txt
)
/bin/chmod 0644 "$PUBLIC_STAGING/SHA256SUMS.txt"
[[ "$(/usr/bin/find "$PUBLIC_STAGING" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "$EXPECTED_ASSET_COUNT" ]] || {
  if [[ "$RELEASE_PROFILE" == "beta" ]]; then
    echo "Prepared public beta package did not contain exactly twelve assets." >&2
  else
    echo "Prepared public package did not contain exactly nine assets." >&2
  fi
  exit 1
}
for name in "${PACKAGE_ASSET_NAMES[@]}"; do
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
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  echo "Prepared the exact twelve manifest-, static-scan-, licence- and material-bound public BETA release assets (material archive sha256 $MATERIAL_SHA256 bound to source commit $SOURCE_COMMIT_OPERAND). This does not qualify them for distribution, is not stable qualification, and closes no third-party licensing obligation."
else
  echo "Prepared the exact nine manifest-, static-scan-, and licence-bound public release assets. This does not qualify them for distribution."
fi
