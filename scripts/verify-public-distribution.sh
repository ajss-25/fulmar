#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 4294967296 --rss-grace-seconds 5 \
    --emergency-rss-bytes 6442450944 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete public-distribution verification" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Public-distribution verification inherited an invalid root-watchdog capability."
  exit 1
fi
source "${0:A:h}/clean-release-environment.zsh"
fulmar_require_clean_release_environment public "$0" "$@"

# An explicit `--profile stable|beta` may follow the positional operands. The
# default remains the unchanged stable contract; the beta profile binds the
# verifier to the separately identifiable beta evidence record and requires the
# two material operands: the expected material archive SHA-256 taken from the
# independently reviewed release record and this checkout's exact source commit.
# Neither may come from the package's own sidecar, checksum list or binding, and
# nothing is read from the environment.
USAGE="Usage: verify-public-distribution.sh [/absolute/public-release-assets] [/absolute/public-external-evidence.json] [--profile stable | --profile beta --material-sha256 <sha256> --source-commit <commit>]"
RELEASE_PROFILE="stable"
typeset -a EVIDENCE_PROFILE_ARGUMENTS
EVIDENCE_PROFILE_ARGUMENTS=()
typeset -a POSITIONAL_OPERANDS
POSITIONAL_OPERANDS=()
PROFILE_SELECTED=0
MATERIAL_SHA256=""
MATERIAL_SHA256_SELECTED=0
SOURCE_COMMIT_OPERAND=""
SOURCE_COMMIT_SELECTED=0
while (( $# > 0 )); do
  case "$1" in
    --profile)
      (( $# >= 2 && PROFILE_SELECTED == 0 )) || {
        print -u2 "$USAGE"
        exit 64
      }
      case "$2" in
        stable|beta) RELEASE_PROFILE="$2" ;;
        *)
          print -u2 "verify-public-distribution.sh accepts only the exact release profiles stable or beta."
          exit 64
          ;;
      esac
      PROFILE_SELECTED=1
      shift 2
      ;;
    --material-sha256)
      (( $# >= 2 && MATERIAL_SHA256_SELECTED == 0 )) || {
        print -u2 "$USAGE"
        exit 64
      }
      MATERIAL_SHA256="$2"
      MATERIAL_SHA256_SELECTED=1
      shift 2
      ;;
    --source-commit)
      (( $# >= 2 && SOURCE_COMMIT_SELECTED == 0 )) || {
        print -u2 "$USAGE"
        exit 64
      }
      SOURCE_COMMIT_OPERAND="$2"
      SOURCE_COMMIT_SELECTED=1
      shift 2
      ;;
    --*)
      print -u2 "$USAGE"
      exit 64
      ;;
    *)
      POSITIONAL_OPERANDS+=("$1")
      shift
      ;;
  esac
done
(( ${#POSITIONAL_OPERANDS[@]} <= 2 )) || {
  print -u2 "$USAGE"
  exit 64
}
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  (( MATERIAL_SHA256_SELECTED == 1 && SOURCE_COMMIT_SELECTED == 1 )) || {
    print -u2 "The beta profile requires --material-sha256 and --source-commit: the expected material archive SHA-256 from the reviewed release record and this checkout's exact source commit."
    exit 64
  }
  [[ "${#MATERIAL_SHA256}" == 64 && "$MATERIAL_SHA256" != *[^a-f0-9]* \
     && "${#SOURCE_COMMIT_OPERAND}" == 40 && "$SOURCE_COMMIT_OPERAND" != *[^a-f0-9]* ]] || {
    print -u2 "Beta material operands must be one lowercase SHA-256 and one full 40-hex source commit."
    exit 64
  }
else
  (( MATERIAL_SHA256_SELECTED == 0 && SOURCE_COMMIT_SELECTED == 0 )) || {
    print -u2 "Material operands are accepted only with --profile beta; the stable package carries no material assets."
    exit 64
  }
fi
unset PROFILE_SELECTED MATERIAL_SHA256_SELECTED SOURCE_COMMIT_SELECTED

source "$PROJECT_DIR/scripts/release-lock.zsh"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
PACKAGE="${POSITIONAL_OPERANDS[1]:-$PROJECT_DIR/build/public-release-assets}"
DEFAULT_PUBLIC_EXTERNAL_EVIDENCE="$PROJECT_DIR/build/public-external-evidence.json"
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  DEFAULT_PUBLIC_EXTERNAL_EVIDENCE="$PROJECT_DIR/build/public-beta-external-evidence.json"
  EVIDENCE_PROFILE_ARGUMENTS=(--profile beta)
fi
PUBLIC_EXTERNAL_EVIDENCE="${POSITIONAL_OPERANDS[2]:-$DEFAULT_PUBLIC_EXTERNAL_EVIDENCE}"
umask 077
TEMP_ROOT=""
cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$TEMP_ROOT" && "$TEMP_ROOT" == /private/tmp/fulmar-public-verify.* \
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
fulmar_acquire_release_lock "Fulmar public-distribution verification"
[[ "$PACKAGE" == /* && -d "$PACKAGE" && ! -L "$PACKAGE" ]] || exit 1
[[ "$PUBLIC_EXTERNAL_EVIDENCE" == /* ]] || {
  echo "Public external evidence must use one absolute path." >&2
  exit 64
}
# Exact asset policy per profile (scripts/public-release-asset-policy.mjs). The
# stable package is the unchanged nine assets with eight SHA256SUMS.txt entries;
# the beta package is exactly those plus the verified material archive, its
# sidecar and its binding (twelve assets, eleven entries), named only from the
# tracked provenance record. Names are in C-locale byte order.
typeset -a STABLE_PACKAGE_ASSET_NAMES
STABLE_PACKAGE_ASSET_NAMES=(Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE LocalHarness.sbom.cdx.json SHA256SUMS.txt THIRD_PARTY_NOTICES.md release-manifest.json static-security-summary.json)
typeset -a PACKAGE_ASSET_NAMES
PACKAGE_ASSET_NAMES=("${STABLE_PACKAGE_ASSET_NAMES[@]}")
typeset -a CHECKSUM_ENTRY_NAMES
CHECKSUM_ENTRY_NAMES=(Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE LocalHarness.sbom.cdx.json THIRD_PARTY_NOTICES.md release-manifest.json static-security-summary.json)
typeset -a MATERIAL_ASSET_NAMES
MATERIAL_ASSET_NAMES=()
if [[ "$RELEASE_PROFILE" == "stable" ]]; then
  [[ "$(/usr/bin/find "$PACKAGE" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 9 ]] || {
    echo "Public package must contain exactly the nine reviewed release assets." >&2; exit 1
  }
  for name in Fulmar.app.zip Fulmar.app.zip.sha256 Fulmar.dSYMs.zip LICENSE release-manifest.json static-security-summary.json LocalHarness.sbom.cdx.json THIRD_PARTY_NOTICES.md SHA256SUMS.txt; do
    [[ -f "$PACKAGE/$name" && ! -L "$PACKAGE/$name" \
       && "$(/usr/bin/stat -f %l "$PACKAGE/$name")" == 1 ]] || exit 1
  done
fi
TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-public-verify.XXXXXX)"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
ASSET_POLICY="$PROJECT_DIR/scripts/public-release-asset-policy.mjs"
PROVENANCE_RECORD="$PROJECT_DIR/Config/ThirdPartyBinaryProvenance.json"
FIRST_PARTY_LICENSE_POLICY="$PROJECT_DIR/scripts/first-party-license-policy.mjs"
# The private checkout-local notice-material cache prepared by
# scripts/bootstrap-source-checkout.sh; verified here, never acquired. A
# missing cache means the bootstrap is required, never a comparison bypass.
RUST_CRATE_MATERIALS="$PROJECT_DIR/build/third-party-notice-materials/sharp-libvips-1.3.3-rust-crate-materials"
NOTICE_MATERIALS_TOOL="$PROJECT_DIR/scripts/prepare-third-party-notice-materials.mjs"
PINNED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
MINIMUM_MACOS="$(/usr/bin/plutil -extract minimumMacOS raw -o - "$RELEASE_IDENTITY")"
PRODUCT_BUNDLE_ID="$(/usr/bin/plutil -extract bundleIdentifier raw -o - "$RELEASE_IDENTITY")"
SOURCE_INPUT_INVENTORY="$PROJECT_DIR/build/source-build-inputs.json"
SOURCE_INPUT_TOOL="$PROJECT_DIR/scripts/source-build-input-inventory.mjs"
STATIC_SECURITY_SUMMARY="$PROJECT_DIR/build/static-security-summary.json"
STATIC_SECURITY_VERIFIER="$PROJECT_DIR/scripts/verify-static-security-summary.mjs"
AUDIT_SUMMARY="$PROJECT_DIR/build/dependency-audit-summary.json"
PACKAGE_LOCK="$PROJECT_DIR/VendorRuntime/package-lock.json"
NOTARY_SUBMISSION_EVIDENCE="$PROJECT_DIR/build/notarization-submission.json"
NOTARY_LOG_EVIDENCE="$PROJECT_DIR/build/notarization-log.json"
[[ -x "$NODE" && "$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')" == "$PINNED_NODE_SHA256" ]] || {
  echo "Public distribution verification requires the exact reviewed Node bootstrap." >&2; exit 1
}
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
  PACKAGE_ASSET_NAMES=("${(@f)$("$NODE" "$ASSET_POLICY" names beta "$PROVENANCE_RECORD")}") || exit 1
  CHECKSUM_ENTRY_NAMES=("${(@f)$("$NODE" "$ASSET_POLICY" checksum-names beta "$PROVENANCE_RECORD")}") || exit 1
  MATERIAL_ASSET_NAMES=("${(@)PACKAGE_ASSET_NAMES:|STABLE_PACKAGE_ASSET_NAMES}")
  (( ${#PACKAGE_ASSET_NAMES[@]} == 12 && ${#CHECKSUM_ENTRY_NAMES[@]} == 11 && ${#MATERIAL_ASSET_NAMES[@]} == 3 )) || {
    echo "The beta asset policy did not yield exactly twelve assets, eleven checksum entries and three material assets." >&2; exit 1
  }
  [[ "$(/usr/bin/find "$PACKAGE" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 12 ]] || {
    echo "Public beta package must contain exactly the twelve reviewed beta release assets (the nine stable assets plus the verified material archive, its sidecar and its binding)." >&2; exit 1
  }
  for name in "${PACKAGE_ASSET_NAMES[@]}"; do
    [[ -f "$PACKAGE/$name" && ! -L "$PACKAGE/$name" \
       && "$(/usr/bin/stat -f %l "$PACKAGE/$name")" == 1 ]] || {
      echo "Public beta package is missing, links or duplicates the reviewed asset: $name" >&2; exit 1
    }
  done
fi
SNAPSHOT="$TEMP_ROOT/package"
/bin/mkdir -m 0700 "$SNAPSHOT"
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/SHA256SUMS.txt" "$SNAPSHOT/SHA256SUMS.txt" 1048576 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/Fulmar.app.zip.sha256" "$SNAPSHOT/Fulmar.app.zip.sha256" 1024 >/dev/null
[[ "$(/usr/bin/wc -l < "$SNAPSHOT/SHA256SUMS.txt" | /usr/bin/tr -d ' ')" == "${#CHECKSUM_ENTRY_NAMES[@]}" ]] || {
  echo "SHA256SUMS.txt has unexpected or unsafe entries." >&2; exit 1
}
checksum_names="$(/usr/bin/sed -E -n 's/^[0-9a-f]{64}  (.*)$/\1/p' "$SNAPSHOT/SHA256SUMS.txt")"
[[ "$checksum_names" == "${(F)CHECKSUM_ENTRY_NAMES}" ]] || {
  echo "SHA256SUMS.txt has unexpected or unsafe entries." >&2; exit 1
}
[[ "$(/usr/bin/wc -l < "$SNAPSHOT/Fulmar.app.zip.sha256" | /usr/bin/tr -d ' ')" == 1 \
   && "$(/usr/bin/sed -E -n 's/^[0-9a-f]{64}  (.*)$/\1/p' "$SNAPSHOT/Fulmar.app.zip.sha256")" == "Fulmar.app.zip" ]] || {
  echo "Fulmar.app.zip.sha256 has unexpected or unsafe content." >&2; exit 1
}
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/Fulmar.app.zip" "$SNAPSHOT/Fulmar.app.zip" >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/Fulmar.dSYMs.zip" "$SNAPSHOT/Fulmar.dSYMs.zip" 268435456 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/release-manifest.json" "$SNAPSHOT/release-manifest.json" 1048576 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/static-security-summary.json" "$SNAPSHOT/static-security-summary.json" 524288 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/LICENSE" "$SNAPSHOT/LICENSE" 1048576 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/LocalHarness.sbom.cdx.json" "$SNAPSHOT/LocalHarness.sbom.cdx.json" 67108864 >/dev/null
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/THIRD_PARTY_NOTICES.md" "$SNAPSHOT/THIRD_PARTY_NOTICES.md" 16777216 >/dev/null
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  for name in "${MATERIAL_ASSET_NAMES[@]}"; do
    case "$name" in
      *.tar) material_bound=2147483648 ;;
      *.tar.sha256) material_bound=1024 ;;
      *.binding.json) material_bound=4194304 ;;
      *) echo "Unexpected beta material asset name: $name" >&2; exit 1 ;;
    esac
    "$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" "$PACKAGE/$name" "$SNAPSHOT/$name" "$material_bound" >/dev/null
  done
  unset material_bound
fi
(cd "$SNAPSHOT" && /usr/bin/shasum -a 256 -c Fulmar.app.zip.sha256)
(cd "$SNAPSHOT" && /usr/bin/shasum -a 256 -c SHA256SUMS.txt)
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  # Beta material binding. The expected digest and source commit are the
  # operator's operands, never the package's own sidecar, checksum list or
  # binding. The checkout must be exactly the named revision; then the existing
  # verify-archive runs on private snapshots of the checksum-verified material
  # copies (the external package is not reopened) with that digest and commit,
  # and only HTTPS-authoritative acquisition is accepted.
  verify_source_commit_operand "$SOURCE_COMMIT_OPERAND"
  /bin/mkdir -m 0700 "$TEMP_ROOT/materials"
  "$NODE" "$ASSET_POLICY" admit-materials "$PROVENANCE_RECORD" "$SNAPSHOT" \
    "$MATERIAL_SHA256" "$SOURCE_COMMIT_OPERAND" "$TEMP_ROOT/materials" "$TEMP_ROOT" \
    > "$TEMP_ROOT/material-admission.json"
  for name in "${MATERIAL_ASSET_NAMES[@]}"; do
    /usr/bin/cmp -s "$SNAPSHOT/$name" "$TEMP_ROOT/materials/$name" || {
      echo "Beta material asset changed between the checksum snapshot and its admission: $name" >&2; exit 1
    }
  done
fi
"$NODE" "$FIRST_PARTY_LICENSE_POLICY" state "$PROJECT_DIR" --require-selected >/dev/null
"$NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" "$AUDIT_SUMMARY" "$PACKAGE_LOCK"
"$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
  "$RELEASE_IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$PROJECT_DIR/build"
"$NODE" "$PROJECT_DIR/scripts/verify-notarization-evidence.mjs" \
  "$NOTARY_SUBMISSION_EVIDENCE" "$NOTARY_LOG_EVIDENCE"
/usr/bin/cmp -s "$PROJECT_DIR/LICENSE" "$SNAPSHOT/LICENSE" || {
  echo "Public package LICENSE is not the exact owner-selected source file." >&2; exit 1
}
REVIEWED_MANIFEST="$TEMP_ROOT/reviewed-release-manifest.json"
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" \
  "$PROJECT_DIR/build/release-manifest.json" "$REVIEWED_MANIFEST" 1048576 >/dev/null
/usr/bin/cmp -s "$SNAPSHOT/release-manifest.json" "$REVIEWED_MANIFEST" || {
  echo "Public package manifest is not the exact locally reviewed release manifest." >&2; exit 1
}
REVIEWED_STATIC_SECURITY="$TEMP_ROOT/reviewed-static-security-summary.json"
"$NODE" "$PROJECT_DIR/scripts/snapshot-regular-file.mjs" \
  "$STATIC_SECURITY_SUMMARY" "$REVIEWED_STATIC_SECURITY" 524288 >/dev/null
/usr/bin/cmp -s "$SNAPSHOT/static-security-summary.json" "$REVIEWED_STATIC_SECURITY" || {
  echo "Public package static-security evidence is not the exact locally reviewed summary." >&2; exit 1
}
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$SNAPSHOT/static-security-summary.json" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json" >/dev/null
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$SNAPSHOT/Fulmar.app.zip" >/dev/null
/usr/bin/ditto -x -k --noqtn "$SNAPSHOT/Fulmar.app.zip" "$TEMP_ROOT/extracted"
APP="$TEMP_ROOT/extracted/Fulmar.app"
[[ -d "$APP" && "$(/usr/bin/find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] || exit 1
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$SNAPSHOT/Fulmar.app.zip" "$APP" >/dev/null
/usr/bin/plutil -convert json -o "$TEMP_ROOT/info.json" "$APP/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/migration-xpc-info.json" \
  "$APP/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/Info.plist"
/usr/bin/plutil -convert json -o "$TEMP_ROOT/broker-xpc-info.json" \
  "$APP/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/Info.plist"
"$NODE" "$PROJECT_DIR/scripts/verify-xpc-service-info.mjs" \
  "$RELEASE_IDENTITY" "$TEMP_ROOT/migration-xpc-info.json" "$TEMP_ROOT/broker-xpc-info.json"
"$NODE" "$PROJECT_DIR/scripts/verify-release-manifest.mjs" \
  "$SNAPSHOT/release-manifest.json" "$SNAPSHOT/Fulmar.app.zip" "$TEMP_ROOT/info.json" \
  "$SNAPSHOT/Fulmar.dSYMs.zip" \
  "$PROJECT_DIR/VendorRuntime.inventory.json" "$PROJECT_DIR/build/runtime-unsigned-inventory.json" \
  "$PROJECT_DIR/build/runtime-signables.json" "$PROJECT_DIR/build/runtime-release-inventory.json" \
  "$PROJECT_DIR/build/source-build-inputs.json" "$SNAPSHOT/static-security-summary.json" \
  "$PROJECT_DIR/build/toolchain-inventory.json" >/dev/null
/bin/zsh -f "$PROJECT_DIR/scripts/verify-macho-compatibility.sh" \
  "$APP" "$PROJECT_DIR/build/runtime-signables.json" "$MINIMUM_MACOS"
SBOM="$APP/Contents/Resources/LocalHarness.sbom.cdx.json"
NOTICES="$APP/Contents/Resources/THIRD_PARTY_NOTICES.md"
/usr/bin/cmp -s "$SNAPSHOT/LocalHarness.sbom.cdx.json" "$SBOM"
/usr/bin/cmp -s "$SNAPSHOT/THIRD_PARTY_NOTICES.md" "$NOTICES"
"$NODE" "$FIRST_PARTY_LICENSE_POLICY" verify-bundle \
  "$PROJECT_DIR" "$APP/Contents/Resources/LICENSE" --require-selected >/dev/null
/usr/bin/cmp -s "$SNAPSHOT/LICENSE" "$APP/Contents/Resources/LICENSE"
"$NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$SNAPSHOT/Fulmar.dSYMs.zip" "" "Fulmar.dSYMs" >/dev/null
/bin/mkdir -m 0700 "$TEMP_ROOT/symbols"
/usr/bin/ditto -x -k --noqtn "$SNAPSHOT/Fulmar.dSYMs.zip" "$TEMP_ROOT/symbols"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-native-symbol-privacy.sh" "$APP" "$TEMP_ROOT/symbols/Fulmar.dSYMs"
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

details="$(/usr/bin/codesign -dvvv "$APP" 2>&1)"
team="$(print -r -- "$details" | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
[[ "$details" == *"Authority=Developer ID Application:"* \
   && "$details" == *"Timestamp="* \
   && "$details" == *"flags="*"runtime"* ]] \
  && [[ "$team" =~ '^[A-Z0-9]{10}$' ]] || {
  echo "Public verification requires timestamped Developer ID Application signing with hardened runtime." >&2
  exit 1
}
/usr/bin/codesign --verify --deep --strict --verbose=4 "$APP"

extract_entitlements() {
  local target="$1"
  local label="$2"
  local plist="$TEMP_ROOT/${label}.entitlements.plist"
  local stderr="$TEMP_ROOT/${label}.entitlements.stderr"
  local json="$TEMP_ROOT/${label}.entitlements.json"
  set +e
  /usr/bin/codesign -d --xml --entitlements - "$target" >"$plist" 2>"$stderr"
  local extraction_status=$?
  set -e
  local unexpected_stderr
  unexpected_stderr="$(/usr/bin/sed -E '/^Executable=/d; /^[[:space:]]*$/d' "$stderr")"
  (( extraction_status == 0 )) && [[ -z "$unexpected_stderr" ]] || {
    echo "Entitlement extraction failed or emitted an unexpected diagnostic: $target" >&2
    /bin/cat "$stderr" >&2
    exit 1
  }
  if [[ -s "$plist" ]]; then
    /usr/bin/plutil -lint "$plist" >/dev/null
    /usr/bin/plutil -convert json -o "$json" "$plist"
  else
    print -r -- '{}' >"$json"
  fi
  print -r -- "$json"
}

assert_exact_entitlements() {
  local target="$1"
  local expected="$2"
  local label="$3"
  local actual_json
  local expected_json="$TEMP_ROOT/${label}.expected-entitlements.json"
  actual_json="$(extract_entitlements "$target" "$label")"
  /usr/bin/plutil -convert json -o "$expected_json" "$expected"
  "$NODE" -e '
    const fs = require("node:fs");
    const sort = (value) => Array.isArray(value) ? value.map(sort)
      : value && typeof value === "object"
        ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])]))
        : value;
    const [actual, expected] = process.argv.slice(1)
      .map((path) => sort(JSON.parse(fs.readFileSync(path, "utf8"))));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) process.exit(1);
  ' "$actual_json" "$expected_json" || {
    echo "Public executable entitlements do not match the reviewed source policy: $target" >&2
    exit 1
  }
}

assert_no_entitlements() {
  local target="$1"
  local label="$2"
  local actual_json
  actual_json="$(extract_entitlements "$target" "$label")"
  "$NODE" -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 0) process.exit(1);
  ' "$actual_json" || {
    echo "An executable that should have no entitlements carries an entitlement: $target" >&2
    exit 1
  }
}

typeset -a signed_targets
signed_targets=("$APP")
while IFS= read -r signed_target; do
  signed_targets+=("$signed_target")
done < <(/usr/bin/find "$APP/Contents/MacOS" -mindepth 1 -maxdepth 1 -print)
MIGRATION_XPC="$APP/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc"
BROKER_XPC="$APP/Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc"
signed_targets+=("$MIGRATION_XPC")
signed_targets+=("$BROKER_XPC")
RUNTIME_SIGNABLE_PATHS="$TEMP_ROOT/runtime-signable-paths.txt"
"$NODE" -e '
  const fs = require("node:fs");
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!Array.isArray(value.paths) || value.paths.length < 1 || value.paths.length > 64
      || value.paths.some((path) => typeof path !== "string" || path.length < 1
        || path.length > 1024 || path.includes("\n") || path.includes("\r"))) process.exit(1);
  process.stdout.write(`${value.paths.join("\n")}\n`);
' "$PROJECT_DIR/build/runtime-signables.json" > "$RUNTIME_SIGNABLE_PATHS"
RUNTIME_SIGNABLE_BYTES="$(/usr/bin/stat -f '%z' "$RUNTIME_SIGNABLE_PATHS")"
[[ -f "$RUNTIME_SIGNABLE_PATHS" && ! -L "$RUNTIME_SIGNABLE_PATHS" \
   && "$RUNTIME_SIGNABLE_BYTES" == <-> \
   && "$RUNTIME_SIGNABLE_BYTES" -ge 1 \
   && "$RUNTIME_SIGNABLE_BYTES" -le 65536 ]] || {
  echo "Runtime signing inventory could not be materialized safely." >&2
  exit 1
}
while IFS= read -r relative; do
  signed_targets+=("$APP/Contents/Resources/Runtime/$relative")
done < "$RUNTIME_SIGNABLE_PATHS"
target_index=0
for target in "${signed_targets[@]}"; do
  target_index=$((target_index + 1))
  /usr/bin/codesign --verify --strict --verbose=4 "$target"
  target_details="$(/usr/bin/codesign -dvvv "$target" 2>&1)"
  [[ "$target_details" == *"TeamIdentifier=$team"* \
     && "$target_details" == *"Authority=Developer ID Application:"* \
     && "$target_details" == *"flags="*"runtime"* \
     && "$target_details" == *"Timestamp="* \
     && "$target_details" != *"Signature=adhoc"* ]] || exit 1
  if [[ "$target" == "$APP" || "$target" == "$APP/Contents/MacOS/LocalHarness" ]]; then
    [[ "$target_details" == *"Identifier=$PRODUCT_BUNDLE_ID"* ]] || exit 1
    assert_exact_entitlements "$target" "$PROJECT_DIR/Resources/LocalHarness.entitlements" "target-$target_index"
  elif [[ "$target" == "$APP/Contents/Resources/Runtime/node" ]]; then
    assert_exact_entitlements "$target" "$PROJECT_DIR/Resources/NodeRuntime.entitlements" "target-$target_index"
  elif [[ "$target" == "$MIGRATION_XPC" ]]; then
    [[ "$target_details" == *"Identifier=$PRODUCT_BUNDLE_ID.credential-helper"* ]] || exit 1
    assert_exact_entitlements \
      "$target" "$PROJECT_DIR/Resources/CredentialMigrationService.entitlements" "target-$target_index"
  elif [[ "$target" == "$BROKER_XPC" ]]; then
    [[ "$target_details" == *"Identifier=$PRODUCT_BUNDLE_ID.credential-helper"* ]] || exit 1
    assert_exact_entitlements \
      "$target" "$PROJECT_DIR/Resources/CredentialBrokerService.entitlements" "target-$target_index"
  else
    case "$target" in
      "$APP/Contents/MacOS/LocalHarnessCredentialHelper") expected_identifier="$PRODUCT_BUNDLE_ID.credential-helper" ;;
      "$APP/Contents/MacOS/LocalHarnessSchedulerHelper") expected_identifier="$PRODUCT_BUNDLE_ID.scheduler-helper" ;;
      "$APP/Contents/MacOS/LocalHarnessUpdateHelper") expected_identifier="$PRODUCT_BUNDLE_ID.update-helper" ;;
      "$APP/Contents/MacOS/LocalHarnessSandboxRunner") expected_identifier="$PRODUCT_BUNDLE_ID.sandbox-runner" ;;
      "$APP/Contents/MacOS/LocalHarnessRuntimeLease") expected_identifier="$PRODUCT_BUNDLE_ID.runtime-lease" ;;
      *) expected_identifier="" ;;
    esac
    [[ -z "$expected_identifier" || "$target_details" == *"Identifier=$expected_identifier"* ]] || exit 1
    assert_no_entitlements "$target" "target-$target_index"
  fi
done
HELPER_DR="$(/usr/bin/codesign -d -r- "$APP/Contents/MacOS/LocalHarnessCredentialHelper" 2>&1 \
  | /usr/bin/sed -n 's/^designated => //p')"
SERVICE_DR="$(/usr/bin/codesign -d -r- "$MIGRATION_XPC" 2>&1 \
  | /usr/bin/sed -n 's/^designated => //p')"
BROKER_DR="$(/usr/bin/codesign -d -r- "$BROKER_XPC" 2>&1 \
  | /usr/bin/sed -n 's/^designated => //p')"
[[ -n "$HELPER_DR" && "$SERVICE_DR" == "$HELPER_DR" \
   && "$BROKER_DR" == "$HELPER_DR" ]] || {
  echo "Credential services and helper do not share the reviewed Keychain requirement." >&2
  exit 1
}
/usr/bin/xcrun stapler validate "$APP"
/usr/sbin/spctl --assess --type execute --verbose=4 "$APP"
"$NODE" "$SOURCE_INPUT_TOOL" verify "$PROJECT_DIR" "$SOURCE_INPUT_INVENTORY"
"$NODE" "$STATIC_SECURITY_VERIFIER" \
  "$STATIC_SECURITY_SUMMARY" "$SOURCE_INPUT_INVENTORY" "$PROJECT_DIR/Config/SemgrepRules.json"
"$NODE" "$PROJECT_DIR/scripts/runtime-inventory.mjs" \
  verify "$PROJECT_DIR/VendorRuntime" "$PROJECT_DIR/VendorRuntime.inventory.json" VendorRuntime
"$NODE" "$PROJECT_DIR/scripts/toolchain-inventory.mjs" \
  verify "$PROJECT_DIR/build/toolchain-inventory.json"
"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" "$AUDIT_SUMMARY" "$PACKAGE_LOCK"
"$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
  "$RELEASE_IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$PROJECT_DIR/build"
PUBLIC_CANDIDATE_SHA256="$(/usr/bin/plutil -extract sha256 raw -o - "$SNAPSHOT/release-manifest.json")"
PUBLIC_VERSION="$(/usr/bin/plutil -extract version raw -o - "$SNAPSHOT/release-manifest.json")"
PUBLIC_BUILD="$(/usr/bin/plutil -extract build raw -o - "$SNAPSHOT/release-manifest.json")"
"$NODE" "$PROJECT_DIR/scripts/verify-public-external-evidence.mjs" \
  "$PUBLIC_EXTERNAL_EVIDENCE" "$PUBLIC_CANDIDATE_SHA256" "$PUBLIC_VERSION" "$PUBLIC_BUILD" \
  "${EVIDENCE_PROFILE_ARGUMENTS[@]}"
if [[ "$RELEASE_PROFILE" == "beta" ]]; then
  # The app candidate digest and the material archive digest identify different
  # artefacts; an operator who supplied the ZIP digest as the material digest is
  # refused above by verify-archive, and never accepted here by coincidence.
  [[ "$MATERIAL_SHA256" != "$PUBLIC_CANDIDATE_SHA256" ]] || {
    echo "The material archive digest equals the app candidate digest; they are different artefacts." >&2; exit 1
  }
  echo "Public BETA distribution verification passed for the exact manifest-bound archive, the verified third-party material archive (sha256 $MATERIAL_SHA256, bound to source commit $SOURCE_COMMIT_OPERAND) and Developer ID team $team (manual install, in-app updater disabled; not stable qualification; the material archive closes no licensing obligation)."
else
  echo "Public distribution verification passed for the exact manifest-bound archive and Developer ID team $team."
fi
