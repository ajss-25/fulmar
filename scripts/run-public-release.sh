#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
TEST_MODE=0
if [[ -n "${FULMAR_PUBLIC_RELEASE_TEST_SEAM:-}" ]]; then
  [[ "$FULMAR_PUBLIC_RELEASE_TEST_SEAM" == "1" ]] || {
    print -u2 "The public-release test seam accepts only the exact value 1."
    exit 64
  }
  case "$PROJECT_DIR" in
    /private/tmp/fulmar-public-release-test.*) ;;
    *)
      print -u2 "The public-release test seam is confined to a copied /private/tmp test root."
      exit 64
      ;;
  esac
  [[ "${PROJECT_DIR:A}" == "$PROJECT_DIR" \
     && "$(/usr/bin/stat -f '%u:%Lp:%HT' "$PROJECT_DIR")" == "$(/usr/bin/id -u):700:Directory" ]] || {
    print -u2 "The public-release test root is not one owner-private physical directory."
    exit 64
  }
  TEST_MODE=1
fi
MODE="fresh"
if [[ "${1:-}" == "--finalize" ]]; then
  MODE="finalize"
  shift
fi
(( $# == 0 )) || {
  print -u2 "Usage: run-public-release.sh [--finalize]"
  exit 64
}

umask 077
export PATH="$SAFE_PATH"
RELEASE_IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
BUILD_DIR="$PROJECT_DIR/build"
APP="/private/tmp/LocalHarnessBuild/Fulmar.app"
if (( TEST_MODE == 1 )); then
  BUILD_DIR="$PROJECT_DIR/test-state/build"
  APP="$PROJECT_DIR/test-state/candidate/Fulmar.app"
fi
ARCHIVE="$BUILD_DIR/Fulmar.app.zip"
MANIFEST="$BUILD_DIR/release-manifest.json"
NOTARY_SUBMISSION="$BUILD_DIR/notarization-submission.json"
NOTARY_LOG="$BUILD_DIR/notarization-log.json"
PUBLIC_ASSETS="$BUILD_DIR/public-release-assets"
PUBLIC_EXTERNAL_EVIDENCE="$BUILD_DIR/public-external-evidence.json"
OPERATOR_HOME="${HOME:-}"
if (( TEST_MODE == 1 )); then
  OPERATOR_HOME="$PROJECT_DIR/test-state/home"
fi
OPERATOR_USER="$(/usr/bin/id -un)"
TEMP_ROOT=""

cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$TEMP_ROOT" && "$TEMP_ROOT" == /private/tmp/fulmar-public-operator.* \
     && -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]]; then
    /bin/rm -rf -- "$TEMP_ROOT"
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

fail_configuration() {
  print -u2 "$1"
  exit 64
}

[[ "$OPERATOR_HOME" == /* && -d "$OPERATOR_HOME" && ! -L "$OPERATOR_HOME" \
   && "$OPERATOR_HOME" != *$'\n'* && "$OPERATOR_HOME" != *$'\r'* ]] || {
  fail_configuration "Public release requires one real absolute user home for Keychain access."
}
[[ -f "$RELEASE_IDENTITY" && ! -L "$RELEASE_IDENTITY" ]] || {
  print -u2 "Public release requires the reviewed release identity."
  exit 1
}

SIGN_IDENTITY="${LOCAL_HARNESS_SIGN_IDENTITY:-}"
SIGNING_KEYCHAIN="${LOCAL_HARNESS_SIGNING_KEYCHAIN:-}"
NOTARY_PROFILE="${LOCAL_HARNESS_NOTARY_PROFILE:-}"
[[ -n "$SIGN_IDENTITY" ]] || {
  fail_configuration "Public release requires LOCAL_HARNESS_SIGN_IDENTITY with the exact Developer ID Application certificate name."
}
[[ -n "$SIGNING_KEYCHAIN" ]] || {
  fail_configuration "Public release requires LOCAL_HARNESS_SIGNING_KEYCHAIN with the absolute signing-Keychain path."
}
[[ -n "$NOTARY_PROFILE" ]] || {
  fail_configuration "Public release requires LOCAL_HARNESS_NOTARY_PROFILE with an Apple notarytool Keychain profile."
}
for value in "$SIGN_IDENTITY" "$SIGNING_KEYCHAIN" "$NOTARY_PROFILE"; do
  [[ "${#value}" -le 512 && "$value" != *$'\n'* && "$value" != *$'\r'* \
     && "$value" != *$'\0'* ]] || fail_configuration "Public release received an unsafe signing option."
done
[[ "$SIGN_IDENTITY" =~ '^Developer ID Application: .+ \([A-Z0-9]{10}\)$' ]] || {
  fail_configuration "LOCAL_HARNESS_SIGN_IDENTITY must be the exact Developer ID Application certificate name, including its 10-character Team ID."
}
[[ "$SIGNING_KEYCHAIN" == /* && -f "$SIGNING_KEYCHAIN" && ! -L "$SIGNING_KEYCHAIN" \
   && "${SIGNING_KEYCHAIN:A}" == "$SIGNING_KEYCHAIN" \
   && "$(/usr/bin/stat -f '%u:%l' "$SIGNING_KEYCHAIN")" == "$(/usr/bin/id -u):1" ]] || {
  fail_configuration "LOCAL_HARNESS_SIGNING_KEYCHAIN must be one owner-controlled absolute regular file."
}
[[ "${LOCAL_HARNESS_SIGN_TIMESTAMP:-1}" == "1" ]] || {
  fail_configuration "Public release requires LOCAL_HARNESS_SIGN_TIMESTAMP=1; timestamp disabling and auto mode are not accepted."
}

# `find-identity -p codesigning` lists only identities whose certificate and
# private key are usable for code signing. Match the quoted common name exactly;
# a substring, SHA-1-only selector, ad-hoc identity, or second ambiguous match is
# not sufficient authority for a public release.
IDENTITY_LISTING=""
if (( TEST_MODE == 1 )); then
  IDENTITY_LISTING="  1) 0000000000000000000000000000000000000000 \"$SIGN_IDENTITY\""
else
  IDENTITY_LISTING="$(/usr/bin/security find-identity -v -p codesigning "$SIGNING_KEYCHAIN" 2>/dev/null)" || {
    fail_configuration "The signing Keychain could not provide a usable code-signing identity; unlock or provision it before retrying."
  }
fi
typeset -i IDENTITY_MATCHES=0
while IFS= read -r identity_line; do
  if [[ "$identity_line" == *\"* ]]; then
    listed_name="${identity_line#*\"}"
    listed_name="${listed_name%%\"*}"
    if [[ "$listed_name" == "$SIGN_IDENTITY" ]]; then
      IDENTITY_MATCHES=$((IDENTITY_MATCHES + 1))
    fi
  fi
done <<< "$IDENTITY_LISTING"
(( IDENTITY_MATCHES == 1 )) || {
  fail_configuration "The signing Keychain must contain exactly one usable identity named $SIGN_IDENTITY."
}
unset IDENTITY_LISTING identity_line listed_name

if (( TEST_MODE == 0 )); then
  PINNED_NODE_SHA256="$(/usr/bin/plutil -extract runtime.nodeSHA256 raw -o - "$RELEASE_IDENTITY")"
  [[ -x "$NODE" && ! -L "$NODE" \
     && "$(/usr/bin/shasum -a 256 "$NODE" | /usr/bin/awk '{print $1}')" == "$PINNED_NODE_SHA256" ]] || {
    print -u2 "Public release requires the exact reviewed Node bootstrap."
    exit 1
  }
fi

run_reviewed_node() {
  /usr/bin/env -i \
    "HOME=$OPERATOR_HOME" "PATH=$SAFE_PATH" "USER=$OPERATOR_USER" "LOGNAME=$OPERATOR_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 TMPDIR=/private/tmp/ \
    "$NODE" "$@"
}

run_clean_script() {
  local script="$1"
  shift
  /usr/bin/env -i \
    "HOME=$OPERATOR_HOME" "CFFIXED_USER_HOME=$OPERATOR_HOME" \
    "PATH=$SAFE_PATH" "USER=$OPERATOR_USER" "LOGNAME=$OPERATOR_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 TMPDIR=/private/tmp/ \
    /bin/zsh -f "$script" "$@"
}

run_static_scan() {
  /usr/bin/env -i \
    "HOME=$OPERATOR_HOME" "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin" \
    "USER=$OPERATOR_USER" "LOGNAME=$OPERATOR_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 TMPDIR=/private/tmp/ \
    /bin/sh -p "$PROJECT_DIR/scripts/run-static-security-scan.sh"
}

run_public_build() {
  /usr/bin/env -i \
    "HOME=$OPERATOR_HOME" "CFFIXED_USER_HOME=$OPERATOR_HOME" \
    "PATH=$SAFE_PATH" "USER=$OPERATOR_USER" "LOGNAME=$OPERATOR_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 TMPDIR=/private/tmp/ \
    "LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1" \
    "LOCAL_HARNESS_SIGN_IDENTITY=$SIGN_IDENTITY" \
    "LOCAL_HARNESS_SIGNING_KEYCHAIN=$SIGNING_KEYCHAIN" \
    "LOCAL_HARNESS_SIGN_TIMESTAMP=1" \
    "LOCAL_HARNESS_NOTARY_PROFILE=$NOTARY_PROFILE" \
    /bin/zsh -f "$PROJECT_DIR/scripts/build-app.sh"
}

retain_public_candidate() {
  /usr/bin/env -i \
    "HOME=$OPERATOR_HOME" "PATH=$SAFE_PATH" "USER=$OPERATOR_USER" "LOGNAME=$OPERATOR_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 TMPDIR=/private/tmp/ \
    LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1 \
    /bin/zsh -f "$PROJECT_DIR/scripts/retain-release-verification.sh" \
      --signing-profile private-stable "$APP"
}

read_candidate_field() {
  /usr/bin/plutil -extract "$1" raw -o - "$MANIFEST"
}

verify_public_candidate() {
  for required in "$APP" "$ARCHIVE" "$MANIFEST" "$NOTARY_SUBMISSION" "$NOTARY_LOG"; do
    [[ ( -f "$required" || -d "$required" ) && ! -L "$required" ]] || {
      print -u2 "The retained public candidate is incomplete or linked: ${required:t}."
      return 1
    }
  done
  for evidence in "$NOTARY_SUBMISSION" "$NOTARY_LOG"; do
    [[ -f "$evidence" && ! -L "$evidence" \
       && "$(/usr/bin/stat -f '%u:%Lp:%l' "$evidence")" == "$(/usr/bin/id -u):600:1" ]] || {
      print -u2 "The retained Apple evidence is not one owner-private regular file: ${evidence:t}."
      return 1
    }
  done

  run_reviewed_node "$PROJECT_DIR/scripts/verify-notarization-evidence.mjs" \
    "$NOTARY_SUBMISSION" "$NOTARY_LOG"
  run_reviewed_node "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
    "$RELEASE_IDENTITY" "$MANIFEST" "$BUILD_DIR"

  local signature_details
  signature_details="$(/usr/bin/codesign -dvvv "$APP" 2>&1)"
  [[ "$signature_details" == *"Authority=$SIGN_IDENTITY"* \
     && "$signature_details" == *"Timestamp="* \
     && "$signature_details" == *"flags="*"runtime"* \
     && "$signature_details" != *"Signature=adhoc"* ]] || {
    print -u2 "The retained candidate does not use the selected timestamped Developer ID Application identity and hardened runtime."
    return 1
  }
  /usr/bin/codesign --verify --deep --strict --verbose=4 "$APP"
  /usr/bin/xcrun stapler validate "$APP"

  TEMP_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-public-operator.XXXXXX)"
  /bin/chmod 0700 "$TEMP_ROOT"
  run_reviewed_node "$PROJECT_DIR/scripts/verify-zip-entries.mjs" "$ARCHIVE" >/dev/null
  /usr/bin/ditto -x -k --noqtn "$ARCHIVE" "$TEMP_ROOT/extracted"
  local archived_app="$TEMP_ROOT/extracted/Fulmar.app"
  [[ -d "$archived_app" && ! -L "$archived_app" \
     && "$(/usr/bin/find "$TEMP_ROOT/extracted" -mindepth 1 -maxdepth 1 \
       | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == "1" ]] || {
    print -u2 "The final public ZIP does not contain exactly one Fulmar.app."
    return 1
  }
  run_reviewed_node "$PROJECT_DIR/scripts/verify-release-tree.mjs" "$APP" "$archived_app"
  /usr/bin/codesign --verify --deep --strict --verbose=4 "$archived_app"
  /usr/bin/xcrun stapler validate "$archived_app"
  local archived_signature_details
  archived_signature_details="$(/usr/bin/codesign -dvvv "$archived_app" 2>&1)"
  [[ "$archived_signature_details" == *"Authority=$SIGN_IDENTITY"* \
     && "$archived_signature_details" == *"Timestamp="* \
     && "$archived_signature_details" == *"flags="*"runtime"* \
     && "$archived_signature_details" != *"Signature=adhoc"* ]] || {
    print -u2 "The regenerated final ZIP does not contain the selected timestamped and stapled Developer ID candidate."
    return 1
  }
  /bin/rm -rf -- "$TEMP_ROOT"
  TEMP_ROOT=""
}

if (( TEST_MODE == 1 )); then
  TEST_SEAM="$PROJECT_DIR/test-support/run-public-release-test-seam.zsh"
  [[ -f "$TEST_SEAM" && ! -L "$TEST_SEAM" \
     && "$(/usr/bin/stat -f '%u:%Lp:%l:%HT' "$TEST_SEAM")" == "$(/usr/bin/id -u):600:1:Regular File" ]] || {
    fail_configuration "The public-release test seam is not one owner-private regular file inside the test root."
  }
  source "$TEST_SEAM"
  for confined_path in "$BUILD_DIR" "$APP" "$ARCHIVE" "$MANIFEST" \
    "$NOTARY_SUBMISSION" "$NOTARY_LOG" "$PUBLIC_ASSETS" "$PUBLIC_EXTERNAL_EVIDENCE"; do
    [[ "$confined_path" == "$PROJECT_DIR/"* ]] || {
      fail_configuration "The public-release test seam attempted to escape its temporary root."
    }
  done
  unset confined_path
fi

# Fail before a costly timestamped build when the owner has not selected the
# first-party terms that must be embedded before code signing.
run_reviewed_node "$PROJECT_DIR/scripts/first-party-license-policy.mjs" \
  state "$PROJECT_DIR" --require-selected >/dev/null

if [[ "$MODE" == "fresh" ]]; then
  [[ ! -e "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" ]] || {
    print -u2 "A retained public asset set already exists. Preserve it and use 'make public-release-finalize' for its exact candidate, or move it aside before creating a new candidate."
    exit 1
  }
  run_static_scan
  run_public_build
  retain_public_candidate
else
  print "Finalizing the retained public candidate without rebuilding it."
fi

verify_public_candidate

CANDIDATE_SHA256="$(read_candidate_field sha256)"
CANDIDATE_VERSION="$(read_candidate_field version)"
CANDIDATE_BUILD="$(read_candidate_field build)"
if [[ ! -f "$PUBLIC_EXTERNAL_EVIDENCE" || -L "$PUBLIC_EXTERNAL_EVIDENCE" ]]; then
  print -u2 "Retained notarized Fulmar $CANDIDATE_VERSION build $CANDIDATE_BUILD candidate $CANDIDATE_SHA256."
  print -u2 "Public release is intentionally paused: complete the eight manual gates and create owner-private build/public-external-evidence.json for this exact candidate, then run 'make public-release-finalize'. Do not rebuild."
  exit 78
fi
if ! run_reviewed_node "$PROJECT_DIR/scripts/verify-public-external-evidence.mjs" \
  "$PUBLIC_EXTERNAL_EVIDENCE" "$CANDIDATE_SHA256" "$CANDIDATE_VERSION" "$CANDIDATE_BUILD"; then
  print -u2 "Public external evidence is incomplete or belongs to another candidate. Correct it for $CANDIDATE_SHA256, then run 'make public-release-finalize'. Do not rebuild."
  exit 78
fi

if [[ ! -e "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" ]]; then
  run_clean_script "$PROJECT_DIR/scripts/prepare-public-release-assets.sh" \
    "$ARCHIVE" "$MANIFEST" "$PUBLIC_ASSETS" \
    "$CANDIDATE_SHA256" "$CANDIDATE_VERSION" "$CANDIDATE_BUILD"
fi
run_clean_script "$PROJECT_DIR/scripts/verify-public-distribution.sh" \
  "$PUBLIC_ASSETS" "$PUBLIC_EXTERNAL_EVIDENCE"
print "Public release qualification passed for retained Fulmar $CANDIDATE_VERSION build $CANDIDATE_BUILD candidate $CANDIDATE_SHA256. No upload or publication was performed."
