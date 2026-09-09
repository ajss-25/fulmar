#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/root-group-lock.zsh"
IDENTITY="$PROJECT_DIR/Config/ReleaseIdentity.json"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
VERIFIER="$PROJECT_DIR/scripts/verify-release.sh"
SIGNING_PROFILE=""
if [[ "${1:-}" == "--signing-profile" ]]; then
  (( $# >= 2 )) || { print -u2 "Missing retained-evidence signing profile."; exit 64; }
  SIGNING_PROFILE="$2"
  shift 2
fi
INTERNAL_STAGE=0
STAGING_SET=""
if [[ "${1:-}" == "--internal-stage" ]]; then
  (( $# == 3 )) || { print -u2 "Invalid internal evidence-stage invocation."; exit 64; }
  INTERNAL_STAGE=1
  STAGING_SET="$2"
  APP_DIR="$3"
else
  (( $# <= 1 )) || { print -u2 "Usage: retain-release-verification.sh --signing-profile private-stable [/exact/Fulmar.app]"; exit 64; }
  APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
fi

# Tests may substitute a tiny verifier only from a disposable, unmistakably
# test-owned project tree. The production checkout can never activate this seam.
if [[ -n "${FULMAR_RELEASE_EVIDENCE_TEST_VERIFIER:-}" ]]; then
  [[ "${FULMAR_RELEASE_EVIDENCE_TEST_ONLY:-0}" == "1" \
     && "$PROJECT_DIR" == /private/tmp/fulmar-release-evidence-test.*/* ]] || {
    print -u2 "The release-evidence test seam is unavailable in a production tree."
    exit 64
  }
  VERIFIER="$FULMAR_RELEASE_EVIDENCE_TEST_VERIFIER"
elif [[ "$SIGNING_PROFILE" != "private-stable" ]]; then
  print -u2 "Release evidence retention requires --signing-profile private-stable."
  exit 64
fi

[[ -f "$IDENTITY" && ! -L "$IDENTITY" && -x "$NODE" && ! -L "$NODE" \
   && -f "$VERIFIER" && ! -L "$VERIFIER" ]] || {
  print -u2 "Release evidence inputs are unavailable or linked."
  exit 1
}

VERSION="$(/usr/bin/plutil -extract appVersion raw -o - "$IDENTITY")"
BUILD="$(/usr/bin/plutil -extract appBuild raw -o - "$IDENTITY")"
[[ "$VERSION" == <->.<->.<-> && "$BUILD" == <-> ]] || {
  print -u2 "Release identity contains an invalid version or build."
  exit 1
}

BUILD_DIR="$PROJECT_DIR/build"
EVIDENCE_BASE="release-verify-$VERSION-build$BUILD"
if [[ ! -e "$BUILD_DIR" && ! -L "$BUILD_DIR" ]]; then /bin/mkdir -m 0700 "$BUILD_DIR"; fi
[[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" \
   && "$BUILD_DIR" == "${BUILD_DIR:A}" \
   && "$(/usr/bin/stat -f '%u:%Lp' "$BUILD_DIR")" == "$(/usr/bin/id -u):700" ]] || {
  print -u2 "The release evidence build directory must be a real owner-private directory."
  exit 1
}
umask 077
TEST_KILL_AT="${FULMAR_RELEASE_EVIDENCE_TEST_KILL_AT:-}"
if [[ -n "$TEST_KILL_AT" ]]; then
  [[ "${FULMAR_RELEASE_EVIDENCE_TEST_ONLY:-0}" == "1" \
     && "$PROJECT_DIR" == /private/tmp/fulmar-release-evidence-test.*/* \
     && ( "$TEST_KILL_AT" == "before-publish" \
       || "$TEST_KILL_AT" == "after-publish-before-parent-fsync" ) ]] || {
    print -u2 "The release-evidence kill seam is unavailable in a production tree."
    exit 64
  }
fi
LOCK_DIR="/private/tmp/LocalHarnessBuild.lock"
if [[ "${FULMAR_RELEASE_EVIDENCE_TEST_ONLY:-0}" == "1" \
   && "$PROJECT_DIR" == /private/tmp/fulmar-release-evidence-test.*/* ]]; then
  FIXTURE_PARENT="${PROJECT_DIR:h}"
  FIXTURE_NAME="${FIXTURE_PARENT:t}"
  FIXTURE_NONCE="${FIXTURE_NAME#fulmar-release-evidence-test.}"
  [[ "$PROJECT_DIR" == "$FIXTURE_PARENT/project" \
     && "$FIXTURE_NAME" =~ '^fulmar-release-evidence-test\.[A-Za-z0-9]{6}$' \
     && "$FIXTURE_NONCE" =~ '^[A-Za-z0-9]{6}$' ]] || {
    print -u2 "The release-evidence fixture has no exact private lock identity."
    exit 64
  }
  LOCK_DIR="/private/tmp/FulmarEvidenceTest-${FIXTURE_NONCE}.lock"
fi

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "Release evidence retention inherited an invalid root-watchdog attestation."
  exit 126
elif (( ROOT_WATCHDOG_STATE == 1 )); then
  (( INTERNAL_STAGE == 0 )) || { print -u2 "Internal evidence staging requires an authenticated root."; exit 126; }
  STAGING_SET="$(/usr/bin/mktemp -d "$BUILD_DIR/.$EVIDENCE_BASE-set.XXXXXX")"
  /bin/chmod 0700 "$STAGING_SET"
  SUCCESSOR_TOKEN="$("$NODE" -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
  [[ "${#SUCCESSOR_TOKEN}" == 64 && "$SUCCESSOR_TOKEN" != *[^a-f0-9]* ]] || exit 1
  SUCCESSOR_RECORD="FULMAR_LOCK_SUCCESSOR_V1
$$
$SUCCESSOR_TOKEN"
  DRIVER_LOCK_OWNED=0
  release_driver_lock() {
    (( DRIVER_LOCK_OWNED == 1 )) || return 0
    local owner="$LOCK_DIR/owner.pid" identity size existing
    identity="$(/usr/bin/stat -f '%u:%Lp:%l' "$owner" 2>/dev/null || true)"
    size="$(/usr/bin/stat -f '%z' "$owner" 2>/dev/null || true)"
    [[ "$identity" == "$(/usr/bin/id -u):600:1" \
       && "$size" == <-> && "$size" -ge 1 && "$size" -le 1024 ]] || return 1
    existing="$(<"$owner")"
    [[ "$existing" == "$SUCCESSOR_RECORD" ]] || return 1
    /bin/rm -f -- "$owner" || return 1
    /bin/rmdir "$LOCK_DIR" || return 1
    DRIVER_LOCK_OWNED=0
  }
  driver_cleanup() {
    local exit_code=$?
    if [[ -n "$STAGING_SET" && "$STAGING_SET" == "$BUILD_DIR/.$EVIDENCE_BASE-set."* \
       && -d "$STAGING_SET" && ! -L "$STAGING_SET" ]]; then
      /bin/rm -rf -- "$STAGING_SET"
    fi
    if ! release_driver_lock; then
      print -u2 "Release evidence could not release its exact parent publication lock."
      exit_code=126
    fi
    return "$exit_code"
  }
  trap driver_cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ "${FULMAR_RELEASE_EVIDENCE_TEST_ONLY:-0}" != "1" ]]; then
    /bin/zsh -f "$PROJECT_DIR/scripts/run-watchdog-self-tests.sh"
  fi
  set +e
  "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 5400 --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 \
    --lock-dir "$LOCK_DIR" --lock-wait-seconds 0 \
    --lock-successor-pid $$ --lock-successor-token "$SUCCESSOR_TOKEN" \
    --label "Fulmar retained release verification" -- \
    /bin/zsh -f "$0" --signing-profile "$SIGNING_PROFILE" --internal-stage "$STAGING_SET" "$APP_DIR"
  STAGE_STATUS=$?
  set -e
  (( STAGE_STATUS == 0 )) || exit "$STAGE_STATUS"
  OWNER_IDENTITY="$(/usr/bin/stat -f '%u:%Lp:%l' "$LOCK_DIR/owner.pid" 2>/dev/null || true)"
  OWNER_SIZE="$(/usr/bin/stat -f '%z' "$LOCK_DIR/owner.pid" 2>/dev/null || true)"
  [[ "$OWNER_IDENTITY" == "$(/usr/bin/id -u):600:1" \
     && "$OWNER_SIZE" == <-> && "$OWNER_SIZE" -ge 1 && "$OWNER_SIZE" -le 1024 \
     && "$(<"$LOCK_DIR/owner.pid")" == "$SUCCESSOR_RECORD" ]] || {
    print -u2 "The drained root did not transfer the publication lock exactly."
    exit 126
  }
  DRIVER_LOCK_OWNED=1

  # The stage can become visible only after the root supervisor has returned
  # success, which is its proof that every member of the verifier PGID is gone.
  "$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
    "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$BUILD_DIR" "$STAGING_SET"
  MANIFEST_SHA256="$(/usr/bin/plutil -extract candidate.sha256 raw -o - \
    "$STAGING_SET/$EVIDENCE_BASE.json")"
  [[ ${#MANIFEST_SHA256} == 64 && "$MANIFEST_SHA256" != *[^a-f0-9]* ]] || {
    print -u2 "The verified release manifest has no valid candidate digest."
    exit 1
  }
  FINAL_SET="$BUILD_DIR/$EVIDENCE_BASE-$MANIFEST_SHA256.evidence"
  if [[ "$TEST_KILL_AT" == "before-publish" ]]; then /bin/kill -KILL $$; fi
  if [[ -e "$FINAL_SET" || -L "$FINAL_SET" ]]; then
    "$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
      "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$BUILD_DIR"
    print "Preserved existing candidate-specific release evidence: ${FINAL_SET#$PROJECT_DIR/}"
    exit 0
  fi
  set +e
  "$NODE" -e '
    const fs = require("node:fs");
    try { fs.renameSync(process.argv[1], process.argv[2]); }
    catch (error) {
      if (error && (error.code === "EEXIST" || error.code === "ENOTEMPTY")) process.exit(17);
      throw error;
    }
  ' "$STAGING_SET" "$FINAL_SET"
  RENAME_STATUS=$?
  set -e
  if (( RENAME_STATUS != 0 )); then
    if (( RENAME_STATUS == 17 )) && [[ -d "$FINAL_SET" && ! -L "$FINAL_SET" ]]; then
      "$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
        "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$BUILD_DIR"
      print "Preserved concurrently published candidate-specific release evidence: ${FINAL_SET#$PROJECT_DIR/}"
      exit 0
    fi
    exit "$RENAME_STATUS"
  fi
  STAGING_SET=""
  if [[ "$TEST_KILL_AT" == "after-publish-before-parent-fsync" ]]; then /bin/kill -KILL $$; fi
  "$NODE" -e '
    const fs = require("node:fs");
    const descriptor = fs.openSync(process.argv[1], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  ' "$BUILD_DIR"
  "$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
    "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$BUILD_DIR"
  release_driver_lock
  print "Retained atomic candidate-specific release evidence: ${FINAL_SET#$PROJECT_DIR/}"
  exit 0
fi

(( INTERNAL_STAGE == 1 )) || {
  print -u2 "An authenticated root may execute only the internal evidence-staging phase."
  exit 126
}
[[ "$STAGING_SET" == "$BUILD_DIR/.$EVIDENCE_BASE-set."* \
   && -d "$STAGING_SET" && ! -L "$STAGING_SET" \
   && "$(/usr/bin/stat -f '%u:%Lp' "$STAGING_SET")" == "$(/usr/bin/id -u):700" \
   && -z "$(/bin/ls -A "$STAGING_SET")" ]] || {
  print -u2 "The private evidence staging directory is unsafe or not empty."
  exit 64
}
if ! fulmar_acquire_root_group_lock "$LOCK_DIR" \
  "Fulmar candidate-specific evidence retention" 1; then
  print -u2 "Release evidence retention is already running for this candidate."
  exit 75
fi

STAGING_LOG="$STAGING_SET/$EVIDENCE_BASE.log"
STAGING_RECORD="$STAGING_SET/$EVIDENCE_BASE.json"
STAGING_SUMMARY="$STAGING_SET/$EVIDENCE_BASE-ci-evidence.json"
STAGING_CI_INPUT="$STAGING_SET/.ci-evidence-input.json"

cleanup() {
  local exit_code=$?
  return "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# pipefail is intentional: tee success must never hide the verifier's status.
# Only the verifier's own combined output is captured; the caller environment is
# never printed or serialized.
set +e
setopt noclobber
exec {STAGING_LOG_FD}> "$STAGING_LOG"
LOG_OPEN_STATUS=$?
setopt clobber
if (( LOG_OPEN_STATUS != 0 )); then
  set -e
  print -u2 "Release evidence could not create its exclusive transcript sink."
  exit 1
fi
typeset -a verifier_arguments
if [[ "$VERIFIER" == "$PROJECT_DIR/scripts/verify-release.sh" ]]; then
  verifier_arguments=(--signing-profile "$SIGNING_PROFILE" "$APP_DIR" "$STAGING_CI_INPUT")
else
  verifier_arguments=("$APP_DIR" "$STAGING_CI_INPUT")
fi
/bin/zsh -f "$VERIFIER" "${verifier_arguments[@]}" 2>&1 \
  | "$NODE" "$PROJECT_DIR/scripts/bounded-redacted-release-stream.mjs" 67108864 \
  | /usr/bin/tee "/dev/fd/$STAGING_LOG_FD"
PIPE_STATUSES=("${pipestatus[@]}")
exec {STAGING_LOG_FD}>&-
set -e
VERIFY_STATUS="${PIPE_STATUSES[1]:-1}"
REDACTION_STATUS="${PIPE_STATUSES[2]:-1}"
TEE_STATUS="${PIPE_STATUSES[3]:-1}"
(( VERIFY_STATUS == 0 )) || exit "$VERIFY_STATUS"
(( REDACTION_STATUS == 0 )) || exit 1
(( TEE_STATUS == 0 )) || exit 1
[[ -f "$STAGING_CI_INPUT" && ! -L "$STAGING_CI_INPUT" ]] || {
  print -u2 "The successful verifier did not publish full-hardware CI evidence."
  exit 1
}

/bin/chmod 0600 "$STAGING_LOG"
/usr/bin/env -i \
  "HOME=${HOME:-/private/tmp}" \
  "PATH=/usr/bin:/bin:/usr/sbin:/sbin" \
  "LANG=en_US.UTF-8" \
  "LC_CTYPE=UTF-8" \
  "$NODE" "$PROJECT_DIR/scripts/record-release-verification.mjs" \
  "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$STAGING_LOG" \
  "$STAGING_CI_INPUT" "$STAGING_RECORD" "$STAGING_SUMMARY"
/bin/rm -f -- "$STAGING_CI_INPUT"
"$NODE" -e '
  const fs = require("node:fs");
  const descriptor = fs.openSync(process.argv[1], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
' "$STAGING_SET"
/bin/chmod 0600 "$STAGING_LOG" "$STAGING_RECORD" "$STAGING_SUMMARY"

# Validate the complete private set while the candidate and evidence locks are
# still root-owned, but leave it private. Only the outer driver may publish it,
# and only after this entire PGID has been proven empty by the supervisor.
"$NODE" "$PROJECT_DIR/scripts/verify-retained-release-evidence.mjs" \
  "$IDENTITY" "$PROJECT_DIR/build/release-manifest.json" "$BUILD_DIR" "$STAGING_SET"
print "Staged candidate-specific release evidence pending outer-root drain."
