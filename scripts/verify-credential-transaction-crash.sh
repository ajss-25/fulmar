#!/bin/zsh -f
set -euo pipefail
unsetopt BG_NICE

PROJECT_DIR="${0:A:h:h}"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PRIVATE_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-credential-crash-gate.XXXXXX)"
CANONICAL_ROOT="/tmp/${PRIVATE_ROOT:t}"
BUILD_HOME="$CANONICAL_ROOT/home"
BUILD_TMP="$CANONICAL_ROOT/tmp"
BUILD_CACHE="$CANONICAL_ROOT/cache"
BUILD_SCRATCH="$CANONICAL_ROOT/swift-build"
SWIFTPM_CACHE="$CANONICAL_ROOT/swiftpm-cache"
SWIFTPM_CONFIG="$CANONICAL_ROOT/swiftpm-config"
SWIFTPM_SECURITY="$CANONICAL_ROOT/swiftpm-security"
CLANG_CACHE="$BUILD_CACHE/clang"
SWIFT_CACHE="$BUILD_CACHE/swift"
CHILD_PID=0

umask 077
/bin/mkdir -p \
  "$BUILD_HOME" "$BUILD_TMP" "$BUILD_CACHE" "$CLANG_CACHE" "$SWIFT_CACHE" \
  "$SWIFTPM_CACHE" "$SWIFTPM_CONFIG" "$SWIFTPM_SECURITY" "$CANONICAL_ROOT/cases"
/bin/chmod 0700 \
  "$PRIVATE_ROOT" "$BUILD_HOME" "$BUILD_TMP" "$BUILD_CACHE" \
  "$SWIFTPM_CACHE" "$SWIFTPM_CONFIG" "$SWIFTPM_SECURITY" "$CANONICAL_ROOT/cases"

cleanup() {
  local exit_code="${1:-$?}"
  if (( CHILD_PID > 0 )) && /bin/kill -0 "$CHILD_PID" 2>/dev/null; then
    /bin/kill -KILL "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
  fi
  case "$PRIVATE_ROOT" in
    /private/tmp/fulmar-credential-crash-gate.*) /bin/rm -rf -- "$PRIVATE_ROOT" ;;
    *) print -u2 "Refusing to remove an invalid credential crash-gate root." ;;
  esac
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

SDKROOT="$(/usr/bin/env -i \
  HOME="$BUILD_HOME" TMPDIR="$BUILD_TMP/" PATH="$SAFE_PATH" \
  /bin/zsh -f -c 'source "$1"; print -r -- "$SDKROOT"' \
  _ "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh")"

typeset -a swift_environment
swift_environment=(
  "HOME=$BUILD_HOME"
  "TMPDIR=$BUILD_TMP/"
  "PATH=$SAFE_PATH"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
  "SDKROOT=$SDKROOT"
  "CLANG_MODULE_CACHE_PATH=$CLANG_CACHE"
  "SWIFTPM_MODULECACHE_OVERRIDE=$SWIFT_CACHE"
)

/usr/bin/env -i "${swift_environment[@]}" /usr/bin/swift build \
  --package-path "$PROJECT_DIR" \
  --disable-sandbox \
  --scratch-path "$BUILD_SCRATCH" \
  --cache-path "$SWIFTPM_CACHE" \
  --config-path "$SWIFTPM_CONFIG" \
  --security-path "$SWIFTPM_SECURITY" \
  --jobs 1 \
  -c release \
  --product CredentialTransactionCrashProbe \
  -Xswiftc -warnings-as-errors

BIN_PATH="$(/usr/bin/env -i "${swift_environment[@]}" /usr/bin/swift build \
  --package-path "$PROJECT_DIR" \
  --disable-sandbox \
  --scratch-path "$BUILD_SCRATCH" \
  --cache-path "$SWIFTPM_CACHE" \
  --config-path "$SWIFTPM_CONFIG" \
  --security-path "$SWIFTPM_SECURITY" \
  --jobs 1 \
  -c release \
  --show-bin-path)"
PROBE="$BIN_PATH/CredentialTransactionCrashProbe"
[[ "$BIN_PATH" == "$BUILD_SCRATCH/"* && -f "$PROBE" && ! -L "$PROBE" && -x "$PROBE" \
   && "$(/usr/bin/stat -f '%u:%l' "$PROBE")" == "$(/usr/bin/id -u):1" ]] || {
  print -u2 "Credential transaction crash probe was not built as a private regular executable."
  exit 1
}
if /usr/bin/nm -u "$PROBE" | /usr/bin/grep -Eq '(_SecItem|_SecKeychain|_LAContext|LocalAuthentication)'; then
  print -u2 "Credential transaction crash probe unexpectedly links a Keychain or LocalAuthentication symbol."
  exit 1
fi
if /usr/bin/otool -L "$PROBE" | /usr/bin/grep -Eq '/(Security|LocalAuthentication)\.framework/'; then
  print -u2 "Credential transaction crash probe unexpectedly links a Keychain or LocalAuthentication framework."
  exit 1
fi

typeset -a probe_environment
probe_environment=(
  "HOME=$BUILD_HOME"
  "TMPDIR=$BUILD_TMP/"
  "PATH=$SAFE_PATH"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
)

typeset -a scenarios checkpoints
scenarios=(create replace adopt remove repair-adopt repair-replace repair-remove unknown-record-remove)
checkpoints=(
  afterJournalPrepared
  afterValueMutation
  afterValueVerification
  afterMetadataCommit
  afterFinalVerification
  afterJournalRemoval
)

case_count=0
for scenario in "${scenarios[@]}"; do
  for checkpoint in "${checkpoints[@]}"; do
    CASE_ROOT="$CANONICAL_ROOT/cases/$scenario-$checkpoint"
    OUTPUT="$CASE_ROOT/probe.log"
    /bin/mkdir -m 0700 "$CASE_ROOT"
    : > "$OUTPUT"
    /bin/chmod 0600 "$OUTPUT"

    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" prepare "$scenario" "$CASE_ROOT" >>"$OUTPUT" 2>&1
    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" mutate "$scenario" "$CASE_ROOT" "$checkpoint" >>"$OUTPUT" 2>&1 &
    CHILD_PID=$!

    reached=0
    for _ in {1..1000}; do
      if /usr/bin/grep -Fqx "CHECKPOINT $checkpoint" "$OUTPUT"; then
        reached=1
        break
      fi
      if ! /bin/kill -0 "$CHILD_PID" 2>/dev/null; then
        break
      fi
      /bin/sleep 0.01
    done
    if (( reached != 1 )); then
      print -u2 "Credential crash probe did not reach $scenario/$checkpoint."
      /bin/cat "$OUTPUT" >&2
      exit 1
    fi

    /bin/kill -KILL "$CHILD_PID"
    set +e
    wait "$CHILD_PID" 2>/dev/null
    killed_status=$?
    set -e
    CHILD_PID=0
    [[ "$killed_status" == "137" ]] || {
      print -u2 "Credential crash probe did not terminate by SIGKILL ($scenario/$checkpoint: $killed_status)."
      exit 1
    }

    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" recover "$scenario" "$CASE_ROOT" "$checkpoint" >>"$OUTPUT" 2>&1
    expected_recovery="RECOVERED $scenario $checkpoint LOCK_RELEASED"
    if [[ ( "$scenario" == "repair-replace" || "$scenario" == "repair-remove" ) \
       && "$checkpoint" == "afterJournalPrepared" ]]; then
      expected_recovery="RECOVERY_ATTENTION $scenario $checkpoint LOCK_RELEASED"
    fi
    /usr/bin/grep -Fqx "$expected_recovery" "$OUTPUT" || {
        print -u2 "Credential crash recovery did not prove state and flock recovery ($scenario/$checkpoint)."
        /bin/cat "$OUTPUT" >&2
        exit 1
      }
    case_count=$((case_count + 1))
  done
done

typeset -a persistence_artifacts persistence_checkpoints
persistence_artifacts=(journal metadata)
persistence_checkpoints=(
  afterTemporaryWrite
  afterFileSynchronize
  afterRename
  afterDirectorySynchronize
)
for artifact in "${persistence_artifacts[@]}"; do
  for checkpoint in "${persistence_checkpoints[@]}"; do
    CASE_ROOT="$CANONICAL_ROOT/cases/persistence-$artifact-$checkpoint"
    OUTPUT="$CASE_ROOT/probe.log"
    /bin/mkdir -m 0700 "$CASE_ROOT"
    : > "$OUTPUT"
    /bin/chmod 0600 "$OUTPUT"

    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" prepare replace "$CASE_ROOT" >>"$OUTPUT" 2>&1
    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" mutate-persistence replace "$CASE_ROOT" "$artifact" "$checkpoint" \
      >>"$OUTPUT" 2>&1 &
    CHILD_PID=$!

    reached=0
    for _ in {1..1000}; do
      if /usr/bin/grep -Fqx "PERSISTENCE_CHECKPOINT $artifact $checkpoint" "$OUTPUT"; then
        reached=1
        break
      fi
      if ! /bin/kill -0 "$CHILD_PID" 2>/dev/null; then
        break
      fi
      /bin/sleep 0.01
    done
    if (( reached != 1 )); then
      print -u2 "Credential crash probe did not reach persistence $artifact/$checkpoint."
      /bin/cat "$OUTPUT" >&2
      exit 1
    fi

    /bin/kill -KILL "$CHILD_PID"
    set +e
    wait "$CHILD_PID" 2>/dev/null
    killed_status=$?
    set -e
    CHILD_PID=0
    [[ "$killed_status" == "137" ]] || {
      print -u2 "Credential persistence probe did not terminate by SIGKILL ($artifact/$checkpoint: $killed_status)."
      exit 1
    }

    /usr/bin/env -i "${probe_environment[@]}" \
      "$PROBE" recover-persistence replace "$CASE_ROOT" "$artifact" "$checkpoint" \
      >>"$OUTPUT" 2>&1
    /usr/bin/grep -Fqx \
      "PERSISTENCE_RECOVERED $artifact $checkpoint LOCK_RELEASED" "$OUTPUT" || {
        print -u2 "Credential persistence recovery did not prove exact state and cleanup ($artifact/$checkpoint)."
        /bin/cat "$OUTPUT" >&2
        exit 1
      }
    case_count=$((case_count + 1))
  done
done

for checkpoint in "${persistence_checkpoints[@]}"; do
  CASE_ROOT="$CANONICAL_ROOT/cases/persistence-unknown-record-remove-journal-$checkpoint"
  OUTPUT="$CASE_ROOT/probe.log"
  /bin/mkdir -m 0700 "$CASE_ROOT"
  : > "$OUTPUT"
  /bin/chmod 0600 "$OUTPUT"

  /usr/bin/env -i "${probe_environment[@]}" \
    "$PROBE" prepare unknown-record-remove "$CASE_ROOT" >>"$OUTPUT" 2>&1
  /usr/bin/env -i "${probe_environment[@]}" \
    "$PROBE" mutate-persistence unknown-record-remove "$CASE_ROOT" journal "$checkpoint" \
    >>"$OUTPUT" 2>&1 &
  CHILD_PID=$!

  reached=0
  for _ in {1..1000}; do
    if /usr/bin/grep -Fqx "PERSISTENCE_CHECKPOINT journal $checkpoint" "$OUTPUT"; then
      reached=1
      break
    fi
    if ! /bin/kill -0 "$CHILD_PID" 2>/dev/null; then
      break
    fi
    /bin/sleep 0.01
  done
  if (( reached != 1 )); then
    print -u2 "Unknown-record removal did not reach journal persistence/$checkpoint."
    /bin/cat "$OUTPUT" >&2
    exit 1
  fi

  /bin/kill -KILL "$CHILD_PID"
  set +e
  wait "$CHILD_PID" 2>/dev/null
  killed_status=$?
  set -e
  CHILD_PID=0
  [[ "$killed_status" == "137" ]] || {
    print -u2 "Unknown-record persistence probe did not terminate by SIGKILL ($checkpoint: $killed_status)."
    exit 1
  }

  /usr/bin/env -i "${probe_environment[@]}" \
    "$PROBE" recover-persistence unknown-record-remove "$CASE_ROOT" journal "$checkpoint" \
    >>"$OUTPUT" 2>&1
  /usr/bin/grep -Fqx \
    "PERSISTENCE_RECOVERED journal $checkpoint LOCK_RELEASED" "$OUTPUT" || {
      print -u2 "Unknown-record persistence recovery did not preserve exact state ($checkpoint)."
      /bin/cat "$OUTPUT" >&2
      exit 1
    }
  case_count=$((case_count + 1))
done

[[ "$case_count" == "60" ]] || {
  print -u2 "Credential crash gate executed an unexpected number of cases: $case_count"
  exit 1
}

print "Credential transaction process-crash gate passed: 60 isolated SIGKILL checkpoints (24 ordinary transactions, 18 v2 foreground repairs, 6 token-bound unknown-record removals, 12 persistence boundaries), file-backed fake store only."
