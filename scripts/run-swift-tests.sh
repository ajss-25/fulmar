#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/root-group-lock.zsh"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
REQUESTED_BUILD_JOBS="${FULMAR_SWIFT_BUILD_JOBS-}"
SWIFT_BUILD_JOBS="${REQUESTED_BUILD_JOBS:-2}"
SWIFT_WATCHDOG_SECONDS="${FULMAR_SWIFT_WATCHDOG_SECONDS:-3600}"
SWIFT_WATCHDOG_RSS_BYTES="${FULMAR_SWIFT_WATCHDOG_RSS_BYTES:-25769803776}"
SWIFT_WATCHDOG_RSS_GRACE="${FULMAR_SWIFT_WATCHDOG_RSS_GRACE_SECONDS:-10}"
SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES="${FULMAR_SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES:-34359738368}"
UPDATE_ARCHIVE_FIXTURE="${LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH-}"
APPLICATION_FIXTURE="${LOCAL_HARNESS_TEST_APP_PATH-}"
TEST_LOCK_DIR="/private/tmp/FulmarSwiftTests.lock"
SWIFT_TEST_PROFILE="full"
SWIFT_TEST_FIXTURE_PROFILE="ordinary"
if [[ -n "$UPDATE_ARCHIVE_FIXTURE" && -n "$APPLICATION_FIXTURE" ]]; then
  SWIFT_TEST_FIXTURE_PROFILE="release-fixtures"
elif [[ -n "$UPDATE_ARCHIVE_FIXTURE" || -n "$APPLICATION_FIXTURE" ]]; then
  print -u2 "Release fixture qualification requires both the exact archive and application."
  exit 64
fi
typeset -a test_selection_arguments
test_selection_arguments=()
if (( $# == 0 )); then
  :
elif (( $# == 2 )) && [[ "$1" == "--focused-filter" \
   && "$2" == "renderedMacOS26Toolbar" ]]; then
  SWIFT_TEST_PROFILE="focused"
  test_selection_arguments=(--filter "$2")
else
  print -u2 "The Swift qualification runner accepts no selectors in full mode; the only focused profile is --focused-filter renderedMacOS26Toolbar."
  exit 64
fi

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 2 )); then
  echo "The Swift gate inherited an invalid root-watchdog attestation." >&2
  exit 1
fi
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 7200 --max-rss-bytes 32212254720 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 --lock-dir "$TEST_LOCK_DIR" \
    --label "complete Swift qualification gate" -- \
    /bin/zsh -f "$0" "$@"
fi

run_guarded() {
  local label="$1" seconds="$2" maximum="$3" grace="$4" emergency="$5"
  shift 5
  [[ "${1:-}" == "--" ]] || return 64
  shift
  # This is a logical stage inside the one authenticated release PGID. The
  # inherited guard never calls setsid: it applies the stage wall/RSS profile
  # while the outer root remains the sole final-drain owner.
  "$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
    --seconds "$seconds" --max-rss-bytes "$maximum" \
    --rss-grace-seconds "$grace" --emergency-rss-bytes "$emergency" \
    --label "$label" -- "$@"
}

[[ "$SWIFT_WATCHDOG_SECONDS" == <-> && "$SWIFT_WATCHDOG_SECONDS" -ge 1 \
   && "$SWIFT_WATCHDOG_SECONDS" -le 7200 \
   && "$SWIFT_WATCHDOG_RSS_BYTES" == <-> && "$SWIFT_WATCHDOG_RSS_BYTES" -ge 67108864 \
   && "$SWIFT_WATCHDOG_RSS_GRACE" == <-> && "$SWIFT_WATCHDOG_RSS_GRACE" -le 300 \
   && "$SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES" == <-> \
   && "$SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES" -ge "$SWIFT_WATCHDOG_RSS_BYTES" ]] || {
  echo "The Swift watchdog profile is invalid." >&2
  exit 64
}
[[ "$SWIFT_BUILD_JOBS" == <-> && "$SWIFT_BUILD_JOBS" -ge 1 \
   && "$SWIFT_BUILD_JOBS" -le 4 ]] || {
  echo "FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 4." >&2
  exit 64
}

# Full release qualification has no caller-selectable execution surface. This
# prevents a filter, skip, compiler override, or changed output path from being
# reported with the same success label as all 1,000+ native tests. The one
# renderer-only profile above is explicitly named and separately accounted.

umask 077
# Serialize and authenticate before examining any stale private roots. The
# outer supervisor owns this lock, so no second legitimate Swift gate can be
# creating or using one of these roots concurrently.
fulmar_acquire_root_group_lock "$TEST_LOCK_DIR" "Fulmar Swift qualification" 1200 || exit

CURRENT_UID="$(/usr/bin/id -u)"
CURRENT_EPOCH="$(/bin/date +%s)"
SWIFT_ROOT_MARKER=".fulmar-swift-test-owner-v1"
typeset -a stale_fields stale_roots
stale_roots=()
while IFS= read -r stale_root; do
  stale_roots+=("$stale_root")
done < <(/usr/bin/find /private/tmp -mindepth 1 -maxdepth 1 -name 'fulmar-swift-tests.*' -print)
for stale_root in "${stale_roots[@]}"; do
  stale_name="${stale_root:t}"
  stale_suffix="${stale_name#fulmar-swift-tests.}"
  [[ "$stale_name" == "fulmar-swift-tests.$stale_suffix" \
     && "${#stale_suffix}" == 6 && "$stale_suffix" != *[^A-Za-z0-9]* \
     && -d "$stale_root" && ! -L "$stale_root" \
     && "$(/usr/bin/stat -f '%u:%HT:%Lp' "$stale_root" 2>/dev/null)" == "$CURRENT_UID:Directory:700" ]] || {
    print -u2 "The Swift gate found an unsafe stale-root candidate: $stale_root"
    exit 126
  }
  stale_marker="$stale_root/$SWIFT_ROOT_MARKER"
  stale_marker_metadata="$(/usr/bin/stat -f '%u:%HT:%Lp:%l:%z' "$stale_marker" 2>/dev/null || true)"
  stale_marker_size="${stale_marker_metadata##*:}"
  [[ -f "$stale_marker" && ! -L "$stale_marker" \
     && "${stale_marker_metadata%:*}" == "$CURRENT_UID:Regular File:600:1" \
     && -n "$stale_marker_size" && "$stale_marker_size" != *[^0-9]* ]] || {
    print -u2 "The Swift gate found an unattested legacy private root requiring manual review: $stale_root"
    exit 126
  }
  [[ "$stale_marker_size" -ge 1 && "$stale_marker_size" -le 2048 ]] || exit 126
  [[ "$(/usr/bin/stat -f '%u:%HT:%Lp:%l:%z' "$stale_marker" 2>/dev/null)" == "$stale_marker_metadata" ]] || exit 126
  stale_fields=()
  while IFS= read -r stale_field || [[ -n "$stale_field" ]]; do
    stale_fields+=("$stale_field")
  done < "$stale_marker"
  (( ${#stale_fields[@]} == 8 )) \
    && [[ "${stale_fields[1]}" == "FULMAR_SWIFT_TEST_ROOT_V1" \
       && -n "${stale_fields[2]}" && "${stale_fields[2]}" != *[^0-9]* && "${stale_fields[2]}" -gt 1 \
       && -n "${stale_fields[3]}" && "${stale_fields[3]}" != *$'\r'* \
       && "${stale_fields[4]}" == "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$stale_root")" \
       && -n "${stale_fields[5]}" && "${stale_fields[5]}" != *[^0-9]* && "${stale_fields[5]}" -le "$CURRENT_EPOCH" \
       && "${stale_fields[6]}" == /private/tmp/fulmar-watchdog-capability.* \
       && "${#stale_fields[7]}" == 64 && "${stale_fields[7]}" != *[^a-f0-9]* \
       && -n "${stale_fields[8]}" && "${stale_fields[8]}" != *[^0-9]* && "${stale_fields[8]}" -gt 1 ]] || {
    print -u2 "The Swift gate found malformed stale-root attestation: $stale_root"
    exit 126
  }
  [[ ! -e "${stale_fields[6]}" && ! -L "${stale_fields[6]}" ]] || {
    print -u2 "The Swift gate retained a stale root whose supervisor cleanup is unproven: $stale_root"
    exit 126
  }
  stale_started="$(/bin/ps -p "${stale_fields[2]}" -o lstart= 2>/dev/null || true)"
  if [[ -n "$stale_started" && "$stale_started" == "${stale_fields[3]}" ]]; then
    print -u2 "The Swift gate found a live owner for private root: $stale_root"
    exit 75
  fi
  stale_age=$(( CURRENT_EPOCH - stale_fields[5] ))
  (( stale_age >= 30 && stale_age <= 2592000 )) || {
    print -u2 "The Swift gate refused a stale root outside its 30-second to 30-day recovery window: $stale_root"
    exit 126
  }
  /bin/rm -rf -- "$stale_root" || exit 126
  [[ ! -e "$stale_root" && ! -L "$stale_root" ]] || exit 126
  print -r -- "Removed stale attested Swift-test root: $stale_root"
done

ISOLATION_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-swift-tests.XXXXXX)"
# Foundation's `standardizedFileURL` represents this macOS alias as `/tmp`,
# even though mktemp returns `/private/tmp`. Export the Foundation-canonical
# spelling so exact no-alias path guards behave identically in tests and live.
CANONICAL_ISOLATION_ROOT="/tmp/${ISOLATION_ROOT:t}"
TEST_HOME="$CANONICAL_ISOLATION_ROOT/home"
TEST_TMP="$CANONICAL_ISOLATION_ROOT/tmp"
TEST_CACHE="$CANONICAL_ISOLATION_ROOT/cache"
TEST_USER="$(/usr/bin/id -un)"
/bin/mkdir -p \
  "$TEST_HOME/Library/Application Support" \
  "$TEST_HOME/Library/Caches" \
  "$TEST_TMP" \
  "$TEST_CACHE/clang" \
  "$TEST_CACHE/swift" \
  "$TEST_CACHE/xdg"
/bin/chmod 0700 \
  "$ISOLATION_ROOT" \
  "$TEST_HOME" \
  "$TEST_HOME/Library" \
  "$TEST_HOME/Library/Application Support" \
  "$TEST_HOME/Library/Caches" \
  "$TEST_TMP" \
  "$TEST_CACHE"
ISOLATION_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT")" || {
  print -u2 "The Swift-test isolation root could not be attested."
  exit 126
}
OWNER_STARTED="$(/bin/ps -p $$ -o lstart=)" || exit 126
CREATED_EPOCH="$(/bin/date +%s)"
ROOT_MARKER_PATH="$ISOLATION_ROOT/$SWIFT_ROOT_MARKER"
setopt localoptions noclobber
print -r -- "FULMAR_SWIFT_TEST_ROOT_V1
$$
$OWNER_STARTED
$ISOLATION_ROOT_IDENTITY
$CREATED_EPOCH
$FULMAR_ROOT_WATCHDOG_CAPABILITY_V1
$FULMAR_ROOT_WATCHDOG_NONCE_V1
$FULMAR_ROOT_WATCHDOG_PID_V1" > "$ROOT_MARKER_PATH" || exit 126
/bin/chmod 0600 "$ROOT_MARKER_PATH" || exit 126
[[ "$(/usr/bin/stat -f '%u:%HT:%Lp:%l' "$ROOT_MARKER_PATH")" == "$CURRENT_UID:Regular File:600:1" ]] || exit 126
EVENT_NONCE="$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]' | /usr/bin/tr -d '-')"
[[ "${#EVENT_NONCE}" == 32 && "$EVENT_NONCE" != *[^a-f0-9]* ]] || {
  print -u2 "The Swift-test event identity could not be generated safely."
  exit 126
}
EVENT_STREAM="$ISOLATION_ROOT/swift-events-$EVENT_NONCE.jsonl"
TEST_PLAN_STREAM="$ISOLATION_ROOT/swift-test-plan-$EVENT_NONCE.txt"
[[ ! -e "$EVENT_STREAM" && ! -L "$EVENT_STREAM" ]] || exit 126
[[ ! -e "$TEST_PLAN_STREAM" && ! -L "$TEST_PLAN_STREAM" ]] || exit 126

cleanup() {
  [[ -n "$ISOLATION_ROOT" ]] || return 0
  case "$ISOLATION_ROOT" in
    /private/tmp/fulmar-swift-tests.*) ;;
    *) print -u2 "Refusing to remove an invalid Swift-test isolation root."; return 126 ;;
  esac
  [[ -d "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" \
     && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT" 2>/dev/null)" == "$ISOLATION_ROOT_IDENTITY" ]] || {
    print -u2 "Refusing to remove a changed Swift-test isolation root."
    return 126
  }
  /bin/rm -rf -- "$ISOLATION_ROOT" || return 126
  [[ ! -e "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" ]] || return 126
  ISOLATION_ROOT=""
}
finish_gate() {
  local requested_status="$1"
  trap - EXIT HUP INT TERM
  if ! cleanup; then
    print -u2 "The Swift gate could not remove its attested private isolation root."
    exit 126
  fi
  # The outer authenticated Perl supervisor is the root-lock owner. Its final
  # status is published only after this process exits, tree drain is proven,
  # and the exact lock owner record is removed; this inner gate must not claim
  # or simulate that irreversible boundary.
  exit "$requested_status"
}
trap 'cleanup >/dev/null 2>&1 || true' EXIT
trap 'cleanup >/dev/null 2>&1 || true; exit 129' HUP
trap 'cleanup >/dev/null 2>&1 || true; exit 130' INT
trap 'cleanup >/dev/null 2>&1 || true; exit 143' TERM

validate_absolute_path() {
  local label="$1" value="$2"
  [[ "$value" == /* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || {
    echo "$label must be one absolute single-line path." >&2
    return 1
  }
}

typeset -a sdk_probe_environment
sdk_probe_environment=(
  "HOME=$TEST_HOME"
  "CFFIXED_USER_HOME=$TEST_HOME"
  "TMPDIR=$TEST_TMP/"
  "PATH=$SAFE_PATH"
  "USER=$TEST_USER"
  "LOGNAME=$TEST_USER"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
)
if (( ROOT_WATCHDOG_STATE == 0 )); then
  fulmar_append_root_watchdog_environment sdk_probe_environment
fi
# SDK probing runs in the same clean home/environment boundary as the tests.
# This prevents compiler loader hooks, proxy credentials, or package-manager
# state from influencing even the pre-test compatibility probe.
SDKROOT="$(run_guarded "Swift SDK compatibility probe" 180 2147483648 3 3221225472 -- \
  /usr/bin/env -i "${sdk_probe_environment[@]}" /bin/zsh -f -c '
  source "$1"
  print -r -- "$SDKROOT"
' _ "$PROJECT_DIR/scripts/select-compatible-swift-sdk.sh")"
validate_absolute_path selected-SDKROOT "$SDKROOT"

DEVELOPER_ROOT="$(/usr/bin/env -i PATH="$SAFE_PATH" /usr/bin/xcode-select -p)"
TESTING_FRAMEWORKS="$DEVELOPER_ROOT/Library/Developer/Frameworks"
TESTING_INTEROP=""
SWIFT_TEST_HOST_SOURCE="$PROJECT_DIR/Tests/Support/SwiftTestingHost.swift"
SWIFT_TEST_HOST_COMPILER="/usr/bin/swiftc"
MINIMUM_MACOS="$(/usr/bin/plutil -extract minimumMacOS raw -o - "$PROJECT_DIR/Config/ReleaseIdentity.json")"
validate_absolute_path Swift-test-host-source "$SWIFT_TEST_HOST_SOURCE"
validate_absolute_path Swift-test-host-compiler "$SWIFT_TEST_HOST_COMPILER"

for candidate in \
  "$DEVELOPER_ROOT/Library/Developer/usr/lib" \
  "$DEVELOPER_ROOT/usr/lib"; do
  if [[ -f "$candidate/lib_TestingInterop.dylib" ]]; then
    TESTING_INTEROP="$candidate"
    break
  fi
done

typeset -a testing_arguments
testing_arguments=()
if [[ -d "$TESTING_FRAMEWORKS/Testing.framework" ]]; then
  # Some standalone Command Line Tools releases expose Swift Testing outside
  # the compiler's default framework and runtime search paths. Add both the
  # compile-time framework path and durable test-bundle rpaths so a genuinely
  # fresh cache neither misses Testing nor depends on ambient DYLD variables.
  testing_arguments+=(
    -Xswiftc -F
    -Xswiftc "$TESTING_FRAMEWORKS"
    -Xlinker "-F$TESTING_FRAMEWORKS"
    -Xlinker -rpath
    -Xlinker "$TESTING_FRAMEWORKS"
  )
  if [[ -n "$TESTING_INTEROP" ]]; then
    testing_arguments+=(
      -Xlinker -rpath
      -Xlinker "$TESTING_INTEROP"
    )
  fi
fi

CLANG_CACHE="$TEST_CACHE/clang"
SWIFT_CACHE="$TEST_CACHE/swift"
validate_absolute_path CLANG_MODULE_CACHE_PATH "$CLANG_CACHE"
validate_absolute_path SWIFTPM_MODULECACHE_OVERRIDE "$SWIFT_CACHE"
typeset -a test_environment
test_environment=(
  "HOME=$TEST_HOME"
  "CFFIXED_USER_HOME=$TEST_HOME"
  "TMPDIR=$TEST_TMP/"
  "XDG_CACHE_HOME=$TEST_CACHE/xdg"
  "PATH=$SAFE_PATH"
  "USER=$TEST_USER"
  "LOGNAME=$TEST_USER"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
  "SDKROOT=$SDKROOT"
  "CLANG_MODULE_CACHE_PATH=$CLANG_CACHE"
  "SWIFTPM_MODULECACHE_OVERRIDE=$SWIFT_CACHE"
  "LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT=$CANONICAL_ISOLATION_ROOT"
)
if (( ROOT_WATCHDOG_STATE == 0 )); then
  fulmar_append_root_watchdog_environment test_environment
fi
if [[ -n "$UPDATE_ARCHIVE_FIXTURE" ]]; then
  validate_absolute_path LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH "$UPDATE_ARCHIVE_FIXTURE"
  [[ -f "$UPDATE_ARCHIVE_FIXTURE" && ! -L "$UPDATE_ARCHIVE_FIXTURE" ]] || {
    echo "LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH is not a regular archive fixture." >&2
    exit 1
  }
  [[ "${UPDATE_ARCHIVE_FIXTURE:A}" == "$UPDATE_ARCHIVE_FIXTURE" ]] || {
    echo "LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH must not traverse symlinks." >&2
    exit 1
  }
  test_environment+=("LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH=$UPDATE_ARCHIVE_FIXTURE")
fi
if [[ -n "$APPLICATION_FIXTURE" ]]; then
  validate_absolute_path LOCAL_HARNESS_TEST_APP_PATH "$APPLICATION_FIXTURE"
  [[ -d "$APPLICATION_FIXTURE" && ! -L "$APPLICATION_FIXTURE" ]] || {
    echo "LOCAL_HARNESS_TEST_APP_PATH is not a regular app fixture." >&2
    exit 1
  }
  [[ "${APPLICATION_FIXTURE:A}" == "$APPLICATION_FIXTURE" ]] || {
    echo "LOCAL_HARNESS_TEST_APP_PATH must not traverse symlinks." >&2
    exit 1
  }
  test_environment+=("LOCAL_HARNESS_TEST_APP_PATH=$APPLICATION_FIXTURE")
fi

# Compile all test products under a generous but bounded machine-wide profile.
# A filtered toolbar test must measure the renderer itself, not SwiftPM's
# compiler/linker working set, so execution happens separately with --skip-build.
run_guarded "Swift test compilation" 3600 25769803776 10 34359738368 -- \
  /usr/bin/env -i "${test_environment[@]}" /usr/bin/swift build \
  --package-path "$PROJECT_DIR" \
  --disable-sandbox \
  --jobs "$SWIFT_BUILD_JOBS" \
  --build-tests \
  "${testing_arguments[@]}" \
  -Xswiftc -warnings-as-errors

# Resolve and attest the just-built bundle before any test process starts. The
# path is reused by the signed first-party host launch and deployment-target
# gate, so execution and post-test inspection cannot diverge.
SWIFTPM_BIN_PATH="$(run_guarded "SwiftPM binary-path query" 600 8589934592 5 12884901888 -- \
  /usr/bin/env -i "${test_environment[@]}" /usr/bin/swift build \
  --package-path "$PROJECT_DIR" \
  --disable-sandbox \
  --jobs "$SWIFT_BUILD_JOBS" \
  --show-bin-path)"
validate_absolute_path SwiftPM-bin-path "$SWIFTPM_BIN_PATH"
[[ -d "$SWIFTPM_BIN_PATH" && ! -L "$PROJECT_DIR/.build" \
   && "${SWIFTPM_BIN_PATH:A}" == "$SWIFTPM_BIN_PATH" \
   && "$SWIFTPM_BIN_PATH" == "$PROJECT_DIR/.build/"* ]] || {
  echo "SwiftPM reported an unsafe or unexpected binary output path." >&2
  exit 1
}
TEST_BUNDLE_EXECUTABLE="$SWIFTPM_BIN_PATH/LocalHarnessPackageTests.xctest/Contents/MacOS/LocalHarnessPackageTests"
[[ -f "$TEST_BUNDLE_EXECUTABLE" && ! -L "$TEST_BUNDLE_EXECUTABLE" \
   && -x "$TEST_BUNDLE_EXECUTABLE" \
   && "${TEST_BUNDLE_EXECUTABLE:A}" == "$TEST_BUNDLE_EXECUTABLE" ]] || {
  print -u2 "The just-built Swift Testing bundle executable is unsafe or missing."
  exit 126
}

# The device-attestation suite is an executable qualification target because it
# must run without importing or touching the app's private Swift Testing host.
# Execute the exact just-built product inside the same clean home, watchdog,
# cache, and filesystem boundary as the canonical native gate.
DEVICE_ATTESTATION_TEST_EXECUTABLE="$SWIFTPM_BIN_PATH/DeviceAttestationAuthorityTests"
if [[ "$SWIFT_TEST_PROFILE" == "full" ]]; then
  [[ -f "$DEVICE_ATTESTATION_TEST_EXECUTABLE" && ! -L "$DEVICE_ATTESTATION_TEST_EXECUTABLE" \
     && -x "$DEVICE_ATTESTATION_TEST_EXECUTABLE" \
     && "${DEVICE_ATTESTATION_TEST_EXECUTABLE:A}" == "$DEVICE_ATTESTATION_TEST_EXECUTABLE" ]] || {
    print -u2 "The just-built device-attestation qualification executable is unsafe or missing."
    exit 126
  }
  run_guarded "Device-attestation authority qualification" 120 2147483648 3 3221225472 -- \
    /usr/bin/env -i "${test_environment[@]}" "$DEVICE_ATTESTATION_TEST_EXECUTABLE"
fi

if [[ "$SWIFT_TEST_PROFILE" == "full" ]]; then
  # Enumerate the independently built binary before executing it, then bind
  # that complete function topology to the checked-in release plan. Event
  # accounting below separately proves that exactly the same count ran.
  umask 077
  run_guarded "Swift full-suite topology enumeration" 600 8589934592 5 12884901888 -- \
    /usr/bin/env -i "${test_environment[@]}" /usr/bin/swift test \
      --package-path "$PROJECT_DIR" \
      --disable-sandbox \
      --jobs "$SWIFT_BUILD_JOBS" \
      list --skip-build --disable-xctest --enable-swift-testing \
      > "$TEST_PLAN_STREAM"
  /bin/chmod 0600 "$TEST_PLAN_STREAM"
  run_guarded "Swift full-suite topology verification" 120 1073741824 2 2147483648 -- \
    /usr/bin/env -i HOME="$TEST_HOME" CFFIXED_USER_HOME="$TEST_HOME" \
      PATH="$SAFE_PATH" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
      "$NODE" "$PROJECT_DIR/scripts/verify-swift-test-plan.mjs" \
      "$TEST_PLAN_STREAM" "$PROJECT_DIR/Config/SwiftTestPlan.json"
fi

# SwiftPM normally executes its Apple helper as a bare command-line binary.
# Repackaging that signed binary as an unsigned app triggers a macOS execution-
# policy prompt before dyld reaches its entry point, while re-signing it would
# silently replace Apple's identity. Compile the reviewed loader as the signed
# executable of a private LSUIElement app instead. The app explicitly opts out
# of automatic termination and the loader also holds both ProcessInfo counters
# before dlopen. There is deliberately no bare-helper, LaunchServices, or
# activation-policy fallback.
TEST_HOST_APP="$ISOLATION_ROOT/FulmarSwiftTestingHost.app"
EXPECTED_TEST_HOST_EXECUTABLE="$TEST_HOST_APP/Contents/MacOS/FulmarSwiftTestingHost"
TEST_HOST_EXECUTABLE="$(run_guarded "private Swift Testing host assembly" 120 1073741824 2 2147483648 -- \
  /usr/bin/env -i HOME="$TEST_HOME" CFFIXED_USER_HOME="$TEST_HOME" \
    TMPDIR="$TEST_TMP/" PATH="$SAFE_PATH" USER="$TEST_USER" LOGNAME="$TEST_USER" \
    LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    /bin/sh -p "$PROJECT_DIR/scripts/prepare-swift-testing-host.sh" \
    "$SWIFT_TEST_HOST_SOURCE" "$TEST_HOST_APP" "$SWIFT_TEST_HOST_COMPILER" \
    "$SDKROOT" "$MINIMUM_MACOS")"
[[ "$TEST_HOST_EXECUTABLE" == "$EXPECTED_TEST_HOST_EXECUTABLE" \
   && -f "$TEST_HOST_EXECUTABLE" && ! -L "$TEST_HOST_EXECUTABLE" \
   && -x "$TEST_HOST_EXECUTABLE" ]] || {
  print -u2 "The private Swift Testing host did not publish its exact executable."
  exit 126
}

HOST_MAJOR="$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F. '{print $1}')"
[[ "$HOST_MAJOR" == <-> && "$HOST_MAJOR" -ge 15 && "$HOST_MAJOR" -le 99 ]] || finish_gate 126
test_status=0
event_status=0
if [[ "$SWIFT_TEST_PROFILE" == "full" ]]; then
  # Swift Testing 1902 can terminate its async-main drain with status zero after
  # several sequential MainActor/AppKit functions while omitting runEnded. Run
  # every independently enumerated function in a fresh signed host instead.
  # The shard driver proves selector uniqueness, exact discovery, complete event
  # accounting, and unchanged host/bundle/plan authority for all 1,000+ shards.
  run_guarded "Swift isolated full test suite" "$SWIFT_WATCHDOG_SECONDS" \
    "$SWIFT_WATCHDOG_RSS_BYTES" "$SWIFT_WATCHDOG_RSS_GRACE" \
    "$SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES" -- \
    /usr/bin/env -i "${test_environment[@]}" "$NODE" \
      "$PROJECT_DIR/scripts/run-swift-test-shards.mjs" \
      "$TEST_PLAN_STREAM" "$TEST_HOST_EXECUTABLE" "$TEST_BUNDLE_EXECUTABLE" \
      "$ISOLATION_ROOT" "$HOST_MAJOR" "$PROJECT_DIR/Config/SwiftTestPlan.json" \
      "$SWIFT_TEST_FIXTURE_PROFILE" "$PROJECT_DIR/scripts/verify-swift-test-events.mjs" \
      || test_status=$?
else
  run_guarded "Swift focused test suite" "$SWIFT_WATCHDOG_SECONDS" \
    "$SWIFT_WATCHDOG_RSS_BYTES" "$SWIFT_WATCHDOG_RSS_GRACE" \
    "$SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES" -- \
    /usr/bin/env -i "${test_environment[@]}" "$TEST_HOST_EXECUTABLE" \
      --test-bundle-path "$TEST_BUNDLE_EXECUTABLE" \
      "${test_selection_arguments[@]}" \
      --no-parallel \
      --event-stream-output-path "$EVENT_STREAM" \
      --event-stream-version 0 \
      --testing-library swift-testing || test_status=$?
  run_guarded "Swift event-accounting verification" 120 1073741824 2 2147483648 -- \
    /usr/bin/env -i HOME="$TEST_HOME" CFFIXED_USER_HOME="$TEST_HOME" \
      PATH="$SAFE_PATH" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
      "$NODE" "$PROJECT_DIR/scripts/verify-swift-test-events.mjs" \
      "$EVENT_STREAM" "$HOST_MAJOR" "$SWIFT_TEST_PROFILE" \
      "$PROJECT_DIR/Config/SwiftTestPlan.json" \
      "$SWIFT_TEST_FIXTURE_PROFILE" || event_status=$?
fi
if (( test_status != 0 )); then
  finish_gate "$test_status"
fi
if (( event_status != 0 )); then
  finish_gate 126
fi

# Swift Testing's summary banner can say `arm64e-apple-macos14.0` because it
# reports Apple's prebuilt Testing.framework slice. It is not Fulmar's product
# deployment target. Inspect the product and exact bundle executed above.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-swiftpm-deployment-target.sh" \
  "$MINIMUM_MACOS" \
  "$SWIFTPM_BIN_PATH/LocalHarness" \
  "$SWIFTPM_BIN_PATH/LocalHarnessPackageTests.xctest/Contents/MacOS/LocalHarnessPackageTests"
finish_gate 0
