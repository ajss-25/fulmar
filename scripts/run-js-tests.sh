#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
NODE="$PROJECT_DIR/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
TEST_USER="$(/usr/bin/id -un)"
TEST_UID="$(/usr/bin/id -u)"
TEST_GROUP="$(/usr/bin/id -gn)"

ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 5 \
    --emergency-rss-bytes 12884901888 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete JavaScript gate" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  echo "The JavaScript gate inherited an invalid root-watchdog attestation." >&2
  exit 1
fi

[[ -x "$NODE" && ! -L "$NODE" && "${NODE:A}" == "$NODE" ]] || {
  echo "The reviewed bundled Node runtime is unavailable or linked." >&2
  exit 1
}

umask 077
ISOLATION_ROOT="$(/usr/bin/mktemp -d /private/tmp/fulmar-js-tests.XXXXXX)"
CANONICAL_ROOT="/tmp/${ISOLATION_ROOT:t}"
TEST_HOME="$CANONICAL_ROOT/home"
TEST_TMP="$CANONICAL_ROOT/tmp"
TEST_CACHE="$CANONICAL_ROOT/cache"
/bin/mkdir -p \
  "$TEST_HOME/Library/Application Support" \
  "$TEST_HOME/Library/Caches" \
  "$TEST_TMP" \
  "$TEST_CACHE/xdg" \
  "$TEST_CACHE/npm"
/bin/chmod 0700 "$ISOLATION_ROOT" "$TEST_HOME" "$TEST_TMP" "$TEST_CACHE"
/usr/bin/chgrp "$TEST_GROUP" \
  "$ISOLATION_ROOT" "$TEST_HOME" "$TEST_TMP" "$TEST_CACHE" \
  "$TEST_CACHE/xdg" "$TEST_CACHE/npm"
ISOLATION_ROOT_IDENTITY="$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT")" || {
  print -u2 "The JavaScript-test isolation root could not be attested."
  exit 126
}
EVENT_NONCE="$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]' | /usr/bin/tr -d '-')"
[[ "${#EVENT_NONCE}" == 32 && "$EVENT_NONCE" != *[^a-f0-9]* ]] || exit 126
EVENT_STREAM="$ISOLATION_ROOT/events-$EVENT_NONCE.jsonl"
[[ ! -e "$EVENT_STREAM" && ! -L "$EVENT_STREAM" ]] || exit 126
setopt localoptions noclobber
: > "$EVENT_STREAM" || exit 126
/bin/chmod 0600 "$EVENT_STREAM" || exit 126
[[ "$(/usr/bin/stat -f '%u:%Lp:%l:%HT' "$EVENT_STREAM")" == "$TEST_UID:600:1:Regular File" ]] || exit 126

cleanup() {
  [[ -n "$ISOLATION_ROOT" ]] || return 0
  case "$ISOLATION_ROOT" in
    /private/tmp/fulmar-js-tests.*) ;;
    *) print -u2 "Refusing to remove an invalid JavaScript-test isolation root."; return 126 ;;
  esac
  [[ -d "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" \
     && "$(/usr/bin/stat -f '%d:%i:%u:%HT:%Lp' "$ISOLATION_ROOT" 2>/dev/null)" == "$ISOLATION_ROOT_IDENTITY" ]] || {
    print -u2 "Refusing to remove a changed JavaScript-test isolation root."
    return 126
  }
  /bin/rm -rf -- "$ISOLATION_ROOT" || return 126
  [[ ! -e "$ISOLATION_ROOT" && ! -L "$ISOLATION_ROOT" ]] || return 126
  ISOLATION_ROOT=""
}
trap 'cleanup >/dev/null 2>&1 || true' EXIT
trap 'cleanup >/dev/null 2>&1 || true; exit 129' HUP
trap 'cleanup >/dev/null 2>&1 || true; exit 130' INT
trap 'cleanup >/dev/null 2>&1 || true; exit 143' TERM

# This is an exact allowlist. In particular, proxy/CA variables, dynamic-loader
# hooks, SSH agents, package-manager credentials, cloud tokens, and the caller's
# HOME/caches never cross into Node or its test children.
typeset -a test_environment
test_environment=(
  "HOME=$TEST_HOME"
  "CFFIXED_USER_HOME=$TEST_HOME"
  "TMPDIR=$TEST_TMP/"
  "XDG_CACHE_HOME=$TEST_CACHE/xdg"
  "NPM_CONFIG_CACHE=$TEST_CACHE/npm"
  "PATH=$SAFE_PATH"
  "USER=$TEST_USER"
  "LOGNAME=$TEST_USER"
  "LANG=en_US.UTF-8"
  "LC_CTYPE=UTF-8"
  "NO_COLOR=1"
  "LOCAL_HARNESS_TEST_NODE=$NODE"
  "LOCAL_HARNESS_JS_TEST_ISOLATION_ROOT=$CANONICAL_ROOT"
)
candidate_policy="${FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS:-0}"
[[ "$candidate_policy" == "0" || "$candidate_policy" == "1" ]] || {
  echo "FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS must be 0 or 1." >&2
  exit 64
}
if [[ "$candidate_policy" == "1" ]]; then
  test_environment+=("FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS=1")
fi

fulmar_append_root_watchdog_environment test_environment

# Node's per-file process-isolation workers discard descriptor 198 while
# retaining the authenticated root environment.  That is correctly rejected
# as a partial capability, but it also means an aggregate gate cannot use those
# workers.  Keep the aggregate `--test` gate in this already-authenticated root
# process, serially, and own both options so callers cannot weaken or conflict
# with the reviewed execution model.  Non-test uses (for example `-e` probes)
# remain untouched.
typeset -a node_arguments
node_arguments=("$@")
test_mode=0
for argument in "${node_arguments[@]}"; do
  case "$argument" in
    --test|--test=true) test_mode=1 ;;
    --test=*)
      print -u2 "run-js-tests.sh requires --test or --test=true for JavaScript test mode."
      exit 64
      ;;
    --no-test|--no-test-*)
      print -u2 "run-js-tests.sh rejects JavaScript test-runner negation options."
      exit 64
      ;;
    --experimental-test-isolation|--experimental-test-isolation=*|--test-concurrency|--test-concurrency=*)
      # These options can activate or alter node:test even when the caller
      # omits the canonical --test switch.  The runner always owns them.
      print -u2 "run-js-tests.sh owns JavaScript test isolation and concurrency."
      exit 64
      ;;
    --test-*)
      # Filtering, only/shard, reporter, timeout, force-exit, snapshot, and
      # coverage switches can all turn a nominal gate into a partial run.
      print -u2 "run-js-tests.sh does not accept caller-owned JavaScript test options."
      exit 64
      ;;
  esac
done
if (( test_mode == 1 )); then
  operand_count=0
  typeset -A seen_test_operands
  for argument in "${node_arguments[@]}"; do
    case "$argument" in
      --test|--test=true) ;;
      -*)
        print -u2 "run-js-tests.sh accepts only reviewed test-file operands in JavaScript test mode."
        exit 64
        ;;
      *)
        [[ "$argument" == *.mjs && -f "$argument" && ! -L "$argument" ]] || {
          print -u2 "run-js-tests.sh requires existing non-linked .mjs test-file operands."
          exit 64
        }
        canonical_operand="${argument:A}"
        [[ -z "${seen_test_operands[$canonical_operand]-}" ]] || {
          print -u2 "run-js-tests.sh rejects duplicate JavaScript test-file operands."
          exit 64
        }
        seen_test_operands[$canonical_operand]=1
        (( operand_count += 1 ))
        ;;
    esac
  done
  (( operand_count > 0 )) || {
    print -u2 "run-js-tests.sh requires at least one JavaScript test file."
    exit 64
  }
  full_test_count="$(/usr/bin/find "$PROJECT_DIR/Tests/JS" -mindepth 1 -maxdepth 1 -type f -name '*.mjs' -print \
    | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  test_profile=full-source
  (( operand_count == full_test_count )) || test_profile=focused
  if [[ "$test_profile" == full-source ]]; then
    while IFS= read -r full_test_file; do
      [[ -n "${seen_test_operands[$full_test_file]-}" ]] || test_profile=focused
    done < <(/usr/bin/find "$PROJECT_DIR/Tests/JS" -mindepth 1 -maxdepth 1 -type f -name '*.mjs' -print)
  fi
  if [[ "$test_profile" == full-source && "$candidate_policy" == 1 ]]; then
    test_profile=full-candidate
  fi
  node_arguments=(--experimental-test-isolation=none --test-concurrency=1 \
    --test-reporter=spec --test-reporter-destination=stdout \
    --test-reporter="$PROJECT_DIR/scripts/self-root-test-event-reporter.mjs" \
    --test-reporter-destination="$EVENT_STREAM" \
    "${node_arguments[@]}")
fi

# Fixture modes must be deterministic across developer shells and CI. The
# isolation root itself remains 0700, so conventional 0644/0755 fixture nodes
# are still unreachable by other users while mode-attestation tests stay exact.
umask 022
set +e
/usr/bin/env -i "${test_environment[@]}" "$NODE" "${node_arguments[@]}"
node_status=$?
set -e

if (( node_status == 0 && test_mode == 1 )); then
  /usr/bin/env -i HOME="$TEST_HOME" PATH="$SAFE_PATH" LANG=en_US.UTF-8 LC_CTYPE=UTF-8 \
    "$NODE" "$PROJECT_DIR/scripts/verify-js-test-events.mjs" \
    "$EVENT_STREAM" "$test_profile" "$PROJECT_DIR" || node_status=126
fi

trap - EXIT HUP INT TERM
if ! cleanup; then
  print -u2 "The JavaScript gate could not remove its attested private isolation root."
  exit 126
fi
exit "$node_status"
