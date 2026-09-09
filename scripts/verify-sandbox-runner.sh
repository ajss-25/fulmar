#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
RUNNER="$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner"
CREDENTIAL_HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
WORKSPACE="$PROJECT_DIR/build/sandbox-canary.$$"
OUTSIDE_ROOT="$PROJECT_DIR/build/sandbox-outside.$$"
OUTSIDE_TARGET="$OUTSIDE_ROOT/denied.txt"
READONLY_ROOT="$PROJECT_DIR/build/sandbox-readonly.$$"
SANDBOX_TEMP="$WORKSPACE/.private-tmp"
WORKSPACE_ROOTS="[\"$WORKSPACE\"]"
READONLY_ROOTS="[\"$READONLY_ROOT\"]"
DSH_LIKE_PARENT_PID=""
RUNNER_CANARY_PID=""
TOOL_CANARY_PID=""
DESCENDANT_CANARY_PID=""
UNRELATED_CANARY_PID=""
LIMIT_RUNNER_PID=""
LIMIT_CASE_STATUS=""
DIRECT_RUNNER_PID=""
DIRECT_TOOL_PID=""
DIRECT_DESCENDANT_PID=""

cleanup() {
  local exit_code="${1:-$?}"
  for candidate in "$DSH_LIKE_PARENT_PID" "$RUNNER_CANARY_PID" "$TOOL_CANARY_PID" "$DESCENDANT_CANARY_PID" "$UNRELATED_CANARY_PID" "$LIMIT_RUNNER_PID" "$DIRECT_RUNNER_PID" "$DIRECT_TOOL_PID" "$DIRECT_DESCENDANT_PID"; do
    if [[ "$candidate" == <-> ]] && /bin/kill -0 "$candidate" >/dev/null 2>&1; then
      /bin/kill -KILL "$candidate" >/dev/null 2>&1 || true
    fi
  done
  if [[ -n "${CREDENTIAL_TEST_REFERENCE:-}" && -x "$CREDENTIAL_HELPER" ]]; then
    "$CREDENTIAL_HELPER" unset "$CREDENTIAL_TEST_REFERENCE" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKSPACE"
  rm -rf "$OUTSIDE_ROOT"
  rm -rf "$READONLY_ROOT"
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

[[ -x "$RUNNER" && -x "$CREDENTIAL_HELPER" ]] || { print -u2 "Missing sandbox or credential helper."; exit 1; }
mkdir -p "$WORKSPACE" "$OUTSIDE_ROOT" "$READONLY_ROOT"
mkdir -p "$SANDBOX_TEMP"
chmod 700 "$WORKSPACE" "$OUTSIDE_ROOT" "$READONLY_ROOT" "$SANDBOX_TEMP"

run_workspace() {
  (cd "$WORKSPACE" && env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
    --tmpfs /tmp --bind "$WORKSPACE" "$WORKSPACE" -- "$@")
}

run_readonly() {
  (cd "$WORKSPACE" && env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
    -- "$@")
}

run_supervisor() {
  (cd "$WORKSPACE" && env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" --supervisor-child -- "$@")
}

run_workspace_connected() {
  (cd "$WORKSPACE" && env LOCAL_HARNESS_STRICT_LOCAL=0 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
    --tmpfs /tmp --bind "$WORKSPACE" "$WORKSPACE" -- "$@")
}

# Run an intentionally hostile stderr producer with an outer five-second
# watchdog. If the runner ever regresses into a blocking pipe read, the test
# still fails promptly and killing the exact runner causes its parent-death
# supervisor to reap the sandboxed process group.
run_workspace_limit_case() {
  local error_file="$1"
  shift
  (
    cd "$WORKSPACE"
    exec env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
      --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
      --tmpfs /tmp --bind "$WORKSPACE" "$WORKSPACE" -- "$@"
  ) >/dev/null 2>"$error_file" &
  LIMIT_RUNNER_PID="$!"
  for _ in {1..100}; do
    /bin/kill -0 "$LIMIT_RUNNER_PID" >/dev/null 2>&1 || break
    sleep 0.05
  done
  if /bin/kill -0 "$LIMIT_RUNNER_PID" >/dev/null 2>&1; then
    /bin/kill -KILL "$LIMIT_RUNNER_PID" >/dev/null 2>&1 || true
    wait "$LIMIT_RUNNER_PID" >/dev/null 2>&1 || true
    LIMIT_RUNNER_PID=""
    print -u2 "A bounded-stderr sandbox case did not complete within five seconds."
    return 1
  fi
  if wait "$LIMIT_RUNNER_PID"; then
    LIMIT_CASE_STATUS=0
  else
    LIMIT_CASE_STATUS="$?"
  fi
  LIMIT_RUNNER_PID=""
}

assert_stderr_limit_result() {
  local error_file="$1"
  local expected_byte="$2"
  local diagnostic='fulmar-sandbox-runner: child stderr exceeded 65536 bytes; output was truncated and the exact process group was stopped'
  [[ "$LIMIT_CASE_STATUS" == "125" ]] || {
    print -u2 "A bounded-stderr case returned $LIMIT_CASE_STATUS instead of the typed exit status 125."
    return 1
  }
  [[ "$(tail -n 1 "$error_file")" == "$diagnostic" ]] || {
    print -u2 "A bounded-stderr case omitted its exact truncation diagnostic."
    return 1
  }
  local expected_size=$((65536 + 1 + ${#diagnostic} + 1))
  [[ "$(wc -c < "$error_file" | tr -d ' ')" == "$expected_size" ]] || {
    print -u2 "A bounded-stderr case retained more or fewer than the exact 65536-byte cap."
    return 1
  }
  [[ "$(/usr/bin/head -c 65536 "$error_file" | /usr/bin/tr -d "$expected_byte" | wc -c | tr -d ' ')" == "0" ]] || {
    print -u2 "A bounded-stderr case changed the retained diagnostic prefix."
    return 1
  }
}

if run_readonly /usr/bin/touch "$WORKSPACE/read-only-denied.txt" >/dev/null 2>&1; then
  print -u2 "Read-only mode unexpectedly allowed a workspace write."
  exit 1
fi
[[ ! -e "$WORKSPACE/read-only-denied.txt" ]]

run_workspace /usr/bin/touch "$WORKSPACE/allowed.txt"
[[ -f "$WORKSPACE/allowed.txt" ]]

printf 'reviewed-skill-resource' > "$READONLY_ROOT/reference.txt"
chmod 600 "$READONLY_ROOT/reference.txt"
[[ "$(run_workspace /bin/cat "$READONLY_ROOT/reference.txt")" == "reviewed-skill-resource" ]]
[[ "$(run_supervisor /bin/cat "$READONLY_ROOT/reference.txt")" == "reviewed-skill-resource" ]]
if run_workspace /usr/bin/touch "$READONLY_ROOT/write-denied.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly wrote into a read-only skill root."
  exit 1
fi
[[ ! -e "$READONLY_ROOT/write-denied.txt" ]]
if run_workspace /bin/ln "$READONLY_ROOT/reference.txt" "$WORKSPACE/skill-hardlink.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly hard-linked a read-only skill resource into the workspace."
  exit 1
fi
[[ ! -e "$WORKSPACE/skill-hardlink.txt" ]]

READONLY_LINK="$OUTSIDE_ROOT/linked-readonly"
ln -s "$READONLY_ROOT" "$READONLY_LINK"
if (
  cd "$WORKSPACE"
  env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="[\"$READONLY_LINK\"]" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent -- /usr/bin/true
) >/dev/null 2>&1; then
  print -u2 "The sandbox runner unexpectedly accepted a linked read-only root."
  exit 1
fi

printf 'outside-read-sentinel' > "$OUTSIDE_ROOT/read-denied.txt"
if run_workspace /bin/cat "$OUTSIDE_ROOT/read-denied.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly read outside the selected workspace."
  exit 1
fi
if run_supervisor /bin/cat "$OUTSIDE_ROOT/read-denied.txt" >/dev/null 2>&1; then
  print -u2 "A supervisor child unexpectedly read outside the selected workspace."
  exit 1
fi

if run_workspace /usr/bin/touch "$OUTSIDE_TARGET" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly wrote outside the selected workspace."
  exit 1
fi
[[ ! -e "$OUTSIDE_TARGET" ]]

if (
  cd "$WORKSPACE"
  run_workspace /usr/bin/touch "../sandbox-outside.$$/traversal.txt" >/dev/null 2>&1
); then
  print -u2 "The tool sandbox unexpectedly allowed parent traversal outside the workspace."
  exit 1
fi

ln -s "$OUTSIDE_ROOT" "$WORKSPACE/outside-symlink"
if run_workspace /usr/bin/touch "$WORKSPACE/outside-symlink/symlink-escape.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly allowed a symlink escape."
  exit 1
fi

printf 'protected' > "$OUTSIDE_ROOT/hardlink-source.txt"
if run_workspace /bin/ln "$OUTSIDE_ROOT/hardlink-source.txt" "$WORKSPACE/new-hardlink.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly created a hard link to an outside file."
  exit 1
fi
/bin/ln "$OUTSIDE_ROOT/hardlink-source.txt" "$WORKSPACE/preexisting-hardlink.txt"
if run_workspace /bin/sh -p -c 'printf changed > "$1"' sh "$WORKSPACE/preexisting-hardlink.txt" >/dev/null 2>&1; then
  print -u2 "The tool sandbox unexpectedly wrote through a pre-existing hard link."
  exit 1
fi
[[ "$(cat "$OUTSIDE_ROOT/hardlink-source.txt")" == "protected" ]]

if run_workspace /bin/sh -p -c '/usr/bin/touch "$1"' sh "$OUTSIDE_ROOT/child-escape.txt" >/dev/null 2>&1; then
  print -u2 "A child of a sandboxed tool unexpectedly wrote outside the workspace."
  exit 1
fi

invalid_target="$WORKSPACE/invalid-runner-executed.txt"
if env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" \
  "$RUNNER" --ro-bind /private/tmp / -- /usr/bin/touch "$invalid_target" >/dev/null 2>&1; then
  print -u2 "The sandbox runner unexpectedly accepted altered grammar."
  exit 1
fi
[[ ! -e "$invalid_target" ]]

LOCAL_HARNESS_AUTH_TOKEN="must-not-leak" OLLAMA_API_KEY="must-not-leak" \
  run_workspace /bin/sh -p -c 'test -z "${LOCAL_HARNESS_AUTH_TOKEN:-}" && test -z "${OLLAMA_API_KEY:-}" && test -z "${LOCAL_HARNESS_READONLY_ROOTS:-}"'
LOCAL_HARNESS_AUTH_TOKEN="must-not-leak" OLLAMA_API_KEY="must-not-leak" \
  run_supervisor /bin/sh -p -c 'test -z "${LOCAL_HARNESS_AUTH_TOKEN:-}" && test -z "${OLLAMA_API_KEY:-}" && test -z "${LOCAL_HARNESS_READONLY_ROOTS:-}"'

if run_workspace /usr/bin/curl -fsS --max-time 2 https://example.com/ >/dev/null 2>&1; then
  print -u2 "Strict Local unexpectedly allowed an external tool connection."
  exit 1
fi

if run_workspace /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  print -u2 "A Strict Local tool unexpectedly reached another loopback service."
  exit 1
fi

if run_supervisor /usr/bin/curl -fsS --max-time 2 https://example.com/ >/dev/null 2>&1; then
  print -u2 "A Strict Local supervisor child unexpectedly reached the internet."
  exit 1
fi
if run_supervisor /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  print -u2 "A supervisor child unexpectedly reached another loopback service."
  exit 1
fi
if run_supervisor /usr/bin/touch "$OUTSIDE_ROOT/supervisor-write-denied.txt" >/dev/null 2>&1; then
  print -u2 "A supervisor child unexpectedly wrote outside the selected workspace."
  exit 1
fi
[[ ! -e "$OUTSIDE_ROOT/supervisor-write-denied.txt" ]]

KEYCHAIN_FILE="$HOME/Library/Keychains/login.keychain-db"
if [[ -f "$KEYCHAIN_FILE" ]] && run_workspace /bin/cat "$KEYCHAIN_FILE" >/dev/null 2>&1; then
  print -u2 "Strict Local unexpectedly allowed a tool to read the login Keychain file."
  exit 1
fi
if [[ -f "$KEYCHAIN_FILE" ]] && run_supervisor /bin/cat "$KEYCHAIN_FILE" >/dev/null 2>&1; then
  print -u2 "A Strict Local supervisor child unexpectedly read the login Keychain file."
  exit 1
fi

# A tool must not be able to turn the app's own helper (or a copied alias of it)
# into a credential oracle. This protection remains active in Connected mode.
CREDENTIAL_TEST_REFERENCE="LOCAL_HARNESS_SANDBOX_TEST_$$"
printf 'credential-canary' | "$CREDENTIAL_HELPER" set "$CREDENTIAL_TEST_REFERENCE"
[[ "$("$CREDENTIAL_HELPER" describe "$CREDENTIAL_TEST_REFERENCE")" == "1" ]]
if run_workspace "$CREDENTIAL_HELPER" get "$CREDENTIAL_TEST_REFERENCE" >/dev/null 2>&1; then
  print -u2 "A sandboxed tool directly executed the credential helper."
  exit 1
fi
ln -s "$CREDENTIAL_HELPER" "$WORKSPACE/credential-helper-symlink"
if run_workspace "$WORKSPACE/credential-helper-symlink" get "$CREDENTIAL_TEST_REFERENCE" >/dev/null 2>&1; then
  print -u2 "A sandboxed tool executed the credential helper through a symlink."
  exit 1
fi
cp "$CREDENTIAL_HELPER" "$WORKSPACE/credential-helper-copy"
chmod 755 "$WORKSPACE/credential-helper-copy"
if run_workspace "$WORKSPACE/credential-helper-copy" get "$CREDENTIAL_TEST_REFERENCE" >/dev/null 2>&1; then
  print -u2 "A copied helper reached Fulmar Keychain credentials."
  exit 1
fi
if run_workspace_connected "$WORKSPACE/credential-helper-copy" get "$CREDENTIAL_TEST_REFERENCE" >/dev/null 2>&1; then
  print -u2 "Connected mode exposed Fulmar Keychain credentials to a tool."
  exit 1
fi
if run_workspace_connected /usr/bin/security find-generic-password \
  -s app.localharness.credentials -a "ref:$CREDENTIAL_TEST_REFERENCE" -w >/dev/null 2>&1; then
  print -u2 "Connected mode allowed a tool to query the Fulmar Keychain service."
  exit 1
fi

# Normal child creation is required by coding workflows, but a direct attempt
# to detach from the runner-owned process group must be denied by Seatbelt.
run_workspace /bin/sh -p -c '/usr/bin/true & wait' >/dev/null
run_workspace /usr/bin/perl -MPOSIX -e \
  '$! = 0; my $session = POSIX::setsid(); exit(($session == -1 && $!{EPERM}) ? 0 : 1)' \
  >/dev/null

# The runner must drain stderr incrementally, retain exactly 64 KiB, emit a
# typed diagnostic/exit status, and stop the whole exact process group. Cover
# a finite burst, a TERM-resistant endless producer, and the easily missed
# case where the group leader exits while a descendant retains the pipe.
FINITE_LIMIT_ERROR="$WORKSPACE/finite-stderr-limit.log"
run_workspace_limit_case "$FINITE_LIMIT_ERROR" /bin/bash -p -c \
  "printf '%070000d' 0 >&2"
assert_stderr_limit_result "$FINITE_LIMIT_ERROR" 0

/bin/sleep 30 &
UNRELATED_CANARY_PID="$!"
ENDLESS_LIMIT_ERROR="$WORKSPACE/endless-stderr-limit.log"
run_workspace_limit_case "$ENDLESS_LIMIT_ERROR" /bin/bash -p -c \
  'trap "" TERM; /usr/bin/yes e | /usr/bin/tr -d "\n" >&2'
assert_stderr_limit_result "$ENDLESS_LIMIT_ERROR" e
/bin/kill -0 "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || {
  print -u2 "Bounded stderr cleanup terminated an unrelated sibling."
  exit 1
}
/bin/kill -KILL "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
wait "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
UNRELATED_CANARY_PID=""

DESCENDANT_LIMIT_ERROR="$WORKSPACE/descendant-stderr-limit.log"
run_workspace_limit_case "$DESCENDANT_LIMIT_ERROR" /bin/bash -p -c \
  '(trap "" TERM; /usr/bin/yes d | /usr/bin/tr -d "\n" >&2) & exit 0'
assert_stderr_limit_result "$DESCENDANT_LIMIT_ERROR" d

# A small Seatbelt denial is not treated as a limit. Preserve the child's
# status and append the existing concise user-facing explanation verbatim.
SMALL_DIAGNOSTIC_ERROR="$WORKSPACE/small-seatbelt-diagnostic.log"
run_workspace_limit_case "$SMALL_DIAGNOSTIC_ERROR" /bin/bash -p -c \
  'printf "sandbox-exec: operation not permitted\\n" >&2; exit 9'
[[ "$LIMIT_CASE_STATUS" == "9" ]] || {
  print -u2 "A small Seatbelt diagnostic did not preserve the child exit status."
  exit 1
}
[[ "$(<"$SMALL_DIAGNOSTIC_ERROR")" == $'sandbox-exec: operation not permitted\npermission denied by Fulmar tool sandbox' ]] || {
  print -u2 "The small Seatbelt diagnostic rewrite changed unexpectedly."
  exit 1
}

# Exercise actual direct runner cancellation in the release binary. The
# deterministic post-spawn/pre-publication boundary itself is covered by the
# DEBUG Swift regression; this candidate row proves the same pre-armed signal
# source forwards and escalates to the complete published group.
DIRECT_TOOL_PID_FILE="$WORKSPACE/direct-signal-tool.pid"
DIRECT_DESCENDANT_PID_FILE="$WORKSPACE/direct-signal-descendant.pid"
(
  cd "$WORKSPACE"
  exec env LOCAL_HARNESS_STRICT_LOCAL=1 LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS" LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS" LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
    --tmpfs /tmp --bind "$WORKSPACE" "$WORKSPACE" -- \
    /bin/bash -p -c '
      trap "" TERM INT HUP
      printf "%s\n" "$$" > "$1"
      /bin/bash -p -c '\''trap "" TERM INT HUP; while :; do /bin/sleep 1; done'\'' &
      printf "%s\n" "$!" > "$2"
      while :; do /bin/sleep 1; done
    ' bash "$DIRECT_TOOL_PID_FILE" "$DIRECT_DESCENDANT_PID_FILE"
) >/dev/null 2>"$WORKSPACE/direct-signal-error.log" &
DIRECT_RUNNER_PID="$!"
for _ in {1..200}; do
  [[ -s "$DIRECT_TOOL_PID_FILE" && -s "$DIRECT_DESCENDANT_PID_FILE" ]] && break
  /bin/kill -0 "$DIRECT_RUNNER_PID" >/dev/null 2>&1 || break
  sleep 0.01
done
[[ -s "$DIRECT_TOOL_PID_FILE" && -s "$DIRECT_DESCENDANT_PID_FILE" ]] || {
  print -u2 "The direct-signal sandbox fixture did not become ready."
  sed -n '1,80p' "$WORKSPACE/direct-signal-error.log" >&2
  exit 1
}
DIRECT_TOOL_PID="$(<"$DIRECT_TOOL_PID_FILE")"
DIRECT_DESCENDANT_PID="$(<"$DIRECT_DESCENDANT_PID_FILE")"
for candidate in "$DIRECT_RUNNER_PID" "$DIRECT_TOOL_PID" "$DIRECT_DESCENDANT_PID"; do
  [[ "$candidate" == <-> ]] || { print -u2 "The direct-signal fixture returned an invalid PID."; exit 1; }
  /bin/kill -0 "$candidate" >/dev/null 2>&1 || { print -u2 "The direct-signal fixture exited before cancellation."; exit 1; }
done
/bin/sleep 30 &
UNRELATED_CANARY_PID="$!"
/bin/kill -TERM "$DIRECT_RUNNER_PID"
for _ in {1..400}; do
  survivors=0
  for candidate in "$DIRECT_RUNNER_PID" "$DIRECT_TOOL_PID" "$DIRECT_DESCENDANT_PID"; do
    /bin/kill -0 "$candidate" >/dev/null 2>&1 && survivors=$((survivors + 1))
  done
  (( survivors == 0 )) && break
  sleep 0.01
done
for candidate in "$DIRECT_RUNNER_PID" "$DIRECT_TOOL_PID" "$DIRECT_DESCENDANT_PID"; do
  if /bin/kill -0 "$candidate" >/dev/null 2>&1; then
    print -u2 "Direct runner cancellation orphaned a sandbox process."
    exit 1
  fi
done
/bin/kill -0 "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || {
  print -u2 "Direct runner cancellation terminated an unrelated sibling."
  exit 1
}
wait "$DIRECT_RUNNER_PID" >/dev/null 2>&1 || true
/bin/kill -KILL "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
wait "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
DIRECT_RUNNER_PID=""
DIRECT_TOOL_PID=""
DIRECT_DESCENDANT_PID=""
UNRELATED_CANARY_PID=""

# Prove the process-group die-with-parent contract with a real, TERM-resistant
# tree. A DSH-like parent launches the runner, the runner establishes its own
# process group, and the sandboxed command creates a same-group descendant. A
# forced parent death must reap the complete leased group while an unrelated
# sibling remains alive.
RUNNER_PID_FILE="$WORKSPACE/runner-canary.pid"
TOOL_PID_FILE="$WORKSPACE/tool-canary.pid"
DESCENDANT_PID_FILE="$WORKSPACE/descendant-canary.pid"
LIFECYCLE_ERROR_FILE="$WORKSPACE/descendant-lifecycle-error.log"
/bin/sleep 30 &
UNRELATED_CANARY_PID="$!"
(
  cd "$WORKSPACE"
  export LOCAL_HARNESS_STRICT_LOCAL=1
  export LOCAL_HARNESS_WORKSPACE_ROOTS="$WORKSPACE_ROOTS"
  export LOCAL_HARNESS_READONLY_ROOTS="$READONLY_ROOTS"
  export LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP"
  exec /usr/bin/perl -e '
  use strict; use warnings;
  my ($pid_file, @command) = @ARGV;
  my $child = fork();
  exit 126 unless defined $child;
  if ($child == 0) { exec { $command[0] } @command; exit 127; }
  open(my $handle, ">", $pid_file) or exit 125;
  print {$handle} "$child\n";
  close($handle) or exit 125;
  waitpid($child, 0);
  exit(($? >> 8) & 255);
  ' "$RUNNER_PID_FILE" "$RUNNER" \
    --ro-bind / / --dev /dev --unshare-pid --proc /proc --die-with-parent \
    --tmpfs /tmp --bind "$WORKSPACE" "$WORKSPACE" -- \
    /bin/sh -p -c '
      trap "" TERM INT HUP
      printf "%s\n" "$$" > "$1"
      /bin/sh -p -c '\''trap "" TERM INT HUP; while :; do /bin/sleep 1; done'\'' &
      printf "%s\n" "$!" > "$2"
      while :; do /bin/sleep 1; done
    ' sh "$TOOL_PID_FILE" "$DESCENDANT_PID_FILE"
) >/dev/null 2>"$LIFECYCLE_ERROR_FILE" &
DSH_LIKE_PARENT_PID="$!"
for _ in {1..100}; do
  [[ -s "$RUNNER_PID_FILE" && -s "$TOOL_PID_FILE" && -s "$DESCENDANT_PID_FILE" ]] && break
  /bin/kill -0 "$DSH_LIKE_PARENT_PID" >/dev/null 2>&1 || break
  sleep 0.05
done
[[ -s "$RUNNER_PID_FILE" && -s "$TOOL_PID_FILE" && -s "$DESCENDANT_PID_FILE" ]] || {
  print -u2 "The sandbox descendant-lifecycle fixture did not become ready."
  [[ -f "$LIFECYCLE_ERROR_FILE" ]] && sed -n '1,80p' "$LIFECYCLE_ERROR_FILE" >&2
  exit 1
}
RUNNER_CANARY_PID="$(<"$RUNNER_PID_FILE")"
TOOL_CANARY_PID="$(<"$TOOL_PID_FILE")"
DESCENDANT_CANARY_PID="$(<"$DESCENDANT_PID_FILE")"
for candidate in "$DSH_LIKE_PARENT_PID" "$RUNNER_CANARY_PID" "$TOOL_CANARY_PID" "$DESCENDANT_CANARY_PID" "$UNRELATED_CANARY_PID"; do
  [[ "$candidate" == <-> ]] || { print -u2 "The sandbox lifecycle fixture returned an invalid PID."; exit 1; }
  /bin/kill -0 "$candidate" >/dev/null 2>&1 || { print -u2 "The sandbox lifecycle fixture exited before the parent-death test."; exit 1; }
done
/bin/kill -KILL "$DSH_LIKE_PARENT_PID"
wait "$DSH_LIKE_PARENT_PID" >/dev/null 2>&1 || true
DSH_LIKE_PARENT_PID=""
for _ in {1..120}; do
  survivors=0
  for candidate in "$RUNNER_CANARY_PID" "$TOOL_CANARY_PID" "$DESCENDANT_CANARY_PID"; do
    /bin/kill -0 "$candidate" >/dev/null 2>&1 && survivors=$((survivors + 1))
  done
  (( survivors == 0 )) && break
  sleep 0.05
done
for candidate in "$RUNNER_CANARY_PID" "$TOOL_CANARY_PID" "$DESCENDANT_CANARY_PID"; do
  if /bin/kill -0 "$candidate" >/dev/null 2>&1; then
    print -u2 "A sandboxed descendant survived its owning parent."
    exit 1
  fi
done
/bin/kill -0 "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || {
  print -u2 "Sandbox lifecycle cleanup terminated an unrelated process."
  exit 1
}
/bin/kill -KILL "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
wait "$UNRELATED_CANARY_PID" >/dev/null 2>&1 || true
UNRELATED_CANARY_PID=""
RUNNER_CANARY_PID=""
TOOL_CANARY_PID=""
DESCENDANT_CANARY_PID=""

print "Deep sandbox matrix passed: read-only, workspace read/write containment, traversal, symlink, hard-link, child, grammar, environment, loopback, egress, private-file, helper-exec, Keychain-IPC, Connected-mode secret boundaries, direct detach denial, exact 64 KiB finite/endless/leader-exit stderr limits with typed exit 125 and sibling survival, small Seatbelt diagnostic preservation, pre-armed direct runner signal cleanup, and TERM-resistant parent-death same-process-group cleanup."
