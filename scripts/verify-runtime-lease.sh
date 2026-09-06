#!/bin/zsh -f
set -euo pipefail
unsetopt BG_NICE

PROJECT_DIR="${0:A:h:h}"
LEASE="${1:-$PROJECT_DIR/.build/debug/LocalHarnessRuntimeLease}"
AUTH_RELAY="$PROJECT_DIR/Tests/Fixtures/RuntimeAuthenticationRelay.pl"
TEST_ROOT="$(mktemp -d /private/tmp/fulmar-runtime-lease.XXXXXX)"
UNRELATED_PID=""
NORMAL_PID=""
CRASH_HOST_PID=""
CRASH_RUNTIME_PID=""
TOKEN="runtime-lease-token-0123456789_ABCDE"
NONCE="runtime-lease-nonce-0123456789_ABCDE"

runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}

fail() {
  print -u2 "Runtime-lease verification failed: $1"
  exit 1
}

exact_pid_is_alive() {
  local candidate="$1"
  [[ "$candidate" == <-> ]] && /bin/kill -0 "$candidate" >/dev/null 2>&1
}

exact_group_is_alive() {
  local candidate="$1"
  [[ "$candidate" == <-> ]] && /bin/kill -0 -- "-$candidate" >/dev/null 2>&1
}

wait_for_file() {
  local marker_path="$1"
  for _ in {1..100}; do
    [[ -s "$marker_path" ]] && return 0
    /bin/sleep 0.02
  done
  return 1
}

wait_for_exact_exit() {
  local candidate="$1"
  for _ in {1..200}; do
    exact_pid_is_alive "$candidate" || return 0
    /bin/sleep 0.02
  done
  return 1
}

wait_for_exact_group_exit() {
  local candidate="$1"
  for _ in {1..200}; do
    exact_group_is_alive "$candidate" || return 0
    /bin/sleep 0.02
  done
  return 1
}

cleanup() {
  local exit_code="${1:-$?}"
  # Cleanup is deliberately restricted to the exact PIDs and process groups
  # created by this test. Never use process names, ports, pgrep, or pkill.
  for candidate in "$CRASH_RUNTIME_PID" "$NORMAL_PID"; do
    if [[ "$candidate" == <-> ]] && exact_group_is_alive "$candidate"; then
      /bin/kill -KILL -- "-$candidate" >/dev/null 2>&1 || true
    fi
  done
  for candidate in "$CRASH_HOST_PID" "$UNRELATED_PID"; do
    if [[ "$candidate" == <-> ]] && exact_pid_is_alive "$candidate"; then
      /bin/kill -KILL "$candidate" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$TEST_ROOT"
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

[[ "$LEASE" == /* && -x "$LEASE" && ! -L "$LEASE" ]] || fail "the exact helper path is missing, relative, non-executable, or a symlink"
[[ -f "$AUTH_RELAY" && ! -L "$AUTH_RELAY" ]] || fail "the runtime-authentication relay fixture is missing or linked"

# The internal guardian cannot be invoked by an unrelated process, even when
# supplied syntactically valid PIDs. A successful direct invocation would let
# an attacker aim its process-group cleanup at a process it does not own.
if "$LEASE" --fulmar-runtime-guardian-v1 "$$" "$$" >/dev/null 2>&1; then
  fail "an unrelated process invoked guardian mode"
else
  case_status="$?"
  [[ "$case_status" == "125" ]] || fail "direct guardian invocation returned $case_status instead of 125"
fi

# Refuse an executable whose group can replace it between validation and exec.
UNSAFE_TARGET="$TEST_ROOT/group-writable-target"
cp /usr/bin/true "$UNSAFE_TARGET"
chmod 0775 "$UNSAFE_TARGET"
if "$LEASE" "$UNSAFE_TARGET" >/dev/null 2>&1; then
  fail "a group-writable executable crossed the launch boundary"
else
  case_status="$?"
  [[ "$case_status" == "125" ]] || fail "unsafe target rejection returned $case_status instead of 125"
fi

# A pipe is private but not seekable or attestable as a one-shot regular
# record. The lease must reject it before the target can execute.
set +e
runtime_auth_frame | "$LEASE" --fulmar-runtime-auth-stdin-v1 /usr/bin/true >/dev/null 2>&1
case_status=$?
set -e
[[ "$case_status" == "125" ]] || fail "runtime-authentication FIFO rejection returned $case_status instead of 125"

# Normal app-style shutdown: signal only the exact leased Process PID, then
# prove the lease admits only an unlinked owner-only authentication descriptor,
# strips its private marker from target argv, closes it before any target child,
# gives the guardian /dev/null instead, and removes the whole process group.
NORMAL_MARKER="$TEST_ROOT/normal.pid"
EXPECTED_AUTH_HASH="$(runtime_auth_frame | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
runtime_auth_frame | /usr/bin/perl "$AUTH_RELAY" "$LEASE" --fulmar-runtime-auth-stdin-v1 /usr/bin/perl -e '
  use Digest::SHA qw(sha256_hex);
  use Fcntl qw(F_GETFD SEEK_CUR);
  $SIG{TERM} = sub { exit 0 };
  $SIG{HUP} = "IGNORE";
  my @metadata = stat(STDIN);
  exit 80 if !@metadata || (($metadata[2] & 0170000) != 0100000)
    || $metadata[3] != 0 || (($metadata[2] & 0777) != 0600)
    || !defined(sysseek(STDIN, 0, SEEK_CUR)) || sysseek(STDIN, 0, SEEK_CUR) != 0
    || @ARGV != 1;
  local $/;
  my $frame = <STDIN>;
  exit 81 if !defined($frame)
    || $frame !~ /\AFULMAR_RUNTIME_AUTH_V1:[A-Za-z0-9_-]{22,128}:[A-Za-z0-9_-]{22,128}\n\z/;
  my $digest = sha256_hex($frame);
  $frame = "\0" x length($frame);
  close(STDIN) or exit 82;
  my $child = system("/usr/bin/perl", "-e", q{my $byte = q{}; my $count = sysread(STDIN, $byte, 1); exit((defined($count) && $count > 0) ? 1 : 0)});
  exit 83 if $child != 0;
  open(my $fh, ">", $ARGV[0]) or die $!;
  print {$fh} "$$ $digest\n";
  close($fh);
  while (1) { select(undef, undef, undef, 0.05); }
' "$NORMAL_MARKER" &
NORMAL_PID="$!"
wait_for_file "$NORMAL_MARKER" || fail "normal-shutdown target did not become ready"
read -r NORMAL_REPORTED_PID NORMAL_AUTH_HASH < "$NORMAL_MARKER"
[[ "$NORMAL_REPORTED_PID" == "$NORMAL_PID" ]] || fail "normal-shutdown target changed PID across exec"
[[ "$NORMAL_AUTH_HASH" == "$EXPECTED_AUTH_HASH" ]] || fail "normal-shutdown target received a changed authentication frame"
exact_group_is_alive "$NORMAL_PID" || fail "normal-shutdown target did not own its exact process group"
TARGET_FD_ZERO="$(/usr/sbin/lsof -a -p "$NORMAL_PID" -d 0 -Fftn 2>/dev/null || true)"
[[ "$TARGET_FD_ZERO" != *$'tREG'* ]] || fail "authenticated target retained its consumed authentication descriptor"
GUARDIAN_PIDS="$(/bin/ps -axo pid=,ppid= | /usr/bin/awk -v parent="$NORMAL_PID" '$2 == parent { print $1 }')"
GUARDIAN_ROWS=("${(@f)GUARDIAN_PIDS}")
[[ "${#GUARDIAN_ROWS}" == "1" && "${GUARDIAN_ROWS[1]}" == <-> ]] || fail "authenticated target did not retain one exact guardian"
GUARDIAN_FD_ZERO="$(/usr/sbin/lsof -a -p "${GUARDIAN_ROWS[1]}" -d 0 -Fn 2>/dev/null)"
[[ "$GUARDIAN_FD_ZERO" == *$'n/dev/null'* ]] || fail "runtime guardian inherited authentication input instead of /dev/null"
/bin/kill -TERM "$NORMAL_PID"
wait "$NORMAL_PID" >/dev/null 2>&1 || true
wait_for_exact_group_exit "$NORMAL_PID" || fail "normal-shutdown process group outlived the bounded guardian"
NORMAL_PID=""

# Keep an unrelated process using the same executable alive throughout the
# parent-crash case. This proves cleanup is identity/group scoped, not a broad
# same-name kill.
/usr/bin/perl -e '
  $SIG{TERM} = "IGNORE";
  $SIG{HUP} = "IGNORE";
  while (1) { select(undef, undef, undef, 0.05); }
' &
UNRELATED_PID="$!"
exact_pid_is_alive "$UNRELATED_PID" || fail "unrelated control process did not start"

# Create a real direct host -> lease -> target chain. The target ignores both
# graceful signals, so only the guardian's bounded escalation can remove it
# after the direct host is SIGKILLed.
CRASH_MARKER="$TEST_ROOT/crash.pid"
CRASH_CHILD_RECORD="$TEST_ROOT/crash-child.pid"
env LEASE_HELPER="$LEASE" LEASE_MARKER="$CRASH_MARKER" LEASE_CHILD_RECORD="$CRASH_CHILD_RECORD" /bin/sh -p -c '
  "$LEASE_HELPER" /usr/bin/perl -e '\''
    $SIG{TERM} = "IGNORE";
    $SIG{HUP} = "IGNORE";
    open(my $fh, ">", $ARGV[0]) or die $!;
    print {$fh} "$$\n";
    close($fh);
    while (1) { select(undef, undef, undef, 0.05); }
  '\'' "$LEASE_MARKER" &
  child="$!"
  printf "%s\n" "$child" > "$LEASE_CHILD_RECORD"
  wait "$child"
' &
CRASH_HOST_PID="$!"
wait_for_file "$CRASH_MARKER" || fail "parent-crash target did not become ready"
wait_for_file "$CRASH_CHILD_RECORD" || fail "parent-crash host did not record its exact child"
CRASH_RUNTIME_PID="$(<"$CRASH_MARKER")"
[[ "$CRASH_RUNTIME_PID" == <-> && "$(<"$CRASH_CHILD_RECORD")" == "$CRASH_RUNTIME_PID" ]] || fail "parent-crash target identity changed across exec"
exact_group_is_alive "$CRASH_RUNTIME_PID" || fail "parent-crash target did not own its exact process group"

/bin/kill -KILL "$CRASH_HOST_PID"
wait "$CRASH_HOST_PID" >/dev/null 2>&1 || true
CRASH_HOST_PID=""
wait_for_exact_exit "$CRASH_RUNTIME_PID" || fail "target outlived its killed direct host"
wait_for_exact_group_exit "$CRASH_RUNTIME_PID" || fail "target process group outlived its killed direct host"
CRASH_RUNTIME_PID=""
exact_pid_is_alive "$UNRELATED_PID" || fail "guardian killed an unrelated same-executable process"

/bin/kill -KILL "$UNRELATED_PID"
wait "$UNRELATED_PID" >/dev/null 2>&1 || true
UNRELATED_PID=""

print "Runtime parent-death lease passed exact normal-exit, SIGKILL-host, bounded-lifetime, unsafe-target, direct-guardian, and unrelated-process checks."
