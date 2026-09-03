#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
PRELOADER="$APP_DIR/Contents/Resources/RuntimeSecurityPreload.mjs"
RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh"
SANDBOX_HELPER="$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner"
MCP_PACKAGE="$RUNTIME_ROOT/node_modules/@local-harness/dsh-mcp-guarded"
AUTH_RELAY="$PROJECT_DIR/Tests/Fixtures/RuntimeAuthenticationRelay.pl"
TEST_ROOT="$(mktemp -d /private/tmp/localharness-mcp-runtime.XXXXXX)"
TOKEN="mcp-runtime-test-token-0123456789"
NONCE="mcp-runtime-test-nonce-0123456789"

runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}

cleanup() {
  local exit_code="${1:-$?}"
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

for item in "$NODE" "$PRELOADER" "$SANDBOX_HELPER" \
  "$MCP_PACKAGE/index.mjs" "$MCP_PACKAGE/catalog-core.mjs" "$MCP_PACKAGE/guarded-runtime.mjs" \
  "$MCP_PACKAGE/wire-guard.mjs" "$MCP_PACKAGE/stdio-guard-runner.mjs" "$MCP_PACKAGE/package.json" \
  "$AUTH_RELAY"; do
  [[ -f "$item" ]] || { print -u2 "Missing packaged MCP security component: $item"; exit 1; }
done

mkdir -p "$TEST_ROOT/workspace" "$TEST_ROOT/sandbox-temp" "$TEST_ROOT/home/.dsh/profiles"
chmod 700 "$TEST_ROOT" "$TEST_ROOT/workspace" "$TEST_ROOT/sandbox-temp" "$TEST_ROOT/home" "$TEST_ROOT/home/.dsh" "$TEST_ROOT/home/.dsh/profiles"
print -r -- "MCP_OUTSIDE_READ_MUST_FAIL" > "$TEST_ROOT/outside-sentinel.txt"
chmod 600 "$TEST_ROOT/outside-sentinel.txt"

(
  cd "$TEST_ROOT/workspace"
  # Simulate a connected/cloud model host. The MCP marker path must still
  # force the subprocess itself into Strict Local mode independently.
  runtime_auth_frame | env -i \
    HOME="$TEST_ROOT/home" \
    USER="$(id -un)" \
    LOGNAME="$(id -un)" \
    PATH="/usr/bin:/bin" \
    LANG="en_US.UTF-8" \
    TMPDIR="$TEST_ROOT/sandbox-temp" \
    DSH_HOME="$TEST_ROOT/home/.dsh" \
    LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" \
    LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" \
    LOCAL_HARNESS_READONLY_ROOTS='[]' \
    LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT/sandbox-temp" \
    LOCAL_HARNESS_STRICT_LOCAL=0 \
    LOCAL_HARNESS_PROVIDER_ORIGINS='[]' \
    LOCAL_HARNESS_RUNTIME_ROOT="$RUNTIME_ROOT" \
    /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$PROJECT_DIR/scripts/verify-mcp-guard-runtime.mjs" "$APP_DIR" "$TEST_ROOT"
)

[[ ! -e "$TEST_ROOT/workspace/MCP_WRITE_MUST_FAIL" ]]
print "Packaged MCP guard verification passed: exact signed runner, environment scrubbing, tools-only stdio, and read-only sandbox."
