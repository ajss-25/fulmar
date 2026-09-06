#!/bin/zsh -f
set -euo pipefail

# This gate verifies the current candidate against a cloned existing runtime
# state. It is intentionally not called an upgrade test: no second DSH version
# is installed or migrated here.
PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
MCP_GUARD="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded"
CLIENT_SECURITY_BRIDGE="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-client-security-bridge"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
FIXTURE_ROOT="$(mktemp -d /private/tmp/fulmar-cloned-state-fixture.XXXXXX)"
FIXTURE_DSH_HOME="$FIXTURE_ROOT/source/.dsh"

cleanup() {
  local exit_code="${1:-$?}"
  case "$FIXTURE_ROOT" in
    /private/tmp/fulmar-cloned-state-fixture.*) rm -rf -- "$FIXTURE_ROOT" ;;
    *) print -u2 "Refusing to remove an invalid cloned-state fixture root." ;;
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

mkdir -p "$FIXTURE_DSH_HOME/.fulmar-ci-fixture/nested"
chmod 700 "$FIXTURE_ROOT" "$FIXTURE_ROOT/source" "$FIXTURE_DSH_HOME" \
  "$FIXTURE_DSH_HOME/.fulmar-ci-fixture" "$FIXTURE_DSH_HOME/.fulmar-ci-fixture/nested"
print -r -- '{"provider":"fixture-local","schemaVersion":1}' \
  > "$FIXTURE_DSH_HOME/.fulmar-ci-clone-fixture.json"
print -r -- 'non-secret prior state fixture' \
  > "$FIXTURE_DSH_HOME/.fulmar-ci-fixture/nested/prior-state.txt"
chmod 600 "$FIXTURE_DSH_HOME/.fulmar-ci-clone-fixture.json" \
  "$FIXTURE_DSH_HOME/.fulmar-ci-fixture/nested/prior-state.txt"

[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$MCP_GUARD/package.json" 2>/dev/null)" == "@local-harness/dsh-mcp-guarded@1.0.0" ]]
[[ "$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(`${p.name}@${p.version}`)' "$CLIENT_SECURITY_BRIDGE/package.json" 2>/dev/null)" == "@local-harness/dsh-client-security-bridge@1.2.1" ]]
for source in index.mjs catalog-core.mjs guarded-runtime.mjs wire-guard.mjs stdio-guard-runner.mjs; do
  "$NODE" --check "$MCP_GUARD/$source" >/dev/null
done
"$NODE" --check "$CLIENT_SECURITY_BRIDGE/index.mjs" >/dev/null
"$NODE" --check "$CLIENT_SECURITY_BRIDGE/client.js" >/dev/null
/bin/zsh -f "$PROJECT_DIR/scripts/verify-mcp-runtime-security.sh" "$APP_DIR"
LOCAL_HARNESS_CANARY_STATE=clone \
LOCAL_HARNESS_CLONED_DSH_SOURCE="$FIXTURE_DSH_HOME" \
LOCAL_HARNESS_REQUIRE_NONEMPTY_CLONE=1 \
  /bin/zsh -f "$PROJECT_DIR/scripts/verify-runtime-security.sh" "$APP_DIR"

echo "Cloned-state security verification passed with a deterministic non-secret prior-DSH-state fixture; this is not a two-version DSH upgrade test."
