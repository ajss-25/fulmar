#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
DSH="$APP_DIR/Contents/Resources/Runtime/dsh/lib/bin.js"
PRELOADER="$APP_DIR/Contents/Resources/RuntimeSecurityPreload.mjs"
PATCH="$APP_DIR/Contents/Resources/LocalHarness.patch.yml"
CREDENTIAL_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-credentials-keychain/index.mjs"
FS_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-fs-confined/index.mjs"
MCP_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded/index.mjs"
CLIENT_SECURITY_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-client-security-bridge/index.mjs"
PERFORMANCE_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-performance-profile/index.mjs"
HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
SANDBOX_HELPER="$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner"
AUTH_RELAY="$PROJECT_DIR/Tests/Fixtures/RuntimeAuthenticationRelay.pl"
TEST_ROOT="$(mktemp -d /private/tmp/local-harness-provider-contract.XXXXXX)"
DSH_HOME="$TEST_ROOT/home/.dsh"
KEYCHAIN_HOME="${HOME:?The login HOME is required for the macOS Keychain credential canary}"
MODEL="simulated-tool-model"
CANARY_SUFFIX="$(uuidgen | tr -d '-')"
CREDENTIAL_REF="LOCAL_HARNESS_SIMULATED_PROVIDER_${CANARY_SUFFIX}"
CREDENTIAL_VALUE="simulated-key-${CANARY_SUFFIX}"
SERVER_PID=""
HEADLESS_PID=""
STAGE="bootstrap"
PERFORMANCE_PROFILES='{"fast":{"maxOutputTokens":4096},"balanced":{"maxOutputTokens":8192},"deep":{"maxOutputTokens":16384}}'
TOKEN="provider-contract-token-0123456789"
NONCE="provider-contract-nonce-0123456789"

runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}

cleanup() {
  local exit_code="${1:-$?}"
  if (( exit_code != 0 )); then
    print -u2 -- "Simulated-provider contract failed during stage: $STAGE"
  fi
  if [[ -n "$HEADLESS_PID" ]] && kill -0 "$HEADLESS_PID" >/dev/null 2>&1; then kill -KILL "$HEADLESS_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then kill "$SERVER_PID" >/dev/null 2>&1 || true; fi
  [[ -n "$HEADLESS_PID" ]] && wait "$HEADLESS_PID" >/dev/null 2>&1 || true
  [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" >/dev/null 2>&1 || true
  "$HELPER" unset "$CREDENTIAL_REF" >/dev/null 2>&1 || true
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

probe_extended_pattern() {
  local pattern="$1"
  shift
  set +e
  /usr/bin/grep -Eq -- "$pattern" "$@"
  local match_status=$?
  set -e
  if (( match_status == 0 )); then
    return 0
  elif (( match_status == 1 )); then
    return 1
  fi
  print -u2 "Simulated-provider evidence could not be scanned safely."
  exit 1
}

assert_extended_pattern_absent() {
  if probe_extended_pattern "$@"; then
    print -u2 "Simulated-provider evidence contained a forbidden value."
    exit 1
  fi
}

for item in "$NODE" "$DSH" "$PRELOADER" "$PATCH" "$CREDENTIAL_PLUGIN" "$FS_PLUGIN" "$MCP_PLUGIN" "$CLIENT_SECURITY_PLUGIN" "$PERFORMANCE_PLUGIN" "$HELPER" "$SANDBOX_HELPER" "$AUTH_RELAY"; do
  [[ -e "$item" ]] || { print -u2 "Missing simulated-provider contract component: $item"; exit 1; }
done

mkdir -p "$DSH_HOME/Agents" "$DSH_HOME/skills/Active" "$TEST_ROOT/workspace" "$TEST_ROOT/sandbox-temp"
chmod 700 "$TEST_ROOT" "$TEST_ROOT/home" "$DSH_HOME" "$DSH_HOME/Agents" "$DSH_HOME/skills" "$DSH_HOME/skills/Active" "$TEST_ROOT/workspace" "$TEST_ROOT/sandbox-temp"
print -r -- '{"mode":"readWrite","reason":"protectedCheckpoint","schemaVersion":1}' > "$DSH_HOME/.fulmar-workspace-mutation-policy.json"
chmod 600 "$DSH_HOME/.fulmar-workspace-mutation-policy.json"
APPLICATION_SUPPORT="$TEST_ROOT/application-support/Local Harness"
THERMAL_DIRECTORY="$APPLICATION_SUPPORT/PerformanceTelemetry"
THERMAL_POLICY="$THERMAL_DIRECTORY/thermal-workload-policy.json"
mkdir -p "$THERMAL_DIRECTORY"
chmod 700 "$TEST_ROOT/application-support" "$APPLICATION_SUPPORT" "$THERMAL_DIRECTORY"
print -r -- '{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"eco","schemaVersion":1}' > "$THERMAL_POLICY"
chmod 600 "$THERMAL_POLICY"
print -r -- '{"schemaVersion":1,"plans":[]}' > "$TEST_ROOT/mcp-catalog.json"
chmod 600 "$TEST_ROOT/mcp-catalog.json"
STAGE="credential-round-trip"
print -rn -- "$CREDENTIAL_VALUE" | "$HELPER" set "$CREDENTIAL_REF"
[[ "$("$HELPER" get "$CREDENTIAL_REF")" == "$CREDENTIAL_VALUE" ]]

STAGE="provider-startup"
"$NODE" "$PROJECT_DIR/scripts/simulated-openai-provider.mjs" \
  "$TEST_ROOT/provider-ready.json" "$TEST_ROOT/provider-log.jsonl" "$CREDENTIAL_VALUE" "$MODEL" \
  >"$TEST_ROOT/provider-output.log" 2>"$TEST_ROOT/provider-error.log" &
SERVER_PID="$!"
for _ in {1..200}; do
  [[ -s "$TEST_ROOT/provider-ready.json" ]] && break
  kill -0 "$SERVER_PID" >/dev/null 2>&1 || { print -u2 "Simulated provider exited before readiness."; exit 1; }
  sleep 0.05
done
[[ -s "$TEST_ROOT/provider-ready.json" ]]
PORT="$("$NODE" -e 'const p=require(process.argv[1]); process.stdout.write(String(p.port))' "$TEST_ROOT/provider-ready.json")"
ORIGIN="http://127.0.0.1:$PORT"
PROVIDER_ORIGINS="[{\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":$PORT,\"boundary\":\"onDevice\"}]"

"$NODE" -e '
  const fs=require("node:fs");
  const [path,port,model,credential]=process.argv.slice(1);
  const settings={
    "agent-default-model": { provider: "simulated-openai", model },
    "llm-pi-ai": { providers: {
      "simulated-openai": {
        apiKeyEnv: credential,
        displayName: "Simulated OpenAI Contract",
        api: "openai-completions",
        baseURL: `http://127.0.0.1:${port}/v1`,
        retryPolicy: { mode: "normal", maxRetries: 0 },
        models: [{ id: model, name: "Simulated Tool Model", contextWindow: 32768, maxTokens: 4096, input: ["text"] }]
      }
    }}
  };
  fs.writeFileSync(path,`${JSON.stringify(settings,null,2)}\n`,{mode:0o600,flag:"wx"});
' "$DSH_HOME/settings.yaml" "$PORT" "$MODEL" "$CREDENTIAL_REF"

contract_environment=(
  # Security.framework resolves the login Keychain through the login HOME.
  # DSH state remains clean and deterministic through the isolated DSH_HOME.
  HOME="$KEYCHAIN_HOME"
  USER="$(id -un)"
  LOGNAME="$(id -un)"
  PATH="/usr/bin:/bin"
  TMPDIR="$TEST_ROOT/sandbox-temp"
  DSH_HOME="$DSH_HOME"
  DSH_AGENTS_HOME="$DSH_HOME/Agents"
  DSH_TELEMETRY_MODE="DISABLED"
  NARB_DISABLE_NATIVE_CACHE="1"
  LOCAL_HARNESS_CREDENTIAL_PLUGIN="$CREDENTIAL_PLUGIN"
  LOCAL_HARNESS_CREDENTIAL_HELPER="$HELPER"
  LOCAL_HARNESS_CREDENTIAL_HOME="$KEYCHAIN_HOME"
  LOCAL_HARNESS_MCP_PLUGIN="$MCP_PLUGIN"
  LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN="$CLIENT_SECURITY_PLUGIN"
  LOCAL_HARNESS_PERFORMANCE_PLUGIN="$PERFORMANCE_PLUGIN"
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER"
  LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]"
  LOCAL_HARNESS_READONLY_ROOTS="[\"$DSH_HOME/skills/Active\"]"
  LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT/sandbox-temp"
  LOCAL_HARNESS_FS_PLUGIN="$FS_PLUGIN"
  LOCAL_HARNESS_MCP_CATALOG="$TEST_ROOT/mcp-catalog.json"
  LOCAL_HARNESS_PERFORMANCE_PROFILE="balanced"
  LOCAL_HARNESS_PERFORMANCE_PROFILES="$PERFORMANCE_PROFILES"
  LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT="$APPLICATION_SUPPORT"
  LOCAL_HARNESS_THERMAL_POLICY_FILE="$THERMAL_POLICY"
  LOCAL_HARNESS_ACTIVE_PROVIDER="simulated-openai"
  LOCAL_HARNESS_STRICT_LOCAL="0"
  LOCAL_HARNESS_PROVIDER_ORIGINS="$PROVIDER_ORIGINS"
  LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh"
)

# Exercise model-list transport through the same preload and prove that an
# adjacent IP or wrong port is denied before a socket is opened.
STAGE="catalog-transport"
runtime_auth_frame | env -i "${contract_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e '
  const [origin,key,model]=process.argv.slice(1);
  const response=await fetch(`${origin}/v1/models`,{headers:{authorization:`Bearer ${key}`}});
  const body=await response.json();
  if(response.status!==200 || body.data?.length!==1 || body.data[0]?.id!==model) process.exit(1);
' "$ORIGIN" "$CREDENTIAL_VALUE" "$MODEL"
STAGE="exact-origin-denial"
runtime_auth_frame | env -i "${contract_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e '
  const port=process.argv[1];
  for(const url of [`http://127.0.0.2:${port}/v1/models`,`http://127.0.0.1:1/v1/models`]) {
    let denied=false;
    try { await fetch(url); } catch(error) { denied=error?.code==="EACCES"; }
    if(!denied) process.exit(1);
  }
' "$PORT"

run_headless() {
  local label="$1"
  local task="$2"
  local expected="$3"
  STAGE="headless-$label"
  (
    cd "$TEST_ROOT/workspace"
    runtime_auth_frame | env -i "${contract_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" "$task"
  ) >"$TEST_ROOT/$label.out" 2>"$TEST_ROOT/$label.err"
  /usr/bin/grep -Eq -- "$expected" "$TEST_ROOT/$label.out"
  assert_extended_pattern_absent "$CREDENTIAL_VALUE|MISSING_CREDENTIAL|no credential for provider route" "$TEST_ROOT/$label.out" "$TEST_ROOT/$label.err"
}

run_headless simple "Reply with exactly SIMULATED_SIMPLE_OK. Contract marker: CONTRACT_SIMPLE" SIMULATED_SIMPLE_OK
run_headless fresh-a "Reply with exactly SIMULATED_FRESH_A_OK. CONTRACT_FRESH_A PRIVATE_OLD_CONTEXT" SIMULATED_FRESH_A_OK
run_headless fresh-b "This must be a fresh session with no earlier marker. Reply exactly SIMULATED_FRESH_OK. CONTRACT_FRESH_B" SIMULATED_FRESH_OK
run_headless tool "Use the Bash tool once to create simulated-provider-tool.txt as instructed by the model, then reply exactly SIMULATED_TOOL_OK. CONTRACT_TOOL" SIMULATED_TOOL_OK
STAGE="tool-artifact"
[[ "$(tr -d '\r\n' < "$TEST_ROOT/workspace/simulated-provider-tool.txt")" == "SIMULATED_TOOL_FILE_OK" ]]

STAGE="bounded-provider-error"
if (
  cd "$TEST_ROOT/workspace"
  runtime_auth_frame | env -i "${contract_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" \
    "Trigger the bounded provider failure. CONTRACT_ERROR"
) >"$TEST_ROOT/error.out" 2>"$TEST_ROOT/error.err"; then
  print -u2 "Simulated provider error unexpectedly succeeded."
  exit 1
fi
/usr/bin/grep -Eiq -- 'rate.limit|429|provider|failed|error' "$TEST_ROOT/error.out" "$TEST_ROOT/error.err"
assert_extended_pattern_absent "$CREDENTIAL_VALUE" "$TEST_ROOT/error.out" "$TEST_ROOT/error.err"

STAGE="transport-cancellation"
(
  cd "$TEST_ROOT/workspace"
  runtime_auth_frame | env -i "${contract_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" \
    "Begin a long response and wait. CONTRACT_CANCEL"
) >"$TEST_ROOT/cancel.out" 2>"$TEST_ROOT/cancel.err" &
HEADLESS_PID="$!"
cancel_request_seen=0
for _ in {1..400}; do
  if probe_extended_pattern 'CONTRACT_CANCEL' "$TEST_ROOT/provider-log.jsonl"; then
    cancel_request_seen=1
    break
  fi
  kill -0 "$HEADLESS_PID" >/dev/null 2>&1 || { print -u2 "Cancellation canary exited before opening its stream."; exit 1; }
  sleep 0.05
done
(( cancel_request_seen == 1 )) || { print -u2 "Cancellation canary never published its request marker."; exit 1; }
kill -TERM "$HEADLESS_PID"
for _ in {1..100}; do
  kill -0 "$HEADLESS_PID" >/dev/null 2>&1 || break
  sleep 0.05
done
if kill -0 "$HEADLESS_PID" >/dev/null 2>&1; then
  print -u2 "Cancellation did not stop the headless route within five seconds."
  exit 1
fi
wait "$HEADLESS_PID" >/dev/null 2>&1 || true
HEADLESS_PID=""
cancel_ack_seen=0
for _ in {1..100}; do
  if probe_extended_pattern '"kind":"cancelled"' "$TEST_ROOT/provider-log.jsonl"; then
    cancel_ack_seen=1
    break
  fi
  sleep 0.05
done
(( cancel_ack_seen == 1 )) || { print -u2 "Cancellation acknowledgement was not recorded."; exit 1; }

STAGE="provider-log-audit"
"$NODE" "$PROJECT_DIR/scripts/verify-simulated-provider-log.mjs" "$TEST_ROOT/provider-log.jsonl" "$MODEL"

STAGE="complete"
echo "Simulated OpenAI-compatible contract passed: exact model/default route, authenticated catalog and streaming, tool execution, bounded error, transport cancellation, fresh headless sessions, and exact-origin egress denial. Native WebView fresh-session UI remains covered separately by bridge/unit and manual UI qualification."
