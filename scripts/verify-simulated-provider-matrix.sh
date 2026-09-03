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
PRESET_VERIFIER="$PROJECT_DIR/scripts/verify-sanitized-agent-presets.mjs"
TEST_ROOT="$(mktemp -d /private/tmp/local-harness-provider-matrix.XXXXXX)"
DSH_HOME="$TEST_ROOT/home/.dsh"
KEYCHAIN_HOME="${HOME:?The login HOME is required for the macOS Keychain credential canary}"
CANARY_SUFFIX="$(uuidgen | tr -d '-')"
SERVER_PID=""
HEADLESS_PID=""
PERFORMANCE_PROFILES='{"fast":{"maxOutputTokens":4096},"balanced":{"maxOutputTokens":8192},"deep":{"maxOutputTokens":16384}}'
TOKEN="provider-matrix-token-0123456789"
NONCE="provider-matrix-nonce-0123456789"

runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}

typeset -A CREDENTIAL_REFS CREDENTIAL_VALUES ROUTE_PROVIDERS ROUTE_MODELS ROUTE_TOKENS
CREDENTIAL_REFS=(
  deepseek "LOCAL_HARNESS_MATRIX_DEEPSEEK_${CANARY_SUFFIX}"
  responses "LOCAL_HARNESS_MATRIX_RESPONSES_${CANARY_SUFFIX}"
  anthropic "LOCAL_HARNESS_MATRIX_ANTHROPIC_${CANARY_SUFFIX}"
  custom "LOCAL_HARNESS_MATRIX_CUSTOM_${CANARY_SUFFIX}"
)
CREDENTIAL_VALUES=(
  deepseek "matrix-deepseek-secret-${CANARY_SUFFIX}"
  responses "matrix-responses-secret-${CANARY_SUFFIX}"
  anthropic "matrix-anthropic-secret-${CANARY_SUFFIX}"
  custom "matrix-custom-secret-${CANARY_SUFFIX}"
)
ROUTE_PROVIDERS=(
  deepseek deepseek-official
  responses matrix-responses
  anthropic matrix-anthropic
  custom matrix-custom
)
ROUTE_MODELS=(
  deepseek matrix-deepseek-model
  responses matrix-responses-model
  anthropic matrix-anthropic-model
  custom matrix-custom-model
)
ROUTE_TOKENS=(
  deepseek DEEPSEEK
  responses RESPONSES
  anthropic ANTHROPIC
  custom CUSTOM
)

cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$HEADLESS_PID" ]] && kill -0 "$HEADLESS_PID" >/dev/null 2>&1; then
    kill -KILL "$HEADLESS_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  [[ -n "$HEADLESS_PID" ]] && wait "$HEADLESS_PID" >/dev/null 2>&1 || true
  [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" >/dev/null 2>&1 || true
  for route in deepseek responses anthropic custom; do
    "$HELPER" unset "${CREDENTIAL_REFS[$route]}" >/dev/null 2>&1 || true
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

for item in "$NODE" "$DSH" "$PRELOADER" "$PATCH" "$CREDENTIAL_PLUGIN" "$FS_PLUGIN" "$MCP_PLUGIN" "$CLIENT_SECURITY_PLUGIN" "$PERFORMANCE_PLUGIN" "$HELPER" "$SANDBOX_HELPER" "$PRESET_VERIFIER" "$AUTH_RELAY"; do
  [[ -e "$item" ]] || { print -u2 "Missing provider-matrix component: $item"; exit 1; }
done
"$NODE" "$PRESET_VERIFIER" "$APP_DIR/Contents/Resources/Runtime/dsh" >/dev/null

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

for route in deepseek responses anthropic custom; do
  print -rn -- "${CREDENTIAL_VALUES[$route]}" | "$HELPER" set "${CREDENTIAL_REFS[$route]}"
  [[ "$("$HELPER" get "${CREDENTIAL_REFS[$route]}")" == "${CREDENTIAL_VALUES[$route]}" ]]
done

env -i \
  HOME="$TEST_ROOT/home" \
  PATH="/usr/bin:/bin" \
  MATRIX_DEEPSEEK_KEY="${CREDENTIAL_VALUES[deepseek]}" \
  MATRIX_RESPONSES_KEY="${CREDENTIAL_VALUES[responses]}" \
  MATRIX_ANTHROPIC_KEY="${CREDENTIAL_VALUES[anthropic]}" \
  MATRIX_CUSTOM_KEY="${CREDENTIAL_VALUES[custom]}" \
  MATRIX_HARNESS_MODE="1" \
  "$NODE" "$PROJECT_DIR/scripts/simulated-provider-matrix.mjs" \
    "$TEST_ROOT/provider-ready.json" "$TEST_ROOT/provider-log.jsonl" \
    >"$TEST_ROOT/provider-output.log" 2>"$TEST_ROOT/provider-error.log" &
SERVER_PID="$!"
for _ in {1..200}; do
  [[ -s "$TEST_ROOT/provider-ready.json" ]] && break
  kill -0 "$SERVER_PID" >/dev/null 2>&1 || { print -u2 "Provider-matrix fixture exited before readiness."; exit 1; }
  sleep 0.05
done
[[ -s "$TEST_ROOT/provider-ready.json" ]]
PORT="$("$NODE" -e 'const p=require(process.argv[1]);process.stdout.write(String(p.port))' "$TEST_ROOT/provider-ready.json")"
ORIGIN="http://127.0.0.1:$PORT"
PROVIDER_ORIGINS="[{\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":$PORT,\"boundary\":\"onDevice\"}]"

"$NODE" -e '
  const fs=require("node:fs");
  const [path,origin,deepseekRef,responsesRef,anthropicRef,customRef]=process.argv.slice(1);
  const retryPolicy={
    mode:"normal",
    maxRetries:2,
    retryableCodes:["EMPTY_RESPONSE","RATE_LIMIT","SERVER","TIMEOUT","TRANSPORT"],
    backoff:{initialDelayMs:1,maxDelayMs:2,jitterRatio:0}
  };
  const model=(id,name)=>({id,name,contextWindow:32768,maxTokens:64,input:["text"]});
  const settings={
    "agent-default-model":{provider:"deepseek-official",model:"matrix-deepseek-model"},
    "llm-deepseek":{
      apiKeyEnv:deepseekRef,
      baseURL:`${origin}/deepseek/v1`,
      thinking:"disabled",
      reasoningEffort:"off",
      maxTokens:64,
      defaultContextWindow:32768,
      models:[{
        id:"matrix-deepseek-model",
        name:"Matrix DeepSeek",
        contextWindow:32768,
        maxTokens:64,
        inputModalities:["text"]
      }],
      streamIdleTimeoutMs:5000,
      retryPolicy
    },
    "llm-pi-ai":{providers:{
      "matrix-responses":{
        apiKeyEnv:responsesRef,
        displayName:"Matrix OpenAI Responses",
        api:"openai-responses",
        baseURL:`${origin}/responses/v1`,
        models:[model("matrix-responses-model","Matrix OpenAI Responses")],
        streamIdleTimeoutMs:5000,
        retryPolicy
      },
      "matrix-anthropic":{
        apiKeyEnv:anthropicRef,
        displayName:"Matrix Anthropic Messages",
        api:"anthropic-messages",
        baseURL:`${origin}/anthropic`,
        models:[model("matrix-anthropic-model","Matrix Anthropic Messages")],
        streamIdleTimeoutMs:5000,
        retryPolicy
      },
      "matrix-custom":{
        apiKeyEnv:customRef,
        displayName:"Matrix Custom OpenAI-Compatible",
        api:"openai-completions",
        baseURL:`${origin}/custom/v1`,
        compat:{
          supportsStore:false,
          supportsDeveloperRole:false,
          supportsReasoningEffort:false,
          supportsUsageInStreaming:true,
          maxTokensField:"max_tokens",
          supportsStrictMode:false
        },
        models:[model("matrix-custom-model","Matrix Custom OpenAI-Compatible")],
        streamIdleTimeoutMs:5000,
        retryPolicy
      }
    }}
  };
  fs.writeFileSync(path,`${JSON.stringify(settings,null,2)}\n`,{mode:0o600,flag:"wx"});
' "$DSH_HOME/settings.yaml" "$ORIGIN" "${CREDENTIAL_REFS[deepseek]}" "${CREDENTIAL_REFS[responses]}" "${CREDENTIAL_REFS[anthropic]}" "${CREDENTIAL_REFS[custom]}"

matrix_environment=(
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
  LOCAL_HARNESS_STRICT_LOCAL="0"
  LOCAL_HARNESS_PROVIDER_ORIGINS="$PROVIDER_ORIGINS"
  LOCAL_HARNESS_MAX_PROVIDER_RESPONSE_BYTES="65536"
  LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh"
)

select_route() {
  local route="$1"
  "$NODE" -e '
    const fs=require("node:fs");
    const [path,provider,model]=process.argv.slice(1);
    const settings=JSON.parse(fs.readFileSync(path,"utf8"));
    settings["agent-default-model"]={provider,model};
    fs.writeFileSync(path,`${JSON.stringify(settings,null,2)}\n`,{mode:0o600});
  ' "$DSH_HOME/settings.yaml" "${ROUTE_PROVIDERS[$route]}" "${ROUTE_MODELS[$route]}"
}

print_safe_diagnostic() {
  local label="$1"
  "$NODE" -e '
    const fs=require("node:fs");
    const files=process.argv.slice(1);
    const parts=[];
    for(const path of files){
      if(!fs.existsSync(path)) continue;
      const text=fs.readFileSync(path,"utf8")
        .replace(/matrix-(?:deepseek|responses|anthropic|custom)-secret-[0-9A-Fa-f-]+/g,"<redacted-matrix-secret>");
      if(text.length>0) parts.push(text.slice(-12000));
    }
    if(parts.length>0) process.stderr.write(`${parts.join("\n")}\n`);
  ' "$TEST_ROOT/$label.out" "$TEST_ROOT/$label.err"
}

invoke_headless() {
  local label="$1"
  local task="$2"
  (
    cd "$TEST_ROOT/workspace"
    runtime_auth_frame | env -i "${matrix_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" "$task"
  ) >"$TEST_ROOT/$label.out" 2>"$TEST_ROOT/$label.err" &
  HEADLESS_PID="$!"
  for _ in {1..1200}; do
    kill -0 "$HEADLESS_PID" >/dev/null 2>&1 || break
    sleep 0.05
  done
  if kill -0 "$HEADLESS_PID" >/dev/null 2>&1; then
    kill -TERM "$HEADLESS_PID" >/dev/null 2>&1 || true
    sleep 0.2
    kill -KILL "$HEADLESS_PID" >/dev/null 2>&1 || true
    wait "$HEADLESS_PID" >/dev/null 2>&1 || true
    HEADLESS_PID=""
    print -u2 "Provider-matrix task timed out: $label"
    return 124
  fi
  local task_exit
  if wait "$HEADLESS_PID"; then task_exit=0; else task_exit=$?; fi
  HEADLESS_PID=""
  return "$task_exit"
}

run_success() {
  local route="$1"
  local label="$2"
  local task="$3"
  local expected="$4"
  select_route "$route"
  if ! invoke_headless "$label" "$task"; then
    print -u2 "Provider-matrix success canary failed: $route/$label"
    print_safe_diagnostic "$label"
    exit 1
  fi
  set +e
  /usr/bin/grep -Eq -- "$expected" "$TEST_ROOT/$label.out"
  expected_status=$?
  set -e
  if (( expected_status != 0 )); then
    print -u2 "Provider-matrix success token was missing: $route/$label"
    (( expected_status == 1 )) || print -u2 "Provider-matrix success evidence could not be scanned safely."
    print_safe_diagnostic "$label"
    exit 1
  fi
}

run_failure() {
  local route="$1"
  local label="$2"
  local marker="$3"
  local error_pattern="$4"
  select_route "$route"
  if invoke_headless "$label" "Fail safely for protocol-matrix marker $marker"; then
    print -u2 "Provider-matrix hostile response unexpectedly succeeded: $route/$marker"
    print_safe_diagnostic "$label"
    exit 1
  fi
  set +e
  /usr/bin/grep -Eiq -- "$error_pattern" "$TEST_ROOT/$label.out" "$TEST_ROOT/$label.err"
  error_status=$?
  set -e
  if (( error_status != 0 )); then
    print -u2 "Provider-matrix failure was not classified safely: $route/$marker"
    (( error_status == 1 )) || print -u2 "Provider-matrix failure evidence could not be scanned safely."
    print_safe_diagnostic "$label"
    exit 1
  fi
}

request_count() {
  local route="$1"
  local marker="$2"
  "$NODE" -e '
    const fs=require("node:fs");
    const [path,route,marker]=process.argv.slice(1);
    const rows=fs.readFileSync(path,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
    process.stdout.write(String(rows.filter((row)=>row.kind==="request"&&row.route===route&&row.marker===marker&&row.phase==="agent").length));
  ' "$TEST_ROOT/provider-log.jsonl" "$route" "$marker"
}

assert_request_count() {
  local route="$1"
  local marker="$2"
  local expected="$3"
  local actual="$(request_count "$route" "$marker")"
  if [[ "$actual" != "$expected" ]]; then
    print -u2 "Provider-matrix retry count mismatch for $route/$marker: expected $expected, received $actual"
    "$NODE" -e '
      const fs=require("node:fs");
      const [path,route,marker]=process.argv.slice(1);
      const all=fs.readFileSync(path,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
      const rows=all
        .filter((row)=>row.route===route&&row.marker===marker)
        .map(({kind,route,marker,phase,attempt,authorized,shape})=>({kind,route,marker,phase,attempt,authorized,shape}));
      const summary=all.filter((row)=>row.kind==="request").map((row)=>({route:row.route,marker:row.marker,attempt:row.attempt,tools:row.shape?.tools?.length??-1,toolResult:row.shape?.hasToolResult??false}));
      process.stderr.write(`${JSON.stringify(rows)}\n${JSON.stringify(summary)}\n`);
    ' "$TEST_ROOT/provider-log.jsonl" "$route" "$marker"
    exit 1
  fi
}

for route in deepseek responses anthropic custom; do
  token="${ROUTE_TOKENS[$route]}"
  run_success "$route" "$route-simple" \
    "Reply exactly ${token}_SIMPLE_OK. Protocol-matrix marker MATRIX_SIMPLE" \
    "${token}_SIMPLE_OK"
  run_success "$route" "$route-tool" \
    "Use the Bash tool exactly once as instructed by the model, then reply exactly ${token}_TOOL_OK. Protocol-matrix marker MATRIX_TOOL" \
    "${token}_TOOL_OK"
  [[ "$(tr -d '\r\n' < "$TEST_ROOT/workspace/matrix-$route-tool.txt")" == "${token}_TOOL_FILE_OK" ]]
  assert_request_count "$route" MATRIX_TOOL 2
done

# Exercise the bundled DeepSeek adapter against continuation frames that omit,
# null, empty, repeat, or conflict with the valid identity while fragmenting
# the arguments.
# Every case must execute one tool, make one correlated follow-up request, and
# terminate; an empty/corrupted identity or a tool loop violates that ceiling.
for identity_mode in OMITTED NULL EMPTY REPEATED CONFLICTING; do
  identity_file="${(L)identity_mode}"
  marker="MATRIX_TOOL_IDENTITY_${identity_mode}"
  run_success deepseek "deepseek-tool-identity-$identity_file" \
    "Use the Bash tool exactly once as instructed by the model, then reply exactly DEEPSEEK_TOOL_OK. Protocol-matrix marker $marker" \
    "DEEPSEEK_TOOL_OK"
  [[ "$(tr -d '\r\n' < "$TEST_ROOT/workspace/matrix-deepseek-tool-identity-$identity_file.txt")" == "DEEPSEEK_TOOL_FILE_OK" ]]
  assert_request_count deepseek "$marker" 2
done

# Authentication and DeepSeek billing errors are terminal; rate limits and server failures receive
# exactly two retries from each adapter's configured provider policy. Recovery
# after the second 429 must also succeed through every claimed protocol SDK.
run_failure deepseek deepseek-error-402 MATRIX_ERROR_402 'insufficient[ _-]*balance|balance.*(credit|billing)|(credit|billing).*balance'
assert_request_count deepseek MATRIX_ERROR_402 1
for route in deepseek responses anthropic custom; do
  token="${ROUTE_TOKENS[$route]}"
  run_failure "$route" "$route-error-401" MATRIX_ERROR_401 'auth|credential|401|invalid'
  assert_request_count "$route" MATRIX_ERROR_401 1
  run_failure "$route" "$route-error-429" MATRIX_ERROR_429 'rate.limit|429|retry|provider|failed|error'
  assert_request_count "$route" MATRIX_ERROR_429 3
  run_failure "$route" "$route-error-500" MATRIX_ERROR_500 '503|server|retry|provider|failed|error'
  assert_request_count "$route" MATRIX_ERROR_500 3
  run_success "$route" "$route-retry-success" \
    "Recover only after the provider retry succeeds. Protocol-matrix marker MATRIX_RETRY_SUCCESS_429" \
    "${token}_SIMPLE_OK"
  assert_request_count "$route" MATRIX_RETRY_SUCCESS_429 3
done

# Each SDK/parser must reject invalid event framing without accepting an empty
# or fabricated assistant response. Parser failures are not in the configured
# transient-error taxonomy, so the agent phase must remain terminal.
for route in deepseek responses anthropic custom; do
  run_failure "$route" "$route-malformed" MATRIX_MALFORMED 'empty|malformed|parse|stream|provider|failed|error'
  assert_request_count "$route" MATRIX_MALFORMED 1
done

# The preload must reject a declared oversized response before buffering or
# parsing it. The test override lowers the production 16 MiB ceiling to 64 KiB.
# The preload's source probe above observes EMSGSIZE exactly. pi-ai intentionally
# normalizes that Fetch failure at the model boundary to its TRANSPORT taxonomy;
# the fixture request/count pairing keeps this from accepting an unrelated path.
run_failure custom custom-oversized MATRIX_OVERSIZED 'EMSGSIZE|byte.limit|too.large|oversiz|response.size|TRANSPORT|connection.error'
assert_request_count custom MATRIX_OVERSIZED 3
run_failure custom custom-oversized-chunked MATRIX_OVERSIZED_CHUNKED 'EMSGSIZE|byte.limit|too.large|oversiz|response.size|TRANSPORT|connection.error'
# Once streamed bytes have been exposed to the parser, the agent must not
# replay the request: a retry could duplicate already-observed output/tool data.
assert_request_count custom MATRIX_OVERSIZED_CHUNKED 1

for route in deepseek responses anthropic custom; do
  select_route "$route"
  label="$route-cancel"
  (
    cd "$TEST_ROOT/workspace"
    runtime_auth_frame | env -i "${matrix_environment[@]}" /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" \
      "Begin the cancellable protocol-matrix stream. MATRIX_CANCEL"
  ) >"$TEST_ROOT/$label.out" 2>"$TEST_ROOT/$label.err" &
  HEADLESS_PID="$!"
  marker_seen=0
  for _ in {1..400}; do
    set +e
    "$NODE" -e '
      const fs=require("node:fs");
      const [path,route]=process.argv.slice(1);
      if(!fs.existsSync(path)) process.exit(1);
      const text=fs.readFileSync(path,"utf8");
      const complete=text.endsWith("\n") ? text : text.slice(0,Math.max(0,text.lastIndexOf("\n")+1));
      let rows;
      try { rows=complete.split("\n").filter(Boolean).map(JSON.parse); }
      catch { process.exit(2); }
      process.exit(rows.some((row)=>row.kind==="request"&&row.route===route&&row.marker==="MATRIX_CANCEL"&&row.phase==="agent")?0:1);
    ' "$TEST_ROOT/provider-log.jsonl" "$route"
    marker_status=$?
    set -e
    if (( marker_status == 0 )); then
      marker_seen=1
      break
    fi
    if (( marker_status != 1 )); then
      print -u2 "Provider-matrix cancellation evidence became malformed: $route"
      exit 1
    fi
    kill -0 "$HEADLESS_PID" >/dev/null 2>&1 || { print -u2 "Cancellation canary exited before opening $route stream."; exit 1; }
    sleep 0.05
  done
  (( marker_seen == 1 )) || {
    print -u2 "Cancellation canary never published its exact request marker: $route"
    exit 1
  }
  kill -TERM "$HEADLESS_PID"
  for _ in {1..100}; do
    kill -0 "$HEADLESS_PID" >/dev/null 2>&1 || break
    sleep 0.05
  done
  if kill -0 "$HEADLESS_PID" >/dev/null 2>&1; then
    print -u2 "Cancellation did not stop the $route route within five seconds."
    exit 1
  fi
  wait "$HEADLESS_PID" >/dev/null 2>&1 || true
  HEADLESS_PID=""
  cancel_ack_seen=0
  for _ in {1..100}; do
    set +e
    /usr/bin/grep -Eq "\"kind\":\"cancelled\",\"route\":\"$route\"" "$TEST_ROOT/provider-log.jsonl"
    cancel_ack_status=$?
    set -e
    if (( cancel_ack_status == 0 )); then
      cancel_ack_seen=1
      break
    elif (( cancel_ack_status != 1 )); then
      print -u2 "Provider-matrix cancellation evidence could not be scanned: $route"
      exit 1
    fi
    sleep 0.05
  done
  (( cancel_ack_seen == 1 )) || { print -u2 "Provider-matrix cancellation acknowledgement was missing: $route"; exit 1; }
  assert_request_count "$route" MATRIX_CANCEL 1
done

"$NODE" -e '
  const fs=require("node:fs");
  const [path]=process.argv.slice(1);
  const fail=(code)=>{process.stderr.write(`Provider-matrix audit failed: ${code}\n`);process.exit(1);};
  const rows=fs.readFileSync(path,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
  const routes=["deepseek","responses","anthropic","custom"];
  for(const route of routes){
    const requests=rows.filter((row)=>row.kind==="request"&&row.route===route);
    if(requests.length===0) fail(`${route}-missing-request`);
    if(requests.some((row)=>row.authorized!==true)) fail(`${route}-authorization`);
    if(requests.some((row)=>!row.shape?.json||!row.shape?.attributed||!row.shape?.model||!row.shape?.stream||!row.shape?.privateIdentifiersAbsent)) fail(`${route}-shape`);
    if(requests.some((row)=>row.shape.tools.some((name)=>/^(?:workflow|ralph)$/i.test(String(name))))) fail(`${route}-forbidden-tool`);
    const firstTool=requests.find((row)=>row.marker==="MATRIX_TOOL"&&!row.shape.hasToolResult&&row.shape.tools.some((name)=>String(name).toLowerCase()==="bash"));
    const toolResult=requests.find((row)=>row.marker==="MATRIX_TOOL"&&row.shape.hasToolResult);
    if(!firstTool?.shape?.tools.some((name)=>String(name).toLowerCase()==="bash")||!toolResult) fail(`${route}-tool-round-trip`);
  }
  for(const marker of [
    "MATRIX_TOOL_IDENTITY_OMITTED",
    "MATRIX_TOOL_IDENTITY_NULL",
    "MATRIX_TOOL_IDENTITY_EMPTY",
    "MATRIX_TOOL_IDENTITY_REPEATED",
    "MATRIX_TOOL_IDENTITY_CONFLICTING"
  ]){
    const requests=rows.filter((row)=>row.kind==="request"&&row.route==="deepseek"&&row.marker===marker&&row.phase==="agent");
    if(requests.length!==2) fail(`${marker}-request-count`);
    const [initial,followUp]=requests;
    if(initial.shape.hasToolResult||!initial.shape.tools.some((name)=>String(name).toLowerCase()==="bash")) fail(`${marker}-initial-shape`);
    if(!followUp.shape.hasToolResult||followUp.shape.assistantToolCalls.length!==1||followUp.shape.toolResultCallIds.length!==1) fail(`${marker}-follow-up-shape`);
    const call=followUp.shape.assistantToolCalls[0];
    // The adapter preserves the streamed provider identity; DSH then resolves
    // the approved tool to its canonical lowercase registry name for replay.
    if(call.id!=="call_matrix_deepseek"||call.name!=="bash"||followUp.shape.toolResultCallIds[0]!==call.id) {
      const observed=JSON.stringify({id:call.id,name:call.name,resultID:followUp.shape.toolResultCallIds[0]});
      fail(`${marker}-tool-identity-${observed}`);
    }
  }
' "$TEST_ROOT/provider-log.jsonl"

# The private DeepSeek adapter is deliberately patched not to generate the
# stable upstream installation identifier, while the preload independently
# strips both it and the internal Harness session header from every provider
# request. Exercise both properties against the composed candidate.
[[ ! -e "$DSH_HOME/.anonymous-user-id" ]]

for route in deepseek responses anthropic custom; do
  set +e
  /usr/bin/grep -r -F -q -- "${CREDENTIAL_VALUES[$route]}" "$TEST_ROOT"
  secret_scan_status=$?
  set -e
  if (( secret_scan_status == 0 )); then
    print -u2 "Provider-matrix secret leakage detected in test artifacts."
    exit 1
  elif (( secret_scan_status != 1 )); then
    print -u2 "Provider-matrix artifacts could not be scanned safely."
    exit 1
  fi
done
[[ ! -s "$TEST_ROOT/provider-error.log" ]]

echo "Candidate-backed provider protocol matrix passed: official DeepSeek chat completions, OpenAI Responses, Anthropic Messages, and custom OpenAI-compatible auth and request shapes; streaming and split tool calls; DeepSeek omitted/null/empty/repeated/conflicting continuation identity preservation with one tool and no loop; cancellation; terminal 401 and DeepSeek 402 insufficient-balance handling; bounded 429/5xx retries; malformed and oversized response rejection; private identifier suppression; and secret non-leakage."
