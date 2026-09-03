#!/bin/zsh -f
set -euo pipefail
# Do not implicitly lower the qualification child when zsh backgrounds it;
# hardened runners may deny setpriority(2) even though process launch itself
# is permitted, which would otherwise add a misleading warning to evidence.
unsetopt BG_NICE

PROJECT_DIR="${0:A:h:h}"
source "$PROJECT_DIR/scripts/supervised-process-group.zsh"
source "$PROJECT_DIR/scripts/attested-loopback-fetch.zsh"
source "$PROJECT_DIR/scripts/watchdog-root.zsh"
source "$PROJECT_DIR/scripts/release-lock.zsh"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
ROUTE_MODE="${2:-bash}"
ROOT_WATCHDOG_STATE=0
fulmar_root_watchdog_state || ROOT_WATCHDOG_STATE=$?
if (( ROOT_WATCHDOG_STATE == 1 )); then
  exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" \
    --seconds 1800 --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 --lock-dir /private/tmp/LocalHarnessBuild.lock \
    --label "complete isolated DSH Qwen route" -- \
    /bin/zsh -f "$0" "$@"
elif (( ROOT_WATCHDOG_STATE == 2 )); then
  print -u2 "The Qwen route inherited an invalid root-watchdog attestation."
  exit 1
fi
fulmar_acquire_release_lock "isolated DSH Qwen route"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
DSH="$APP_DIR/Contents/Resources/Runtime/dsh/lib/bin.js"
PRELOADER="$APP_DIR/Contents/Resources/RuntimeSecurityPreload.mjs"
PATCH="$APP_DIR/Contents/Resources/LocalHarness.patch.yml"
PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-credentials-keychain/index.mjs"
FS_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-fs-confined/index.mjs"
MCP_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded/index.mjs"
CLIENT_SECURITY_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-client-security-bridge/index.mjs"
PERFORMANCE_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-performance-profile/index.mjs"
HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
SANDBOX_HELPER="$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner"
AUTH_RELAY="$PROJECT_DIR/Tests/Fixtures/RuntimeAuthenticationRelay.pl"
TEST_ROOT="$(mktemp -d /private/tmp/localharness-agent-route.XXXXXX)"
PROCESS_STATUS_FILE="$TEST_ROOT/dsh-supervisor.status"
DSH_TEST_HOME="$TEST_ROOT/home/.dsh"
PROCESS_ID=""
PROCESS_GROUP_ID=""
OLLAMA_FIXTURE_PID=""
OLLAMA_FIXTURE_GROUP_ID=""
OLLAMA_LISTENER_PID=""
OLLAMA_PORT=""
THERMAL_ABORTED=0
THERMAL_ADMISSION_SAMPLES=5
THERMAL_ADMISSION_INTERVAL_SECONDS=2
MODEL_ID="qwen3.8:27b-mlx"
EXPECTED_MANIFEST_DIGEST="5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"
MODEL_CONTEXT_WINDOW=49152
EXPECTED="LOCAL_HARNESS_DSH_QWEN_OK"
FS_CANARY_FILE="local_harness_fs_canary.txt"
BASH_CANARY_FILE="local_harness_bash_canary.txt"
MAX_SECONDS=360
PERFORMANCE_PROFILES='{"fast":{"maxOutputTokens":4096},"balanced":{"maxOutputTokens":8192},"deep":{"maxOutputTokens":16384}}'
PERFORMANCE_PROFILE="balanced"
MODEL_MAX_TOKENS=8192
PROVIDER_ORIGINS=""
TOKEN="agent-route-test-token-0123456789"
NONCE="agent-route-test-nonce-0123456789"

runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}

read_thermal_state() {
  local state
  state="$(/usr/bin/osascript -l JavaScript -e 'ObjC.import("Foundation"); $.NSProcessInfo.processInfo.thermalState.toString()' 2>/dev/null)" || return 1
  [[ "$state" == <0-3> ]] || return 1
  print -r -- "$state"
}

require_stable_thermal_headroom() {
  local sample state
  for ((sample = 1; sample <= THERMAL_ADMISSION_SAMPLES; sample++)); do
    state="$(read_thermal_state || print 3)"
    if [[ "$state" -ge 1 ]]; then
      print -u2 "The Qwen canary did not start because macOS could not prove sustained nominal thermal headroom. Let the Mac cool down, then rerun it."
      exit 75
    fi
    if (( sample < THERMAL_ADMISSION_SAMPLES )); then
      sleep "$THERMAL_ADMISSION_INTERVAL_SECONDS"
    fi
  done
}

case "$ROUTE_MODE" in
  bash)
    MAX_SECONDS=240
    PERFORMANCE_PROFILE="fast"
    MODEL_CONTEXT_WINDOW=32768
    MODEL_MAX_TOKENS=4096
    TASK="Begin immediately with exactly one Bash tool call; do not send a preamble or stop after planning. Use Bash with a concise description to create $BASH_CANARY_FILE in the current workspace containing exactly $EXPECTED. Do not request sandbox escalation. Do not claim success unless the Bash tool reports success. Immediately afterward, reply with exactly: $EXPECTED"
    ;;
  filesystem)
    MAX_SECONDS=240
    PERFORMANCE_PROFILE="fast"
    MODEL_CONTEXT_WINDOW=32768
    MODEL_MAX_TOKENS=4096
    TASK="Begin immediately with tools; do not send a preamble or stop after planning. First use the write tool to create $FS_CANARY_FILE containing exactly ORIGINAL. Second use the edit tool to replace ORIGINAL with exactly $EXPECTED. Third use the read tool to verify the exact final content. Do not use Bash or request sandbox escalation. Never claim success without the successful read-tool result. Immediately afterward, reply with exactly: $EXPECTED"
    ;;
  project)
    # A release canary must prove multi-file tool use without granting an
    # ordinary smoke task the same output budget as an explicit deep run.
    # Four thousand tokens is ample for this sub-3 KiB fixture and prevents a
    # long private reasoning loop from creating unnecessary verifier heat before
    # the first tool call.
    MAX_SECONDS=300
    PERFORMANCE_PROFILE="fast"
    MODEL_CONTEXT_WINDOW=32768
    MODEL_MAX_TOKENS=4096
    TASK="Begin immediately with tools; do not send a preamble or stop after planning. Use exactly three write-tool calls, in this order: create index.html with a canvas plus references to styles.css and game.js; create styles.css with local body and canvas rules; create game.js with valid JavaScript that obtains the canvas and draws one coloured rectangle. Keep each file under 1 KiB. Do not read back, edit, run Bash, use external assets or network access, request sandbox escalation, or create any other file. Do not reason about or verify the result after the third write; immediately reply with exactly: $EXPECTED"
    ;;
  realistic)
    # This is an explicit opt-in stress canary, not part of release assembly.
    # Bound this external verifier even though the native app's adaptive Eco
    # controller is not present here; a verifier must not create unbounded heat.
    MAX_SECONDS=300
    PERFORMANCE_PROFILE="fast"
    MODEL_CONTEXT_WINDOW=32768
    MODEL_MAX_TOKENS=4096
    TASK="Begin immediately with exactly three write-tool calls and no preamble, plan, explanation, or verification. First create game.js (under 4500 bytes): a compact playable 10x16 canvas falling-block puzzle; one-cell coloured pieces are acceptable, but it must support left/right/down keys, row clearing, score, level, pause, restart, a next-colour display, and a timed game loop. Second create index.html (under 900 bytes) containing the canvas, score/level/next/status elements, controls text, restart/pause buttons, and references to styles.css and game.js. Third create styles.css (under 1200 bytes) with a polished dark responsive layout, canvas styling, button styling, and one @media rule. Use no external assets, network APIs, Bash, reads, edits, sandbox escalation, or other files. Immediately after the third successful write, reply with exactly: $EXPECTED"
    ;;
  *)
    print -u2 "Unknown Qwen route mode: $ROUTE_MODE"
    exit 2
    ;;
esac

CONTEXT_ENFORCEMENT="{\"provider\":\"ollama\",\"model\":\"$MODEL_ID\",\"contextWindowTokens\":$MODEL_CONTEXT_WINDOW}"

cleanup() {
  local exit_code="${1:-$?}"
  if [[ -n "$PROCESS_ID" ]]; then
    fulmar_stop_inherited_process "$PROCESS_ID" "DSH Qwen route" || true
  fi
  if [[ -n "$OLLAMA_FIXTURE_PID" ]]; then
    fulmar_stop_inherited_process "$OLLAMA_FIXTURE_PID" "Ollama fixture" || true
  fi
  case "$TEST_ROOT" in
    /private/tmp/localharness-agent-route.[A-Za-z0-9]*) rm -rf -- "$TEST_ROOT" ;;
    *) print -u2 "Refusing to remove an unexpected Qwen-route path." ;;
  esac
  fulmar_release_release_lock
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

report_workspace_shape() {
  local summary=""
  local file size
  for file in index.html styles.css game.js; do
    if [[ -f "$TEST_ROOT/workspace/$file" && ! -L "$TEST_ROOT/workspace/$file" ]]; then
      size="$(stat -f '%z' "$TEST_ROOT/workspace/$file" 2>/dev/null || print '?')"
      summary+=" $file=$size"
    else
      summary+=" $file=absent"
    fi
  done
  print -u2 "Content-free project workspace shape:$summary"
}

for item in "$NODE" "$DSH" "$PRELOADER" "$PATCH" "$PLUGIN" "$FS_PLUGIN" "$MCP_PLUGIN" "$CLIENT_SECURITY_PLUGIN" "$PERFORMANCE_PLUGIN" "$HELPER" "$SANDBOX_HELPER" "$AUTH_RELAY"; do
  [[ -e "$item" ]] || { print -u2 "Missing agent-route component: $item"; exit 1; }
done

# These direct DSH canaries do not run inside the native adaptive controller.
# Refuse even fair pressure before loading a 27B model, and keep sampling every
# two seconds while it is resident. A thermal abort is evidence that the host
# needs to cool down; it is never converted into a passing release result.
require_stable_thermal_headroom

# Never reuse a pre-existing listener. Allocate a fresh non-conventional port,
# launch the exact signed Ollama binary in a supervised process group, and
# attest that the sole listener PID is the setsid group leader before trusting
# any HTTP bytes. A malicious service already bound to 11434 is irrelevant.
OLLAMA_FIXTURE_BINARY="/Applications/Ollama.app/Contents/Resources/ollama"
[[ -x "$OLLAMA_FIXTURE_BINARY" && ! -L "$OLLAMA_FIXTURE_BINARY" ]] || {
  print -u2 "The exact Ollama application binary is unavailable for the isolated Qwen fixture."
  exit 1
}
/usr/bin/codesign --verify --strict --requirements '=designated => identifier "ai.ollama.ollama" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "3MU9H2V9Y9"' "$OLLAMA_FIXTURE_BINARY"
OLLAMA_PORT="$("$NODE" "$PROJECT_DIR/scripts/allocate-loopback-port.mjs" --exclude 11434)"
[[ "$OLLAMA_PORT" == <-> && "$OLLAMA_PORT" -ge 1024 && "$OLLAMA_PORT" -le 65535 \
   && "$OLLAMA_PORT" != 11434 ]] || {
  print -u2 "The isolated Ollama fixture port was not a safe random loopback port."
  exit 1
}
PROVIDER_ORIGINS="[{\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":$OLLAMA_PORT,\"boundary\":\"onDevice\"}]"

"$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
  --seconds 1800 --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
  --emergency-rss-bytes 38654705664 --label "isolated Ollama fixture" -- \
  /usr/bin/env OLLAMA_HOST="127.0.0.1:$OLLAMA_PORT" "$OLLAMA_FIXTURE_BINARY" serve \
  >"$TEST_ROOT/ollama-stdout.txt" 2>"$TEST_ROOT/ollama-stderr.txt" &
OLLAMA_FIXTURE_PID="$!"
OLLAMA_FIXTURE_GROUP_ID="$FULMAR_ROOT_WATCHDOG_PGID_V1"
OLLAMA_LISTENER_PID="$(fulmar_attest_sole_inherited_child \
  "$OLLAMA_FIXTURE_PID" "$OLLAMA_FIXTURE_GROUP_ID")" || {
  print -u2 "The Ollama fixture did not establish one attested inherited child."
  exit 1
}

attest_ollama_listener() {
  local listeners listener_count
  listeners="$(/usr/sbin/lsof -nP -a -iTCP@127.0.0.1:"$OLLAMA_PORT" -sTCP:LISTEN -t 2>/dev/null)" || return 1
  listener_count="$(print -r -- "$listeners" | /usr/bin/awk 'NF == 1 { count += 1 } END { print count + 0 }')"
  [[ "$listener_count" == "1" && "$listeners" == "$OLLAMA_LISTENER_PID" \
     && "$OLLAMA_FIXTURE_GROUP_ID" == <-> ]] || return 1
  fulmar_attest_pid_in_process_group "$OLLAMA_LISTENER_PID" "$OLLAMA_FIXTURE_GROUP_ID" || return 1
  kill -0 "$OLLAMA_FIXTURE_PID" >/dev/null 2>&1
}

for _ in {1..80}; do
  kill -0 "$OLLAMA_FIXTURE_PID" >/dev/null 2>&1 || break
  if fulmar_fetch_attested_loopback_json \
      "$OLLAMA_LISTENER_PID" "$OLLAMA_FIXTURE_GROUP_ID" "$OLLAMA_PORT" \
      /api/version "$TEST_ROOT/ollama-version.json" 1 256; then
    break
  fi
  sleep 0.25
done
[[ -s "$TEST_ROOT/ollama-version.json" ]] || {
  print -u2 "The isolated Ollama fixture did not publish its bounded version endpoint."
  tail -c 4096 "$TEST_ROOT/ollama-stderr.txt" >&2 2>/dev/null || true
  exit 1
}
OLLAMA_VERSION="$("$NODE" "$PROJECT_DIR/scripts/ollama-version-policy.mjs" \
  --response "$TEST_ROOT/ollama-version.json")"

attest_ollama_listener || { print -u2 "The Ollama fixture listener identity changed."; exit 1; }
fulmar_fetch_attested_loopback_json \
  "$OLLAMA_LISTENER_PID" "$OLLAMA_FIXTURE_GROUP_ID" "$OLLAMA_PORT" \
  /api/tags "$TEST_ROOT/ollama-tags.json" 2 $((5 * 1024 * 1024))
[[ -s "$TEST_ROOT/ollama-tags.json" ]] || {
  print -u2 "The isolated Ollama fixture did not publish a bounded model catalog."
  tail -c 4096 "$TEST_ROOT/ollama-stderr.txt" >&2 2>/dev/null || true
  exit 1
}
"$NODE" -e '
  const fs=require("node:fs");
  const [path,expected,expectedDigest]=process.argv.slice(1);
  const body=JSON.parse(fs.readFileSync(path,"utf8"));
  const matches=(body.models??[]).filter((entry)=>entry?.name===expected || entry?.model===expected);
  if(matches.length!==1 || matches[0]?.digest!==expectedDigest) {
    process.stderr.write(`Required immutable Ollama model is not installed: ${expected}@${expectedDigest}\n`);
    process.exit(1);
  }
' "$TEST_ROOT/ollama-tags.json" "$MODEL_ID" "$EXPECTED_MANIFEST_DIGEST"

SKILL_ROOT="$DSH_TEST_HOME/skills/Active"
SANDBOX_TEMP="$TEST_ROOT/private-tmp"
mkdir -p "$DSH_TEST_HOME" "$DSH_TEST_HOME/Agents" "$SKILL_ROOT" "$TEST_ROOT/workspace" "$SANDBOX_TEMP"
chmod 700 "$TEST_ROOT" "$TEST_ROOT/home" "$DSH_TEST_HOME" "$DSH_TEST_HOME/Agents" "$DSH_TEST_HOME/skills" "$SKILL_ROOT" "$TEST_ROOT/workspace" "$SANDBOX_TEMP"
print -r -- '{"mode":"readWrite","reason":"protectedCheckpoint","schemaVersion":1}' > "$DSH_TEST_HOME/.fulmar-workspace-mutation-policy.json"
chmod 600 "$DSH_TEST_HOME/.fulmar-workspace-mutation-policy.json"
APPLICATION_SUPPORT="$TEST_ROOT/application-support/Local Harness"
THERMAL_DIRECTORY="$APPLICATION_SUPPORT/PerformanceTelemetry"
THERMAL_POLICY="$THERMAL_DIRECTORY/thermal-workload-policy.json"
mkdir -p "$THERMAL_DIRECTORY"
chmod 700 "$TEST_ROOT/application-support" "$APPLICATION_SUPPORT" "$THERMAL_DIRECTORY"
if [[ "$ROUTE_MODE" == "realistic" ]]; then
  # Reproduce the shipping app's conservative workload boundary. This forces
  # a realistic artifact build through the same 2K segments and automatic
  # continuation path that exposed the user's failure.
  print -r -- '{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"eco","schemaVersion":1}' > "$THERMAL_POLICY"
else
  print -r -- '{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"normal","schemaVersion":1}' > "$THERMAL_POLICY"
fi
chmod 600 "$THERMAL_POLICY"
MCP_CATALOG="$TEST_ROOT/mcp-activation-catalog.json"
print -r -- '{"schemaVersion":1,"plans":[]}' > "$MCP_CATALOG"
chmod 600 "$MCP_CATALOG"
"$NODE" -e '
  const fs=require("node:fs");
  const [path,model,rawContextWindow,rawMaxTokens,rawPort]=process.argv.slice(1);
  const contextWindow=Number(rawContextWindow);
  const maxTokens=Number(rawMaxTokens);
  const port=Number(rawPort);
  if(!Number.isSafeInteger(port) || port<1024 || port>65535 || port===11434) process.exit(1);
  const settings={
    "agent-default-model": { provider: "ollama", model },
    "llm-pi-ai": {
      providers: {
        ollama: {
          apiKeyEnv: "OLLAMA_API_KEY",
          displayName: "Ollama (isolated Qwen canary)",
          api: "openai-completions",
          baseURL: `http://127.0.0.1:${port}/v1`,
          reasoning: "off",
          compat: { maxTokensField: "max_tokens", supportsReasoningEffort: true },
          models: [{
            id: model,
            name: "Qwen 3.8 27B MLX (exact canary)",
            contextWindow,
            maxTokens,
            input: ["text"],
            reasoningEfforts: { off: "none", high: "high" }
          }]
        }
      }
    }
  };
  fs.writeFileSync(path,`${JSON.stringify(settings,null,2)}\n`,{mode:0o600,flag:"wx"});
' "$DSH_TEST_HOME/settings.yaml" "$MODEL_ID" "$MODEL_CONTEXT_WINDOW" "$MODEL_MAX_TOKENS" "$OLLAMA_PORT"
"$NODE" -e '
  const fs=require("node:fs");
  const [path,model,rawContextWindow,rawMaxTokens,rawPort]=process.argv.slice(1);
  const contextWindow=Number(rawContextWindow);
  const maxTokens=Number(rawMaxTokens);
  const port=Number(rawPort);
  const settings=JSON.parse(fs.readFileSync(path,"utf8"));
  const selected=settings["agent-default-model"];
  const profile=settings["llm-pi-ai"]?.providers?.ollama;
  if(selected?.provider!=="ollama" || selected?.model!==model
      || profile?.baseURL!==`http://127.0.0.1:${port}/v1`
      || profile?.api!=="openai-completions"
      || profile?.apiKeyEnv!=="OLLAMA_API_KEY"
      || profile?.compat?.maxTokensField!=="max_tokens"
      || profile?.compat?.supportsReasoningEffort!==true
      || profile?.reasoning!=="off"
      || profile?.models?.length!==1 || profile.models[0]?.id!==model
      || profile.models[0]?.reasoningEfforts?.off!=="none"
      || profile.models[0]?.reasoningEfforts?.high!=="high"
      || profile.models[0]?.contextWindow!==contextWindow
      || profile.models[0]?.maxTokens!==maxTokens) process.exit(1);
' "$DSH_TEST_HOME/settings.yaml" "$MODEL_ID" "$MODEL_CONTEXT_WINDOW" "$MODEL_MAX_TOKENS" "$OLLAMA_PORT"

# This test-only random listener passed the exact PID/catalog/model
# preflight above. Admit only that literal origin through Strict Local; an
# empty origin set correctly blocks the provider transport itself.
(
  cd "$TEST_ROOT/workspace"
  runtime_auth_frame | exec "$PROJECT_DIR/scripts/run-with-watchdog.sh" --inherit-root \
    --seconds "$MAX_SECONDS" --max-rss-bytes 34359738368 --rss-grace-seconds 10 \
    --emergency-rss-bytes 38654705664 --status-file "$PROCESS_STATUS_FILE" \
    --label "DSH Qwen route" -- \
    env -i \
    HOME="$TEST_ROOT/home" \
    USER="$(id -un)" \
    LOGNAME="$(id -un)" \
    PATH="/usr/bin:/bin" \
    TMPDIR="$TEST_ROOT" \
    DSH_HOME="$DSH_TEST_HOME" \
    DSH_AGENTS_HOME="$DSH_TEST_HOME/Agents" \
    DSH_TELEMETRY_MODE="DISABLED" \
    OLLAMA_HOST="127.0.0.1:$OLLAMA_PORT" \
    OLLAMA_API_KEY="local-ollama" \
    LOCAL_HARNESS_CREDENTIAL_PLUGIN="$PLUGIN" \
    LOCAL_HARNESS_CREDENTIAL_HELPER="$HELPER" \
    LOCAL_HARNESS_CREDENTIAL_HOME="$TEST_ROOT/home" \
    LOCAL_HARNESS_MCP_PLUGIN="$MCP_PLUGIN" \
    LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN="$CLIENT_SECURITY_PLUGIN" \
    LOCAL_HARNESS_PERFORMANCE_PLUGIN="$PERFORMANCE_PLUGIN" \
    LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" \
    LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" \
    LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" \
    LOCAL_HARNESS_SANDBOX_TEMP="$SANDBOX_TEMP" \
    LOCAL_HARNESS_FS_PLUGIN="$FS_PLUGIN" \
    LOCAL_HARNESS_MCP_CATALOG="$MCP_CATALOG" \
    LOCAL_HARNESS_PERFORMANCE_PROFILE="$PERFORMANCE_PROFILE" \
    LOCAL_HARNESS_PERFORMANCE_PROFILES="$PERFORMANCE_PROFILES" \
    LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT="$APPLICATION_SUPPORT" \
    LOCAL_HARNESS_THERMAL_POLICY_FILE="$THERMAL_POLICY" \
    LOCAL_HARNESS_ACTIVE_PROVIDER="ollama" \
    LOCAL_HARNESS_CONTEXT_ENFORCEMENT="$CONTEXT_ENFORCEMENT" \
    LOCAL_HARNESS_STRICT_LOCAL=1 \
    LOCAL_HARNESS_PROVIDER_ORIGINS="$PROVIDER_ORIGINS" \
    LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
    NARB_DISABLE_NATIVE_CACHE=1 \
    /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" --profile headless --patch "$PATCH" \
      "$TASK"
) >"$TEST_ROOT/output.txt" 2>"$TEST_ROOT/error.txt" &
PROCESS_ID="$!"
PROCESS_GROUP_ID="$FULMAR_ROOT_WATCHDOG_PGID_V1"
fulmar_attest_pid_in_process_group "$PROCESS_ID" "$PROCESS_GROUP_ID" || {
  print -u2 "The DSH Qwen route did not remain in its attested root process group."
  exit 1
}

ATTEMPT_LIMIT=$(( MAX_SECONDS * 4 ))
THERMAL_POLL_COUNTDOWN=8
for ((attempt = 1; attempt <= ATTEMPT_LIMIT; attempt++)); do
  kill -0 "$PROCESS_ID" >/dev/null 2>&1 || break
  THERMAL_POLL_COUNTDOWN=$(( THERMAL_POLL_COUNTDOWN - 1 ))
  if (( THERMAL_POLL_COUNTDOWN == 0 )); then
    THERMAL_POLL_COUNTDOWN=8
    thermal_state="$(read_thermal_state || print 3)"
    if [[ "$thermal_state" -ge 1 ]]; then
      THERMAL_ABORTED=1
      fulmar_stop_inherited_process "$PROCESS_ID" "DSH Qwen route" || true
      PROCESS_ID=""
      PROCESS_GROUP_ID=""
      break
    fi
  fi
  sleep 0.25
done
if (( THERMAL_ABORTED == 1 )); then
  print -u2 "The Qwen canary stopped because macOS reported thermal pressure. Let the Mac cool down, then rerun it."
  [[ "$ROUTE_MODE" == "project" || "$ROUTE_MODE" == "realistic" ]] && report_workspace_shape
  exit 75
fi
if kill -0 "$PROCESS_ID" >/dev/null 2>&1; then
  print -u2 "The DSH-to-Qwen canary exceeded $MAX_SECONDS seconds."
  [[ "$ROUTE_MODE" == "project" || "$ROUTE_MODE" == "realistic" ]] && report_workspace_shape
  tail -c 32768 "$TEST_ROOT/error.txt" >&2
  tail -c 32768 "$TEST_ROOT/output.txt" >&2
  exit 1
fi
for _ in {1..20}; do
  [[ -f "$PROCESS_STATUS_FILE" ]] && break
  sleep 0.05
done
PROCESS_STATUS_METADATA="$(/usr/bin/stat -f '%u:%Lp:%l:%z' "$PROCESS_STATUS_FILE" 2>/dev/null || true)"
case "$PROCESS_STATUS_METADATA" in
  "$(/usr/bin/id -u):600:1:2"|"$(/usr/bin/id -u):600:1:3"|"$(/usr/bin/id -u):600:1:4") ;;
  *)
  print -u2 "The DSH-to-Qwen supervisor did not publish a safe bounded status receipt."
  exit 1
  ;;
esac
PROCESS_STATUS="$(/bin/cat "$PROCESS_STATUS_FILE")"
if [[ "$PROCESS_STATUS" != "0" ]]; then
  [[ "$ROUTE_MODE" == "project" || "$ROUTE_MODE" == "realistic" ]] && report_workspace_shape
  tail -c 32768 "$TEST_ROOT/error.txt" >&2
  tail -c 32768 "$TEST_ROOT/output.txt" >&2
  exit 1
fi
PROCESS_ID=""
PROCESS_GROUP_ID=""

/usr/bin/grep -Eq -- "$EXPECTED" "$TEST_ROOT/output.txt"
if [[ "$ROUTE_MODE" == "bash" ]]; then
  [[ "$(tr -d '\r\n' < "$TEST_ROOT/workspace/$BASH_CANARY_FILE")" == "$EXPECTED" ]]
else
  if [[ "$ROUTE_MODE" == "filesystem" ]]; then
    [[ "$(tr -d '\r\n' < "$TEST_ROOT/workspace/$FS_CANARY_FILE")" == "$EXPECTED" ]]
  else
    for project_file in index.html styles.css game.js; do
      [[ -s "$TEST_ROOT/workspace/$project_file" ]]
    done
    /usr/bin/grep -Eq 'canvas' "$TEST_ROOT/workspace/index.html"
    /usr/bin/grep -Eq 'styles\.css' "$TEST_ROOT/workspace/index.html"
    /usr/bin/grep -Eq 'game\.js' "$TEST_ROOT/workspace/index.html"
    "$NODE" --check "$TEST_ROOT/workspace/game.js" >/dev/null
    if [[ "$ROUTE_MODE" == "realistic" ]]; then
      "$NODE" "$PROJECT_DIR/scripts/verify-realistic-workspace.mjs" "$TEST_ROOT/workspace"
    fi
  fi
fi
for forbidden_pattern in \
  'MISSING_CREDENTIAL|no credential for provider route|Add an API key to get started' \
  'sandbox_apply: Operation not permitted|danger-full-access'; do
  set +e
  /usr/bin/grep -Eq "$forbidden_pattern" "$TEST_ROOT/output.txt" "$TEST_ROOT/error.txt"
  FORBIDDEN_STATUS=$?
  set -e
  if (( FORBIDDEN_STATUS == 0 )); then
    print -u2 "The Qwen route emitted a forbidden failure marker."
    exit 1
  elif (( FORBIDDEN_STATUS != 1 )); then
    print -u2 "The Qwen route evidence could not be scanned safely."
    exit 1
  fi
done
"$NODE" -e '
  const fs=require("node:fs");
  const [path,model]=process.argv.slice(1);
  const settings=JSON.parse(fs.readFileSync(path,"utf8"));
  if(settings["agent-default-model"]?.provider!=="ollama"
      || settings["agent-default-model"]?.model!==model
      || settings["llm-pi-ai"]?.providers?.ollama?.models?.[0]?.id!==model) process.exit(1);
' "$DSH_TEST_HOME/settings.yaml" "$MODEL_ID"
attest_ollama_listener || { print -u2 "The isolated Ollama listener identity changed before completion."; exit 1; }
print "Full isolated DSH agent route used compatible Ollama $OLLAMA_VERSION with exact local model $MODEL_ID and completed the $ROUTE_MODE tool path without reading user DSH settings or requiring a DeepSeek API key."
