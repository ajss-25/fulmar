#!/bin/zsh -f
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_DIR="${1:-/private/tmp/LocalHarnessBuild/Fulmar.app}"
NODE="$APP_DIR/Contents/Resources/Runtime/node"
DSH="$APP_DIR/Contents/Resources/Runtime/dsh/lib/bin.js"
PRELOADER="$APP_DIR/Contents/Resources/RuntimeSecurityPreload.mjs"
PATCH="$APP_DIR/Contents/Resources/LocalHarness.patch.yml"
PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-credentials-keychain/index.mjs"
FS_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-fs-confined/index.mjs"
MCP_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded/index.mjs"
CLIENT_SECURITY_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-client-security-bridge/index.mjs"
PERFORMANCE_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-performance-profile/index.mjs"
WEB_FETCH_PLUGIN="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@local-harness/dsh-web-fetch-safe/index.mjs"
HELPER="$APP_DIR/Contents/MacOS/LocalHarnessCredentialHelper"
SANDBOX_HELPER="$APP_DIR/Contents/MacOS/LocalHarnessSandboxRunner"
TREE_SNAPSHOT_HELPER="$PROJECT_DIR/scripts/local-tree-snapshot.mjs"
AUTH_RELAY="$PROJECT_DIR/Tests/Fixtures/RuntimeAuthenticationRelay.pl"
CANARY_STATE="${LOCAL_HARNESS_CANARY_STATE:-empty}"
CLONED_DSH_SOURCE="${LOCAL_HARNESS_CLONED_DSH_SOURCE:-}"
REQUIRE_NONEMPTY_CLONE="${LOCAL_HARNESS_REQUIRE_NONEMPTY_CLONE:-0}"
[[ "$CANARY_STATE" == "empty" || "$CANARY_STATE" == "clone" ]] || {
  print -u2 "Runtime security canary state must be empty or clone."
  exit 64
}
[[ "$REQUIRE_NONEMPTY_CLONE" == "0" || "$REQUIRE_NONEMPTY_CLONE" == "1" ]] || {
  print -u2 "LOCAL_HARNESS_REQUIRE_NONEMPTY_CLONE must be 0 or 1."
  exit 64
}
if [[ -n "$CLONED_DSH_SOURCE" ]]; then
  [[ "$CANARY_STATE" == "clone" && "$CLONED_DSH_SOURCE" == /* \
     && -d "$CLONED_DSH_SOURCE" && ! -L "$CLONED_DSH_SOURCE" \
     && "${CLONED_DSH_SOURCE:A}" == "$CLONED_DSH_SOURCE" \
     && "$(/usr/bin/stat -f '%u:%Lp' "$CLONED_DSH_SOURCE")" == "$(/usr/bin/id -u):700" ]] || {
    print -u2 "The explicit cloned DSH source is not a private owner-controlled real directory."
    exit 1
  }
  USER_DSH_HOME="$CLONED_DSH_SOURCE"
else
  USER_DSH_HOME="$HOME/.dsh"
fi
if [[ "$REQUIRE_NONEMPTY_CLONE" == "1" && -z "$CLONED_DSH_SOURCE" ]]; then
  print -u2 "A required deterministic cloned-state canary needs an explicit source fixture."
  exit 1
fi
if [[ "$CANARY_STATE" == "clone" \
      && ( ! -d "$USER_DSH_HOME" || -L "$USER_DSH_HOME" ) ]]; then
  print -u2 "Clone-state verification requires one real existing DSH source directory."
  exit 1
fi
TEST_ROOT="$(mktemp -d /private/tmp/localharness-security.XXXXXX)"
EVIDENCE_ROOT="$TEST_ROOT/evidence"
RUNTIME_SANDBOX_TEMP="$TEST_ROOT/runtime-sandbox-temp"
SKILL_ROOT="$TEST_ROOT/home/.dsh/skills/Active"
PROCESS_ID=""
SOURCE_STATE_SNAPSHOT_ENABLED=0
SOURCE_STATE_BEFORE="$EVIDENCE_ROOT/source-state-before.json"
SOURCE_STATE_AFTER="$EVIDENCE_ROOT/source-state-after.json"
SUPPRESS_RUNTIME_FAILURE_DETAILS=0
PERFORMANCE_PROFILES='{"fast":{"maxOutputTokens":4096},"balanced":{"maxOutputTokens":8192},"deep":{"maxOutputTokens":16384}}'
APPLICATION_SUPPORT="$TEST_ROOT/application-support/Local Harness"
THERMAL_DIRECTORY="$APPLICATION_SUPPORT/PerformanceTelemetry"
THERMAL_POLICY="$THERMAL_DIRECTORY/thermal-workload-policy.json"

stop_authenticated_runtime() {
  [[ -n "$PROCESS_ID" ]] || return 0
  local pid="$PROCESS_ID"
  /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
  for _ in {1..100}; do
    /bin/kill -0 "$pid" >/dev/null 2>&1 || break
    sleep 0.05
  done
  if /bin/kill -0 "$pid" >/dev/null 2>&1; then
    /bin/kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
  PROCESS_ID=""
  ! /bin/kill -0 "$pid" >/dev/null 2>&1
}

assert_extended_pattern_absent() {
  local pattern="$1"
  shift
  set +e
  /usr/bin/grep -Eq -- "$pattern" "$@"
  local match_status=$?
  set -e
  if (( match_status == 0 )); then
    print -u2 "Runtime security evidence contained a forbidden value."
    exit 1
  elif (( match_status != 1 )); then
    print -u2 "Runtime security evidence could not be scanned safely."
    exit 1
  fi
}

cleanup() {
  local exit_code="${1:-$?}"
  if (( exit_code != 0 )); then
    print -u2 "Runtime security verification failed with status $exit_code."
    if (( ! SUPPRESS_RUNTIME_FAILURE_DETAILS )); then
      [[ -f "$EVIDENCE_ROOT/runtime-error.log" ]] && sed -n '1,160p' "$EVIDENCE_ROOT/runtime-error.log" >&2
      [[ -f "$EVIDENCE_ROOT/runtime.log" ]] && tail -80 "$EVIDENCE_ROOT/runtime.log" >&2
    fi
  fi
  if [[ -n "$PROCESS_ID" ]]; then
    stop_authenticated_runtime || true
  fi
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

for item in "$NODE" "$DSH" "$PRELOADER" "$PATCH" "$PLUGIN" "$FS_PLUGIN" "$MCP_PLUGIN" "$CLIENT_SECURITY_PLUGIN" "$PERFORMANCE_PLUGIN" "$WEB_FETCH_PLUGIN" "$HELPER" "$SANDBOX_HELPER" "$TREE_SNAPSHOT_HELPER" "$AUTH_RELAY"; do
  [[ -e "$item" ]] || { print -u2 "Missing runtime component: $item"; exit 1; }
done

TOKEN="test-token-0123456789abcdefghijklmnopqrstuvwxyz"
NONCE="test-nonce-0123456789"
runtime_auth_frame() {
  print -r -- "FULMAR_RUNTIME_AUTH_V1:$TOKEN:$NONCE"
}
mkdir -p "$TEST_ROOT/home" "$TEST_ROOT/workspace" "$SKILL_ROOT" "$EVIDENCE_ROOT" "$RUNTIME_SANDBOX_TEMP"
chmod 700 "$TEST_ROOT" "$TEST_ROOT/home" "$TEST_ROOT/home/.dsh" "$TEST_ROOT/home/.dsh/skills" "$SKILL_ROOT" "$TEST_ROOT/workspace" "$EVIDENCE_ROOT" "$RUNTIME_SANDBOX_TEMP"
: > "$EVIDENCE_ROOT/runtime.log"
: > "$EVIDENCE_ROOT/runtime-error.log"
chmod 600 "$EVIDENCE_ROOT/runtime.log" "$EVIDENCE_ROOT/runtime-error.log"
mkdir -p "$THERMAL_DIRECTORY"
chmod 700 "$TEST_ROOT/application-support" "$APPLICATION_SUPPORT" "$THERMAL_DIRECTORY"
print -r -- '{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"normal","schemaVersion":1}' > "$THERMAL_POLICY"
chmod 600 "$THERMAL_POLICY"
mkdir -p "$TEST_ROOT/credential-home"
chmod 700 "$TEST_ROOT/credential-home"
MCP_CATALOG="$TEST_ROOT/mcp-activation-catalog.json"
print -r -- '{"schemaVersion":1,"plans":[]}' > "$MCP_CATALOG"
chmod 600 "$MCP_CATALOG"
if [[ "$CANARY_STATE" == "clone" && -d "$USER_DSH_HOME" && ! -L "$USER_DSH_HOME" ]]; then
  if [[ "$REQUIRE_NONEMPTY_CLONE" == "1" ]]; then
    for fixture_path in \
      ".fulmar-ci-clone-fixture.json" \
      ".fulmar-ci-fixture/nested/prior-state.txt"; do
      [[ -f "$USER_DSH_HOME/$fixture_path" && ! -L "$USER_DSH_HOME/$fixture_path" ]] || {
        print -u2 "The deterministic cloned-state source fixture is incomplete."
        exit 1
      }
    done
  fi
  "$NODE" "$TREE_SNAPSHOT_HELPER" "$USER_DSH_HOME" "$SOURCE_STATE_BEFORE"
  SOURCE_STATE_SNAPSHOT_ENABLED=1
  mkdir -p "$TEST_ROOT/home/.dsh"
  /usr/bin/rsync -a \
    --exclude '.credentials.yaml' \
    --exclude '.env' \
    --exclude '.env.*' \
    --exclude '*credential*' \
    --exclude '*private-key*' \
    --exclude '*.pem' \
    --exclude '*.key' \
    --exclude '*.p12' \
    --exclude '*.pfx' \
    --exclude 'skills' \
    "$USER_DSH_HOME/" "$TEST_ROOT/home/.dsh/"
  if [[ "$REQUIRE_NONEMPTY_CLONE" == "1" ]]; then
    /usr/bin/cmp -s \
      "$USER_DSH_HOME/.fulmar-ci-clone-fixture.json" \
      "$TEST_ROOT/home/.dsh/.fulmar-ci-clone-fixture.json" || {
      print -u2 "The deterministic cloned-state marker was not copied byte-for-byte."
      exit 1
    }
    /usr/bin/cmp -s \
      "$USER_DSH_HOME/.fulmar-ci-fixture/nested/prior-state.txt" \
      "$TEST_ROOT/home/.dsh/.fulmar-ci-fixture/nested/prior-state.txt" || {
      print -u2 "The nested deterministic cloned-state fixture was not copied byte-for-byte."
      exit 1
    }
  fi
fi
mkdir -p "$SKILL_ROOT"
chmod 700 "$TEST_ROOT/home/.dsh" "$TEST_ROOT/home/.dsh/skills" "$SKILL_ROOT"
cd "$TEST_ROOT/workspace"

# DSH_HOME is a required security boundary, not an incidental CLI default.
# Missing or linked roots must fail before any probe body can execute.
if runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e 'process.exit(0)' >/dev/null 2>&1; then
  print -u2 "Runtime preloader unexpectedly accepted a missing DSH_HOME."
  exit 1
fi
mkdir "$TEST_ROOT/unsafe-dsh-target"
chmod 700 "$TEST_ROOT/unsafe-dsh-target"
ln -s "$TEST_ROOT/unsafe-dsh-target" "$TEST_ROOT/unsafe-dsh-link"
if runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/unsafe-dsh-link" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e 'process.exit(0)' >/dev/null 2>&1; then
  print -u2 "Runtime preloader unexpectedly accepted a linked DSH_HOME."
  exit 1
fi

# Assert both halves of Strict Local independently so authentication success cannot
# hide a future tool-sandbox or supervisor-preload regression.
/bin/zsh -f "$PROJECT_DIR/scripts/verify-sandbox-runner.sh" "$APP_DIR"
/bin/zsh -f "$PROJECT_DIR/scripts/verify-mcp-runtime-security.sh" "$APP_DIR"
# The harness keeps its own private HOME, while only the exact reviewed
# credential helper is launched with the separately captured login-home
# boundary. The boundary variable must not remain visible to DSH code, and a
# caller-provided child HOME must not be able to override it.
runtime_auth_frame | env -i HOME="$TEST_ROOT/home" USER="$(id -un)" LOGNAME="$(id -un)" PATH="/usr/bin:/bin" LANG="en_US.UTF-8" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_CREDENTIAL_HELPER="$PROJECT_DIR/Tests/Fixtures/CanaryCredentialHelper.sh" LOCAL_HARNESS_CREDENTIAL_HOME="$TEST_ROOT/credential-home" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e '
    const cp = require("node:child_process");
    const helper = process.argv[1];
    const privateHome = process.argv[2];
    const credentialHome = process.argv[3];
    const result = cp.spawnSync(helper, ["environment-home"], {
      encoding: "utf8",
      env: { HOME: privateHome, USER: "forged", LOGNAME: "forged", PATH: "/private/forged" }
    });
    const hidden = process.env.LOCAL_HARNESS_CREDENTIAL_HOME === undefined;
    process.exit(result.status === 0 && result.stdout === credentialHome && process.env.HOME === privateHome && hidden ? 0 : 9);
  ' "$PROJECT_DIR/Tests/Fixtures/CanaryCredentialHelper.sh" "$TEST_ROOT/home" "$TEST_ROOT/credential-home" >/dev/null
runtime_auth_frame | env -i HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" PATH="/usr/bin:/bin" LANG="en_US.UTF-8" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=0 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[{"scheme":"https","host":"public.example","port":443,"boundary":"cloud"}]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" \
    --import "$PROJECT_DIR/Tests/Fixtures/RuntimeSecurityGuardedFetchStubPreload.mjs" \
    --import "$PRELOADER" \
  "$PROJECT_DIR/Tests/Fixtures/RuntimeSecurityGuardedFetchTLSProbe.mjs" public.example \
  >/dev/null
runtime_auth_frame | env -i HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" PATH="/usr/bin:/bin" LANG="en_US.UTF-8" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" \
    --import "$PROJECT_DIR/Tests/Fixtures/RuntimeSecurityGuardedFetchStubPreload.mjs" \
    --import "$PRELOADER" \
    "$PROJECT_DIR/Tests/Fixtures/RuntimeSecurityAuxiliaryWebProbe.mjs" \
  >/dev/null
runtime_auth_frame | env -i HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" PATH="/usr/bin:/bin" LANG="en_US.UTF-8" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=0 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[{"scheme":"https","host":"93.184.216.34","port":443,"boundary":"cloud"},{"scheme":"http","host":"192.168.1.20","port":8080,"boundary":"localNetwork"},{"scheme":"http","host":"127.0.0.1","port":11434,"boundary":"onDevice"}]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$PROJECT_DIR/Tests/Fixtures/RuntimeSecurityNetworkProbe.mjs" \
  >/dev/null
runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" --input-type=module -e \
  'import fs, { realpathSync } from "node:fs"; const expected=process.argv[1]; const a=fs.realpathSync.native(expected); const b=realpathSync.native(expected); process.exit(a===expected&&b===expected?0:8)' \
  "$APP_DIR/Contents/Resources/Runtime/dsh" >/dev/null 2>&1

runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e \
  'try{require("net").connect(443,"1.1.1.1");process.exit(5)}catch(e){process.exit(e.code==="EACCES"?0:4)}' \
  >/dev/null 2>&1
runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e '
    const expectDenied = (fn) => { try { fn(); return false; } catch (error) { return error?.code === "EACCES"; } };
    const socket = new (require("node:net").Socket)();
    const udp = require("node:dgram").createSocket("udp4");
    const direct = [
      expectDenied(() => socket.connect({ host: "203.0.113.1", port: 9 })),
      expectDenied(() => require("node:net").connect(11434, "127.0.0.1")),
      expectDenied(() => fetch("http://127.0.0.1:11434/api/tags")),
      expectDenied(() => udp.send(Buffer.from("x"), 9, "203.0.113.1", () => {})),
      expectDenied(() => require("node:dns").resolve4("nonexistent.invalid", () => {})),
      expectDenied(() => require("node:dns").resolve4("localhost", () => {})),
      expectDenied(() => require("node:dns").lookup("localhost", () => {})),
      expectDenied(() => process.binding("tcp_wrap")),
      expectDenied(() => process.execve("/usr/bin/false", ["false"], {})),
      expectDenied(() => process.dlopen({}, "/private/tmp/unreviewed.node")),
      expectDenied(() => new (require("node:worker_threads").Worker)("", { eval: true, execArgv: [] }))
    ];
    socket.destroy(); udp.close();
    (async () => {
      let promiseDenied = false;
      try { await new (require("node:dns").promises.Resolver)().resolve4("nonexistent.invalid"); }
      catch (error) { promiseDenied = error?.code === "EACCES"; }
      process.exit(direct.every(Boolean) && promiseDenied ? 0 : 8);
    })();
  ' >/dev/null 2>&1
AUTH_TEST_PORT="$("$NODE" -e 'const n=require("node:net").createServer();n.listen(0,"127.0.0.1",()=>{console.log(n.address().port);n.close()})')"
runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS="[{\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":$AUTH_TEST_PORT,\"boundary\":\"onDevice\"}]" LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e '
    const http = require("node:http");
    const server = new http.Server();
    server.on("request", (_request, response) => response.end("UNWRAPPED"));
    const timer = setTimeout(() => process.exit(9), 5000);
    server.listen(Number(process.argv[1]), "127.0.0.1", async () => {
      try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
        const body = await response.text();
        clearTimeout(timer); server.close();
        process.exit(response.status === 401 && !body.includes("UNWRAPPED") ? 0 : 8);
      } catch { clearTimeout(timer); server.close(); process.exit(7); }
    });
  ' "$AUTH_TEST_PORT" >/dev/null 2>&1
runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e \
  'const cp=require("node:child_process");const external=cp.spawnSync("/usr/bin/curl",["-fsS","--max-time","2","https://example.com/"],{stdio:"ignore"});const local=cp.spawnSync("/usr/bin/curl",["-fsS","--max-time","2","http://127.0.0.1:11434/api/tags"],{stdio:"ignore"});process.exit(external.status!==0&&local.status!==0?0:6)' \
  >/dev/null 2>&1
printf 'LOCAL_HARNESS_RG_OK\n' > "$TEST_ROOT/workspace/search-canary.txt"
RG_PATH="$APP_DIR/Contents/Resources/Runtime/dsh/node_modules/@vscode/ripgrep-darwin-arm64/bin/rg"
runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e \
  'const cp=require("node:child_process");const r=cp.spawnSync(process.argv[1],["--no-config","LOCAL_HARNESS_RG_OK",process.argv[2]],{encoding:"utf8"});process.exit(r.status===0&&r.stdout.includes("LOCAL_HARNESS_RG_OK")?0:7)' \
  "$RG_PATH" "$TEST_ROOT/workspace" >/dev/null 2>&1
KEYCHAIN_FILE="$HOME/Library/Keychains/login.keychain-db"
if [[ -f "$KEYCHAIN_FILE" ]] && runtime_auth_frame | env -i HOME="$HOME" PATH="/usr/bin:/bin" TMPDIR="$TEST_ROOT" DSH_HOME="$TEST_ROOT/home/.dsh" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" LOCAL_HARNESS_SANDBOX_TEMP="$TEST_ROOT" LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" -e 'require("fs").readFileSync(process.argv[1])' \
  "$KEYCHAIN_FILE" >/dev/null 2>&1; then
  print -u2 "Strict Local unexpectedly allowed reading the login Keychain file."
  exit 1
fi

runtime_auth_frame | env -i \
  HOME="$TEST_ROOT/home" \
  USER="$(id -un)" \
  LOGNAME="$(id -un)" \
  PATH="/usr/bin:/bin" \
  TMPDIR="$RUNTIME_SANDBOX_TEMP" \
  DSH_HOME="$TEST_ROOT/home/.dsh" \
  DSH_TELEMETRY_MODE="DISABLED" \
  OLLAMA_HOST="127.0.0.1:11434" \
  OLLAMA_API_KEY="local-ollama" \
  NARB_DISABLE_NATIVE_CACHE=1 \
  LOCAL_HARNESS_CREDENTIAL_PLUGIN="$PLUGIN" \
  LOCAL_HARNESS_CREDENTIAL_HELPER="$HELPER" \
  LOCAL_HARNESS_CREDENTIAL_HOME="$TEST_ROOT/home" \
  LOCAL_HARNESS_MCP_PLUGIN="$MCP_PLUGIN" \
  LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN="$CLIENT_SECURITY_PLUGIN" \
  LOCAL_HARNESS_PERFORMANCE_PLUGIN="$PERFORMANCE_PLUGIN" \
  LOCAL_HARNESS_SANDBOX_HELPER="$SANDBOX_HELPER" \
  LOCAL_HARNESS_WORKSPACE_ROOTS="[\"$TEST_ROOT/workspace\"]" \
  LOCAL_HARNESS_READONLY_ROOTS="[\"$SKILL_ROOT\"]" \
  LOCAL_HARNESS_SANDBOX_TEMP="$RUNTIME_SANDBOX_TEMP" \
  LOCAL_HARNESS_FS_PLUGIN="$FS_PLUGIN" \
  LOCAL_HARNESS_MCP_CATALOG="$MCP_CATALOG" \
  LOCAL_HARNESS_PERFORMANCE_PROFILE="balanced" \
  LOCAL_HARNESS_PERFORMANCE_PROFILES="$PERFORMANCE_PROFILES" \
  LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT="$APPLICATION_SUPPORT" \
  LOCAL_HARNESS_THERMAL_POLICY_FILE="$THERMAL_POLICY" \
  LOCAL_HARNESS_ACTIVE_PROVIDER="ollama" \
  LOCAL_HARNESS_STRICT_LOCAL=1 \
  LOCAL_HARNESS_PROVIDER_ORIGINS='[]' \
  LOCAL_HARNESS_RUNTIME_ROOT="$APP_DIR/Contents/Resources/Runtime/dsh" \
  /usr/bin/perl "$AUTH_RELAY" "$NODE" --import "$PRELOADER" "$DSH" web --patch "$PATCH" \
    --no-open --host 127.0.0.1 --port 0 \
    >"$EVIDENCE_ROOT/runtime.log" 2>"$EVIDENCE_ROOT/runtime-error.log" &
PROCESS_ID="$!"

PORT=""
# Match the production application's bounded 60-second readiness allowance.
# Use only system tools from the clean release PATH: an absent Homebrew `rg`
# must never be mistaken for a runtime that failed to publish its port.
for _ in {1..600}; do
  set +e
  PORT_LINES="$(/usr/bin/grep -Eo 'dsh web: http://127\.0\.0\.1:[0-9]+' \
    "$EVIDENCE_ROOT/runtime.log" 2>"$EVIDENCE_ROOT/port-parser-error.log")"
  PORT_PARSE_STATUS=$?
  set -e
  if (( PORT_PARSE_STATUS == 0 )); then
    PORT_LINE="${PORT_LINES##*$'\n'}"
    PORT="${PORT_LINE##*:}"
    [[ "$PORT" == <-> && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || {
      print -u2 "Runtime published a malformed port record."
      exit 1
    }
  elif (( PORT_PARSE_STATUS != 1 )); then
    print -u2 "Runtime port evidence could not be parsed safely."
    [[ -f "$EVIDENCE_ROOT/port-parser-error.log" ]] && /usr/bin/sed -n '1,20p' "$EVIDENCE_ROOT/port-parser-error.log" >&2
    exit 1
  fi
  [[ -n "$PORT" ]] && break
  kill -0 "$PROCESS_ID" >/dev/null 2>&1 || {
    sed -n '1,120p' "$EVIDENCE_ROOT/runtime-error.log" >&2
    exit 1
  }
  sleep 0.1
done

[[ -n "$PORT" ]] || { print -u2 "Runtime did not publish an ephemeral port."; exit 1; }
[[ "$PORT" != "3080" ]] || { print -u2 "Runtime reused the retired fixed port."; exit 1; }
BASE="http://127.0.0.1:$PORT"

[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/")" == "401" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-Local-Harness-Token: wrong' "$BASE/api/host.describe")" == "401" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: attacker.invalid' -H "X-Local-Harness-Token: $TOKEN" "$BASE/")" == "401" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' "$BASE/api/events.host")" == "401" ]]
for malformed_cookie in '%' '%ZZ' '%E0%A4%A'; do
  [[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: LocalHarnessSession=$malformed_cookie" "$BASE/")" == "401" ]]
  kill -0 "$PROCESS_ID" >/dev/null 2>&1
done
OVERSIZED_COOKIE="$(/usr/bin/printf '%09000d' 0 | /usr/bin/tr 0 x)"
OVERSIZED_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: LocalHarnessSession=$OVERSIZED_COOKIE" "$BASE/" || true)"
[[ "$OVERSIZED_STATUS" == "401" || "$OVERSIZED_STATUS" == "431" ]]
kill -0 "$PROCESS_ID" >/dev/null 2>&1

HEALTH="$EVIDENCE_ROOT/health.json"
[[ "$(curl -sS -o "$HEALTH" -w '%{http_code}' -H "X-Local-Harness-Token: $TOKEN" "$BASE/_local_harness/health")" == "200" ]]
/usr/bin/grep -Eq '"service":"app\.localharness\.runtime"' "$HEALTH"
/usr/bin/grep -Eq '"protocolVersion":1' "$HEALTH"
/usr/bin/grep -Eq "\"nonce\":\"$NONCE\"" "$HEALTH"
/usr/bin/grep -Eq "\"pid\":$PROCESS_ID" "$HEALTH"

ROOT_HEADERS="$EVIDENCE_ROOT/root-headers.txt"
[[ "$(curl -sS -D "$ROOT_HEADERS" -o /dev/null -w '%{http_code}' -H "X-Local-Harness-Token: $TOKEN" "$BASE/")" == "200" ]]
# These assertions intentionally verify the authenticated loopback-only CSP;
# the production guard pins both host and exact ephemeral port.
/usr/bin/grep -Eq "connect-src 'self' ws://127\\.0\\.0\\.1:$PORT;" "$ROOT_HEADERS" # nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
assert_extended_pattern_absent 'ws://127\.0\.0\.1:\*' "$ROOT_HEADERS" # nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

COOKIE_JAR="$EVIDENCE_ROOT/cookies.txt"
BOOTSTRAP_HEADERS="$EVIDENCE_ROOT/bootstrap-headers.txt"
[[ "$(curl -sS -D "$BOOTSTRAP_HEADERS" -c "$COOKIE_JAR" -o /dev/null -w '%{http_code}' -H "X-Local-Harness-Token: $TOKEN" "$BASE/_local_harness/bootstrap")" == "303" ]]
/usr/bin/grep -Eiq 'Set-Cookie: LocalHarnessSession=.*HttpOnly; SameSite=Strict; Path=/' "$BOOTSTRAP_HEADERS"
[[ "$(curl -sS -b "$COOKIE_JAR" -o /dev/null -w '%{http_code}' "$BASE/")" == "200" ]]

stop_authenticated_runtime || { print -u2 "Authenticated runtime failed to stop."; exit 1; }
if (( SOURCE_STATE_SNAPSHOT_ENABLED )); then
  "$NODE" "$TREE_SNAPSHOT_HELPER" "$USER_DSH_HOME" "$SOURCE_STATE_AFTER"
  if ! /usr/bin/cmp -s "$SOURCE_STATE_BEFORE" "$SOURCE_STATE_AFTER"; then
    SUPPRESS_RUNTIME_FAILURE_DETAILS=1
    print -u2 "Existing Harness state changed during isolated runtime verification."
    exit 1
  fi
  print "Authenticated runtime verification passed against an isolated clone of existing Harness state."
else
  print "Authenticated runtime verification passed on an ephemeral port."
fi
