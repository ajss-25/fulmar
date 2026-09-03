import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  DSHCompatibilityError,
  EXPECTED_CONTEXT_WINDOW,
  EXPECTED_MAX_TOKENS,
  EXPECTED_MODEL,
  EXPECTED_PROVIDER,
  MCP_MAX_OUTPUT_BYTES,
  MCP_OUTPUT_PADDING_LENGTH,
  MCP_TOOL_NAME,
  TELEMETRY_MAXIMUM_RECORDS,
  UPSTREAM_MODEL,
  UPSTREAM_PROVIDER,
  assertBlankLocalSession,
  assertExactMCPProviderCallTopology,
  assertExactLocalDefault,
  assertFreshRuntimeState,
  assertLocalCatalog,
  assertMCPAllowedOutput,
  assertMCPToolAdvertisement,
  assertPerformanceTelemetryDocument,
  assertPerformanceTelemetryContentAbsent,
  hasSuccessfulWebFetchToolResult,
  hasCompletedFixtureTurn,
  localProviderProfile,
  providerFixtureBaseURL,
  providerFixtureSecurityEnvironment,
  turnEndCount
} from "../../scripts/verify-dsh-web-rpc-canary.mjs";

test("live approved-page evidence matches DSH's canonical fetch rendering", () => {
  const success = [{
    toolCallId: "call_web_fetch_1",
    content: "Fetched https://www.darkbloom.dev/ (HTTP 200)\n\nDarkBloom"
  }];
  assert.equal(hasSuccessfulWebFetchToolResult(success), true);
  assert.equal(hasSuccessfulWebFetchToolResult([{ content: "Status: 200" }]), false);
  assert.equal(hasSuccessfulWebFetchToolResult([{
    content: "Fetched https://www.darkbloom.dev/ (HTTP 301)"
  }]), false);
  assert.equal(hasSuccessfulWebFetchToolResult([{
    content: "Fetched https://example.com/ (HTTP 200)"
  }]), false);
});

test("the packaged client-bridge proof creates one browser-faithful Web Crypto realm", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes("crypto: Object.freeze({ randomUUID })"));
  assert.ok(source.includes("browserWindow.window = browserWindow;"));
  assert.ok(source.includes("window === globalThis && window.crypto === globalThis.crypto"));
  assert.ok(source.includes("typeof crypto.randomUUID === 'function'"));
  assert.match(
    source,
    /runInNewContext\(served\.toString\("utf8"\), browserWindow, \{/u
  );
  assert.doesNotMatch(
    source,
    /runInNewContext\(served\.toString\("utf8"\), \{\s*window:/u
  );
});

function settings(defaultValue = { provider: UPSTREAM_PROVIDER, model: UPSTREAM_MODEL }) {
  return {
    writable: true,
    hasDocument: true,
    namespaces: [
      {
        ns: "agent-default-model",
        schema: {},
        value: defaultValue,
        applies: "live",
        secrets: [],
        revision: 0
      },
      {
        ns: "llm-pi-ai",
        schema: {},
        value: { providers: {} },
        applies: "live",
        secrets: [],
        revision: 0
      }
    ]
  };
}

function expectCompatibilityFailure(action, pattern) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof DSHCompatibilityError);
    assert.match(error.message, pattern);
    return true;
  });
}

test("reviewed first-run profile exactly matches the native Ollama/Qwen bootstrap", () => {
  assert.deepEqual(localProviderProfile(), {
    apiKeyEnv: "OLLAMA_API_KEY",
    displayName: "Ollama (Local)",
    api: "openai-completions",
    baseURL: "http://127.0.0.1:11434/v1",
    reasoning: "off",
    compat: { maxTokensField: "max_tokens", supportsReasoningEffort: true },
    models: [{
      id: EXPECTED_MODEL,
      name: "Qwen 3.8 27B MLX (Local)",
      contextWindow: EXPECTED_CONTEXT_WINDOW,
      maxTokens: EXPECTED_MAX_TOKENS,
      input: ["text"],
      reasoningEfforts: { off: "none", high: "high" }
    }]
  });
});

test("provider fixture accepts only an exact ephemeral IPv4 loopback origin", () => {
  assert.equal(providerFixtureBaseURL("http://127.0.0.1:43127"), "http://127.0.0.1:43127/v1");
  assert.deepEqual(providerFixtureSecurityEnvironment(undefined), {
    ollamaHost: "127.0.0.1:11434",
    providerOrigins: []
  });
  assert.deepEqual(providerFixtureSecurityEnvironment({ origin: "http://127.0.0.1:43127" }), {
    ollamaHost: "127.0.0.1:43127",
    providerOrigins: [{ scheme: "http", host: "127.0.0.1", port: 43_127, boundary: "onDevice" }]
  });
  for (const origin of [
    "https://127.0.0.1:43127",
    "http://localhost:43127",
    "http://127.0.0.2:43127",
    "http://127.0.0.1",
    "http://127.0.0.1:43127/path",
    "https://api.deepseek.com"
  ]) {
    expectCompatibilityFailure(() => providerFixtureBaseURL(origin), /exact ephemeral IPv4 loopback origin/u);
  }
});

test("fixture completion ignores an earlier context-injection turn", () => {
  const contextOnly = {
    events: [
      { event: { type: "message", role: "system", content: "context injection" } },
      { event: { type: "turn/end" } }
    ]
  };
  const baseline = turnEndCount(contextOnly);
  assert.equal(baseline, 1);
  assert.equal(hasCompletedFixtureTurn(contextOnly, 0, "SIMULATED_SIMPLE_OK"), false);

  const responseWithoutEnd = {
    events: [...contextOnly.events, { event: { type: "message", role: "assistant", content: "SIMULATED_SIMPLE_OK" } }]
  };
  assert.equal(hasCompletedFixtureTurn(responseWithoutEnd, baseline, "SIMULATED_SIMPLE_OK"), false);

  const completed = {
    events: [...responseWithoutEnd.events, { event: { type: "turn/end" } }]
  };
  assert.equal(hasCompletedFixtureTurn(completed, baseline, "SIMULATED_SIMPLE_OK"), true);
  assert.equal(hasCompletedFixtureTurn(completed, baseline, "WRONG_MARKER"), false);
});

test("MCP call topology separates one title request from the exact request/result agent pair", () => {
  const agentRequest = { tools: [MCP_TOOL_NAME] };
  const title = { tools: [] };
  const agentResult = { tools: [MCP_TOOL_NAME], toolMessages: [{ toolCallId: "call", content: "bounded" }] };
  const denied = [agentRequest, title, agentResult];
  const allowed = [agentRequest, title, agentResult];
  const classified = assertExactMCPProviderCallTopology(denied, allowed);
  assert.deepEqual(classified.deniedRows, [agentRequest, agentResult]);
  assert.deepEqual(classified.allowedRows, [agentRequest, agentResult]);

  for (const malformed of [
    [agentRequest, agentResult],
    [agentRequest, title, title, agentResult],
    [agentRequest, { tools: [MCP_TOOL_NAME] }, agentResult],
    [agentRequest, { tools: [], toolMessages: [] }, agentResult]
  ]) {
    expectCompatibilityFailure(
      () => assertExactMCPProviderCallTopology(malformed, allowed),
      /exactly one title call plus one tool-request and one tool-result call/u
    );
  }
});

test("the isolated-port Qwen qualification admits only its exact attested loopback origin", async () => {
  const [source, fetcher] = await Promise.all([
    readFile(new URL("../../scripts/verify-dsh-qwen-route.sh", import.meta.url), "utf8"),
    readFile(new URL("../../scripts/attested-loopback-fetch.zsh", import.meta.url), "utf8")
  ]);
  assert.ok(source.includes("unsetopt BG_NICE"));
  assert.ok(source.includes('allocate-loopback-port.mjs" --exclude 11434'));
  assert.ok(source.includes('PROVIDER_ORIGINS="[{\\"scheme\\":\\"http\\",\\"host\\":\\"127.0.0.1\\",\\"port\\":$OLLAMA_PORT,\\"boundary\\":\\"onDevice\\"}]"'));
  assert.doesNotMatch(source, /http:\/\/127\.0\.0\.1:11434/u);
  assert.ok(source.includes('    LOCAL_HARNESS_PROVIDER_ORIGINS="$PROVIDER_ORIGINS" \\'));
  assert.doesNotMatch(source, /^    LOCAL_HARNESS_PROVIDER_ORIGINS='\[\]' \\$/mu);
  assert.ok(source.includes('bash)\n    MAX_SECONDS=240\n    PERFORMANCE_PROFILE="fast"\n    MODEL_CONTEXT_WINDOW=32768\n    MODEL_MAX_TOKENS=4096'));
  assert.ok(source.includes('Begin immediately with exactly one Bash tool call'));
  assert.ok(source.includes('filesystem)\n    MAX_SECONDS=240\n    PERFORMANCE_PROFILE="fast"\n    MODEL_CONTEXT_WINDOW=32768\n    MODEL_MAX_TOKENS=4096'));
  assert.ok(source.includes('Never claim success without the successful read-tool result.'));
  assert.ok(source.includes('project)\n    # A release canary must prove multi-file tool use'));
  assert.ok(source.includes('    PERFORMANCE_PROFILE="fast"\n    MODEL_CONTEXT_WINDOW=32768\n    MODEL_MAX_TOKENS=4096'));
  assert.ok(source.includes('Keep each file under 1 KiB.'));
  assert.ok(source.includes('Do not read back, edit, run Bash'));
  assert.ok(source.includes('Do not reason about or verify the result after the third write; immediately reply with exactly:'));
  assert.equal(source.match(/^    PERFORMANCE_PROFILE="fast"$/gmu)?.length, 4);
  assert.equal(source.match(/^    MODEL_CONTEXT_WINDOW=32768$/gmu)?.length, 4);
  assert.equal(source.match(/^    MODEL_MAX_TOKENS=4096$/gmu)?.length, 4);
  assert.match(source, /^    MAX_SECONDS=300$/mu);
  assert.ok(source.includes('First create game.js (under 4500 bytes)'));
  assert.ok(source.includes('Second create index.html (under 900 bytes)'));
  assert.ok(source.includes('Third create styles.css (under 1200 bytes)'));
  assert.ok(source.includes('Use no external assets, network APIs, Bash, reads, edits, sandbox escalation, or other files.'));
  assert.ok(source.includes('    LOCAL_HARNESS_PERFORMANCE_PROFILE="$PERFORMANCE_PROFILE" \\'));
  assert.ok(source.includes('Content-free project workspace shape:'));
  assert.ok(source.includes('verify-realistic-workspace.mjs'));
  assert.ok(source.includes('ProcessInfo.processInfo.thermalState'));
  assert.ok(source.includes('"mode":"eco"'));
  assert.ok(source.includes('THERMAL_ADMISSION_SAMPLES=5'));
  assert.ok(source.includes('THERMAL_ADMISSION_INTERVAL_SECONDS=2'));
  assert.ok(source.includes('require_stable_thermal_headroom'));
  assert.ok(source.includes('could not prove sustained nominal thermal headroom'));
  assert.ok(source.includes('ATTEMPT_LIMIT=$(( MAX_SECONDS * 4 ))'));
  assert.ok(source.includes('for ((attempt = 1; attempt <= ATTEMPT_LIMIT; attempt++)); do'));
  assert.ok(source.includes('THERMAL_POLL_COUNTDOWN=$(( THERMAL_POLL_COUNTDOWN - 1 ))'));
  assert.ok(source.includes('if (( THERMAL_POLL_COUNTDOWN == 0 )); then'));
  assert.ok(source.includes('if [[ "$thermal_state" -ge 1 ]]; then'));
  assert.doesNotMatch(source, /ROUTE_MODE.*realistic.*THERMAL_POLL_COUNTDOWN/u);
  assert.ok(source.includes('The Qwen canary stopped because macOS reported thermal pressure.'));
  assert.match(source, /"\$OLLAMA_PORT" \\\n\s+\/api\/version "\$TEST_ROOT\/ollama-version\.json" 1 256/u);
  assert.ok(fetcher.includes('--max-filesize "$maximum_bytes"'));
  assert.ok(source.includes('scripts/ollama-version-policy.mjs'));
  assert.ok(source.includes('--response "$TEST_ROOT/ollama-version.json"'));
  assert.ok(source.indexOf('api/version') < source.indexOf('api/tags'));
});

test("the app-owned Ollama generation gate is thermally bounded before and during model residency", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-app-owned-ollama-generation.sh", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes('ProcessInfo.processInfo.thermalState'));
  assert.ok(source.includes('THERMAL_ADMISSION_SAMPLES=5'));
  assert.ok(source.includes('THERMAL_ADMISSION_INTERVAL_SECONDS=2'));
  assert.ok(source.includes('require_stable_thermal_headroom'));
  assert.ok(source.includes('could not prove sustained nominal thermal headroom'));
  assert.ok(source.includes('THERMAL_POLL_COUNTDOWN=$(( THERMAL_POLL_COUNTDOWN - 1 ))'));
  assert.ok(source.includes('if (( THERMAL_POLL_COUNTDOWN == 0 )); then'));
  assert.ok(source.includes('if [[ "$thermal_state" -ge 1 ]]; then'));
  assert.ok(source.includes('THERMAL_ABORTED=1'));
  assert.ok(source.includes('exit 75'));
  assert.ok(source.includes('"ollamaVersion"'));
  assert.ok(source.includes('scripts/ollama-version-policy.mjs'));
  assert.ok(source.includes('--version "$EVIDENCE_VERSION"'));
});

test("native admission and both hardware gates share the reviewed Ollama version floor", async () => {
  const [policy, nativePolicy, client, app, generation, route] = await Promise.all([
    readFile(new URL("../../scripts/ollama-version-policy.mjs", import.meta.url), "utf8"),
    readFile(new URL("../../Sources/LocalHarness/OllamaVersionCompatibility.swift", import.meta.url), "utf8"),
    readFile(new URL("../../Sources/LocalHarness/OllamaClient.swift", import.meta.url), "utf8"),
    readFile(new URL("../../Sources/LocalHarness/LocalHarnessApp.swift", import.meta.url), "utf8"),
    readFile(new URL("../../Sources/LocalHarness/AppOwnedOllamaGenerationCanary.swift", import.meta.url), "utf8"),
    readFile(new URL("../../scripts/verify-dsh-qwen-route.sh", import.meta.url), "utf8")
  ]);
  assert.match(policy, /minimumOllamaVersion = "0\.33\.2"/u);
  assert.match(policy, /testedOllamaVersion = "0\.33\.2"/u);
  assert.match(policy, /qualifiedOllamaSeries = "0\.33\.x"/u);
  assert.match(policy, /actual\.major !== minimum\.major \|\| actual\.minor !== minimum\.minor/u);
  assert.match(nativePolicy, /static let minimum[\s\S]*rawValue: "0\.33\.2"/u);
  assert.match(nativePolicy, /rawValue: "0\.33\.2"/u);
  assert.match(nativePolicy, /static let qualifiedSeries = "0\.33\.x"/u);
  assert.match(nativePolicy, /case newerUnqualified\(actual: String, qualifiedSeries: String\)/u);
  assert.match(nativePolicy, /version\.major == minimum\.major,[\s\S]*version\.minor == minimum\.minor/u);
  assert.match(client, /get\(path: "api\/version", maximumBytes: OllamaVersionCompatibilityPolicy\.maximumResponseBytes\)/u);
  assert.match(app, /validateLocalRuntimeVersion[\s\S]*fetchCompatibleVersion\(\)[\s\S]*inspectInstalledLocalModels/u);
  assert.match(generation, /versionURL[\s\S]*parseResponse[\s\S]*tagsURL/u);
  assert.match(route, /api\/version[\s\S]*ollama-version-policy\.mjs[\s\S]*api\/tags/u);
});

test("qualified Qwen identity matches Ollama's raw tags digest across native and hardware gates", async () => {
  const expected = "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e";
  const [providerModels, generationGate, routeGate] = await Promise.all([
    readFile(new URL("../../Sources/LocalHarness/ProviderModels.swift", import.meta.url), "utf8"),
    readFile(new URL("../../scripts/verify-app-owned-ollama-generation.sh", import.meta.url), "utf8"),
    readFile(new URL("../../scripts/verify-dsh-qwen-route.sh", import.meta.url), "utf8")
  ]);

  assert.match(providerModels, new RegExp(`qwenLocalModelManifestDigest = "${expected}"`, "u"));
  for (const gate of [generationGate, routeGate]) {
    assert.match(gate, new RegExp(`EXPECTED_MANIFEST_DIGEST="${expected}"`, "u"));
    assert.doesNotMatch(gate, new RegExp(`sha256:${expected}`, "u"));
  }
});

test("deterministic fixtures are bound before the first session snapshot", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  const typed = source.slice(
    source.indexOf("async function runTypedCompatibility"),
    source.indexOf("async function waitForMCPApproval")
  );
  const mcp = source.slice(
    source.indexOf("async function runMCPCompatibility"),
    source.indexOf("async function assertEphemeralArtifacts")
  );
  for (const section of [typed, mcp]) {
    const fixture = section.indexOf("providerFixtureBaseURL(state.provider.ready.origin)");
    const restart = section.indexOf("restartCandidateHarness");
    const session = section.indexOf("client.sessions.create");
    assert.ok(fixture >= 0 && restart >= 0 && session >= 0 && fixture < restart && restart < session);
  }
});

test("the installed-bundle MCP canary keeps its reviewed command under a private root", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes('const serverRuntimePath = path.join(state.workspace, "reviewed-mcp-node")'));
  assert.ok(source.includes("await copyFile(layout.node, serverRuntimePath)"));
  assert.ok(source.includes("await chmod(serverRuntimePath, 0o700)"));
  assert.ok(source.includes("auditedMCPFile(serverRuntimePath, true, core)"));
  assert.doesNotMatch(source, /auditedMCPFile\(layout\.node, true, core\)/u);
});

test("the web canary requires the exact private adaptive thermal control plane", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes("LOCAL_HARNESS_THERMAL_POLICY_FILE: state.thermalPolicyFile"));
  assert.ok(source.includes('"thermal-workload-policy.json"'));
  assert.ok(source.includes('thermalPolicy.mode !== "normal"'));
  assert.ok(source.includes("thermalPolicy.ecoMaxOutputTokens !== 2_048"));
  assert.ok(source.includes("thermalPolicy.minimumDelayMilliseconds !== 5_000"));
  assert.ok(source.includes("assertPerformanceTelemetryContentAbsent(thermalPolicyBytes)"));
});

test("the web canary launches authenticated runtimes through one-shot stdin", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes("openRuntimeAuthenticationInput(authentication.token, authentication.nonce)"));
  assert.ok(source.includes('stdio: [authenticationInput, "pipe", stderrLog.fd]'));
  assert.ok(source.includes("closeSync(authenticationInput)"));
  assert.doesNotMatch(source, /LOCAL_HARNESS_(?:AUTH_TOKEN|INSTANCE_NONCE):\s*state\./u);
});

test("the web canary proves a max-token turn continues without another user prompt", async () => {
  const [canary, provider] = await Promise.all([
    readFile(new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url), "utf8"),
    readFile(new URL("../../scripts/simulated-openai-provider.mjs", import.meta.url), "utf8")
  ]);
  assert.ok(provider.includes('text.includes("CONTRACT_AUTO_CONTINUE")'));
  assert.ok(provider.includes('"SIMULATED_AUTOCONTINUE_PARTIAL" }], "length"'));
  assert.ok(provider.includes('text.includes("Continue the unfinished user task from exactly where the previous response stopped.")'));
  assert.ok(canary.includes('automaticTurnEnds.length !== 2'));
  assert.ok(canary.includes('reason?.kind !== "max-tokens"'));
  assert.ok(canary.includes('source?.plugin === "fulmar-automatic-continuation"'));
  assert.ok(canary.includes('summary !== "Fulmar continued automatically · 1/12"'));
});

test("the web canary forbids Keychain access for the exact local Ollama route", async () => {
  const source = await readFile(
    new URL("../../scripts/verify-dsh-web-rpc-canary.mjs", import.meta.url),
    "utf8"
  );
  assert.ok(source.includes('subject === "OLLAMA_API_KEY"'));
  assert.ok(source.includes("isolated local route touched Keychain"));
  assert.ok(source.includes('helperLogInfo === undefined ? ""'));
  assert.doesNotMatch(source, /helperRows\.length === 0/u);
  assert.doesNotMatch(source, /!helperRows\.some\(\(\[command, subject\]\) => command === "get" && subject === "OLLAMA_API_KEY"\)/u);
});

test("fresh-state assertion requires the pinned upstream default and zero sessions", () => {
  const initial = assertFreshRuntimeState(settings(), { items: [] }, false);
  assert.equal(initial.ns, "agent-default-model");
  expectCompatibilityFailure(
    () => assertFreshRuntimeState(settings(), { items: [{ sessionId: "old" }] }, false),
    /contained a session/u
  );
  expectCompatibilityFailure(
    () => assertFreshRuntimeState(settings(), { items: [] }, true),
    /was not clean/u
  );
  expectCompatibilityFailure(
    () => assertFreshRuntimeState(settings({ provider: "ollama", model: EXPECTED_MODEL }), { items: [] }, false),
    /clean pinned DSH default/u
  );
});

test("fresh-state assertion fails closed for missing, duplicate, or read-only namespaces", () => {
  const missing = settings();
  missing.namespaces = missing.namespaces.filter((entry) => entry.ns !== "llm-pi-ai");
  expectCompatibilityFailure(() => assertFreshRuntimeState(missing, { items: [] }, false), /llm-pi-ai/u);

  const duplicate = settings();
  duplicate.namespaces.push({ ...duplicate.namespaces[0] });
  expectCompatibilityFailure(() => assertFreshRuntimeState(duplicate, { items: [] }, false), /2 .*agent-default-model/u);

  const readOnly = settings();
  readOnly.writable = false;
  expectCompatibilityFailure(() => assertFreshRuntimeState(readOnly, { items: [] }, false), /writable/u);
});

test("exact default assertion rejects wrong routes and stale reasoning", () => {
  assert.doesNotThrow(() => assertExactLocalDefault({
    ns: "agent-default-model",
    value: { provider: EXPECTED_PROVIDER, model: EXPECTED_MODEL }
  }));
  expectCompatibilityFailure(() => assertExactLocalDefault({
    ns: "agent-default-model",
    value: { provider: "deepseek-official", model: EXPECTED_MODEL }
  }), /did not retain/u);
  expectCompatibilityFailure(() => assertExactLocalDefault({
    ns: "agent-default-model",
    value: { provider: EXPECTED_PROVIDER, model: EXPECTED_MODEL, reasoningEffort: "high" }
  }), /reasoning effort/u);
});

test("provider/model catalog assertion requires one active exact route with no failure", () => {
  const directory = { providers: [{
    provider: EXPECTED_PROVIDER,
    displayName: "Ollama (Local)",
    settingsNs: "llm-pi-ai",
    settingsPath: ["providers", EXPECTED_PROVIDER],
    active: true
  }] };
  const catalog = {
    groups: [{ id: EXPECTED_PROVIDER, name: "Ollama (Local)", models: [{ id: EXPECTED_MODEL, name: "Qwen" }] }],
    failures: []
  };
  assert.doesNotThrow(() => assertLocalCatalog(directory, catalog));
  expectCompatibilityFailure(
    () => assertLocalCatalog({ providers: [{ ...directory.providers[0], active: false }] }, catalog),
    /not active/u
  );
  expectCompatibilityFailure(
    () => assertLocalCatalog(directory, { ...catalog, groups: [] }),
    /0 exact Qwen routes/u
  );
  expectCompatibilityFailure(
    () => assertLocalCatalog(directory, { ...catalog, failures: [{ id: EXPECTED_PROVIDER, message: "drift" }] }),
    /catalog failure/u
  );
});

test("first-session assertion requires exact route, routability, and blank idle state", () => {
  const models = { current: { provider: EXPECTED_PROVIDER, model: EXPECTED_MODEL }, routable: true };
  const summary = { blank: true, running: false };
  assert.doesNotThrow(() => assertBlankLocalSession(models, summary));
  expectCompatibilityFailure(
    () => assertBlankLocalSession({ ...models, routable: false }, summary),
    /unroutable/u
  );
  expectCompatibilityFailure(
    () => assertBlankLocalSession(models, { blank: false, running: false }),
    /not a stopped blank session/u
  );
});

test("MCP advertisement assertion pins namespace, schema, and distinct subprocess identities", () => {
  const guardPID = process.pid + 10_000;
  const serverPID = process.pid + 10_001;
  const tool = {
    name: MCP_TOOL_NAME,
    description: `Fulmar inert MCP canary; server_pid=${serverPID}; guard_pid=${guardPID}`,
    parameters: { type: "object", properties: {}, additionalProperties: false }
  };
  assert.deepEqual(assertMCPToolAdvertisement(tool), { serverPID, guardPID });
  expectCompatibilityFailure(
    () => assertMCPToolAdvertisement({ ...tool, name: "mcp__shadow__security_canary" }),
    /exact reviewed MCP tool namespace/u
  );
  expectCompatibilityFailure(
    () => assertMCPToolAdvertisement({ ...tool, parameters: { type: "object", additionalProperties: true } }),
    /changed input schema/u
  );
  expectCompatibilityFailure(
    () => assertMCPToolAdvertisement({ ...tool, description: "Fulmar inert MCP canary; server_pid=7; guard_pid=7" }),
    /distinct exact subprocess identities/u
  );
});

test("MCP allowed-output assertion requires one execution and the reviewed byte bound", () => {
  const subprocesses = { serverPID: process.pid + 10_001, guardPID: process.pid + 10_000 };
  const output = `MCP_ALLOWED_ONCE_OK|call_count=1|server_pid=${subprocesses.serverPID}|guard_pid=${subprocesses.guardPID}|padding=${"x".repeat(MCP_OUTPUT_PADDING_LENGTH)}`;
  const bytes = assertMCPAllowedOutput(output, subprocesses);
  assert.ok(bytes > MCP_OUTPUT_PADDING_LENGTH);
  assert.ok(bytes <= MCP_MAX_OUTPUT_BYTES);
  expectCompatibilityFailure(
    () => assertMCPAllowedOutput(output.replace("call_count=1", "call_count=2"), subprocesses),
    /one-call count/u
  );
  expectCompatibilityFailure(
    () => assertMCPAllowedOutput(`${output}x`, subprocesses),
    /reviewed bounded payload/u
  );
});

test("performance telemetry assertion accepts only the exact content-free bounded schema", () => {
  const record = {
    schemaVersion: 1,
    id: "12345678-1234-4abc-8def-1234567890ab",
    provider: EXPECTED_PROVIDER,
    model: EXPECTED_MODEL,
    profile: null,
    startedAtMilliseconds: 1_000,
    completedAtMilliseconds: 1_125,
    firstTokenAtMilliseconds: 1_025,
    elapsedMilliseconds: 125,
    outputTokens: 8,
    outputTokenCountSource: "estimated",
    outcome: "completed",
    failureCategory: null
  };
  assert.equal(assertPerformanceTelemetryDocument({ schemaVersion: 1, records: [record] }), 1);
  assert.doesNotThrow(() => assertPerformanceTelemetryContentAbsent(Buffer.from(JSON.stringify({ schemaVersion: 1, records: [record] }))));
  expectCompatibilityFailure(
    () => assertPerformanceTelemetryDocument({ schemaVersion: 1, records: [] }),
    /bounded document schema/u
  );
  expectCompatibilityFailure(
    () => assertPerformanceTelemetryDocument({ schemaVersion: 1, records: [{ ...record, prompt: "private" }] }),
    /invalid, content-shaped/u
  );
  expectCompatibilityFailure(
    () => assertPerformanceTelemetryDocument({ schemaVersion: 1, records: Array(TELEMETRY_MAXIMUM_RECORDS + 1).fill(record) }),
    /bounded document schema/u
  );
  expectCompatibilityFailure(
    () => assertPerformanceTelemetryDocument({ schemaVersion: 1, records: [{ ...record, provider: "deepseek-official" }] }),
    /wrong-route record/u
  );
  expectCompatibilityFailure(
    () => assertPerformanceTelemetryContentAbsent(`{"records":[],"leak":"${"SIMULATED_SIMPLE_OK"}"}`),
    /retained private turn content marker/u
  );
});
