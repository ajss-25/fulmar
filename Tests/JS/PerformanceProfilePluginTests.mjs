import assert from "node:assert/strict";
import test from "node:test";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  apply,
  LOCAL_POST_TOOL_OUTPUT_TOKENS,
  createAutomaticContinuationController,
  createNativeTelemetryLockTransaction,
  createThermalWorkloadController,
  createPerformanceTelemetryRecorder,
  createPerformanceLimiter,
  decodeTelemetryFile,
  decodePerformanceEnvironment,
  decodeThermalPolicyStorage,
  inject,
  observePerformanceStream,
  observeThermalWorkloadStream,
  readThermalPolicy,
  taggedPerformanceProfile
} from "../../Resources/DSHPlugins/performance-profile/index.mjs";

const catalog = JSON.stringify({
  fast: { maxOutputTokens: 4_096 },
  balanced: { maxOutputTokens: 8_192 },
  deep: { maxOutputTokens: 16_384 }
});

function configuration(
  selected = "balanced",
  profiles = catalog,
  contextEnforcement,
  activeProvider = contextEnforcement?.provider
) {
  return decodePerformanceEnvironment({
    LOCAL_HARNESS_PERFORMANCE_PROFILE: selected,
    LOCAL_HARNESS_PERFORMANCE_PROFILES: profiles,
    ...(activeProvider === undefined ? {} : { LOCAL_HARNESS_ACTIVE_PROVIDER: activeProvider }),
    ...(contextEnforcement === undefined
      ? {}
      : { LOCAL_HARNESS_CONTEXT_ENFORCEMENT: JSON.stringify(contextEnforcement) })
  });
}

function session(profile, suffix = "00000000-0000-4000-8000-000000000001", parentSession) {
  return {
    id: `local-harness-performance-v1-${profile}-${suffix}`,
    session: { header: parentSession === undefined ? {} : { parentSession } }
  };
}

function continuationAgent({ origin } = {}) {
  const id = `continuation-${randomUUID()}`;
  const liveSession = { id, header: origin === undefined ? {} : { origin } };
  const messages = [];
  const agent = {
    id,
    session: liveSession,
    status: "running",
    inbox: { nextTurn: [], nextStep: [] },
    followup(message) { messages.push(message); }
  };
  return { agent, session: liveSession, messages };
}

test("automatically continues a max-token foreground turn through an identified Fulmar notice", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({
    maximumContinuations: 3,
    schedule: (operation) => scheduled.push(operation)
  });
  const fixture = continuationAgent();
  controller.created(fixture.agent);
  controller.requested(
    { agent: fixture.agent, turn: 7 },
    { provider: "ollama", model: "qwen" }
  );

  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end",
    data: { turn: 7, reason: { kind: "max-tokens" } }
  }), true);
  assert.equal(controller.state(fixture.agent).pendingContinuation, true);
  assert.equal(controller.state(fixture.agent).scheduled, false);
  assert.equal(fixture.messages.length, 0);
  assert.equal(scheduled.length, 0);

  fixture.agent.status = "idle";
  assert.equal(controller.status(fixture.agent, "idle"), true);
  assert.equal(controller.state(fixture.agent).scheduled, true);

  scheduled.shift()();
  assert.equal(fixture.messages.length, 1);
  const message = fixture.messages[0];
  assert.match(message.id, /^[0-9a-f-]{36}$/u);
  assert.equal(message.role, "user");
  assert.deepEqual(message.source, {
    kind: "plugin",
    plugin: "fulmar-automatic-continuation",
    form: "notice",
    summary: "Fulmar continued automatically · 1/3"
  });
  assert.match(message.content[0].text, /tool call or file edit was cut off/u);
  assert.equal(Object.isFrozen(message), true);
  assert.equal(Object.isFrozen(message.content), true);
  assert.equal(controller.state(fixture.agent).continuations, 1);

  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end",
    data: { turn: 7, reason: { kind: "max-tokens" } }
  }), false);
  assert.equal(scheduled.length, 0);
  assert.equal(fixture.messages.length, 1);
});

test("automatic continuation is bounded, yields to queued user work, and emits a final safety summary turn", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({
    maximumContinuations: 2,
    schedule: (operation) => scheduled.push(operation)
  });
  const fixture = continuationAgent();
  controller.created(fixture.agent);

  fixture.agent.inbox.nextTurn.push({ id: "queued-user" });
  controller.requested({ agent: fixture.agent, turn: 1 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), false);
  assert.equal(scheduled.length, 0);
  fixture.agent.inbox.nextTurn.length = 0;

  for (const turn of [2, 3, 4]) {
    fixture.agent.status = "running";
    controller.requested({ agent: fixture.agent, turn }, { provider: "ollama", model: "qwen" });
    assert.equal(controller.sessionEvent(fixture.session, {
      type: "turn/end", data: { turn, reason: { kind: "max-tokens" } }
    }), true);
    fixture.agent.status = "idle";
    assert.equal(controller.status(fixture.agent, "idle"), true);
    scheduled.shift()();
  }
  assert.equal(fixture.messages.length, 3);
  assert.match(fixture.messages[2].source.summary, /safety limit/u);
  assert.match(fixture.messages[2].content[0].text, /Do not start more tool work/u);

  controller.requested({ agent: fixture.agent, turn: 5 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 5, reason: { kind: "max-tokens" } }
  }), false);
  assert.equal(scheduled.length, 0);

  controller.sessionEvent(fixture.session, {
    type: "user/message",
    data: { source: { kind: "user" } }
  });
  assert.equal(controller.state(fixture.agent).continuations, 0);
  assert.equal(controller.state(fixture.agent).budgetNoticeQueued, false);
});

test("automatic continuation never takes ownership of subagent settlement or an unobserved turn", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({ schedule: (operation) => scheduled.push(operation) });
  const child = continuationAgent({ origin: "subagent" });
  controller.created(child.agent);
  controller.requested({ agent: child.agent, turn: 1 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(child.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), false);

  const root = continuationAgent();
  controller.created(root.agent);
  assert.equal(controller.sessionEvent(root.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), false);
  assert.equal(scheduled.length, 0);
  controller.disposed(root.agent);
  assert.equal(controller.state(root.agent), undefined);
});

test("turn-end publication still continues when DSH has already published idle", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({
    schedule: (operation) => scheduled.push(operation)
  });
  const fixture = continuationAgent();
  controller.created(fixture.agent);
  controller.requested({ agent: fixture.agent, turn: 1 }, { provider: "ollama", model: "qwen" });

  fixture.agent.status = "idle";
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), true);
  assert.equal(scheduled.length, 1);
  assert.equal(controller.state(fixture.agent).scheduled, true);

  scheduled.shift()();
  assert.equal(fixture.messages.length, 1);
  assert.equal(fixture.messages[0].source.summary, "Fulmar continued automatically · 1/12");
  assert.equal(controller.status(fixture.agent, "idle"), false);
});

test("a user message arriving after idle publication wins over a staged automatic continuation", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({
    schedule: (operation) => scheduled.push(operation)
  });
  const fixture = continuationAgent();
  controller.created(fixture.agent);
  controller.requested({ agent: fixture.agent, turn: 1 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), true);
  fixture.agent.status = "idle";
  assert.equal(controller.status(fixture.agent, "idle"), true);

  fixture.agent.inbox.nextTurn.push({ id: "new-user-work" });
  fixture.agent.status = "running";
  scheduled.shift()();
  assert.equal(fixture.messages.length, 0);
  assert.equal(controller.state(fixture.agent).pendingContinuation, false);
  assert.equal(controller.state(fixture.agent).scheduled, false);
});

test("a durable user turn invalidates a published continuation without letting its stale callback clobber later work", () => {
  const scheduled = [];
  const controller = createAutomaticContinuationController({
    schedule: (operation) => scheduled.push(operation)
  });
  const fixture = continuationAgent();
  controller.created(fixture.agent);

  controller.requested({ agent: fixture.agent, turn: 1 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 1, reason: { kind: "max-tokens" } }
  }), true);
  fixture.agent.status = "idle";
  assert.equal(controller.status(fixture.agent, "idle"), true);

  // The inbox can already be drained by the time the durable user/message is
  // delivered, so status and pendingWork alone are not sufficient ownership
  // checks. The exact user source must revoke the staged plugin follow-up.
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "user/message", data: { source: { kind: "user" } }
  }), false);
  assert.equal(controller.state(fixture.agent).pendingContinuation, false);
  assert.equal(controller.state(fixture.agent).scheduled, false);

  fixture.agent.status = "running";
  controller.requested({ agent: fixture.agent, turn: 2 }, { provider: "ollama", model: "qwen" });
  assert.equal(controller.sessionEvent(fixture.session, {
    type: "turn/end", data: { turn: 2, reason: { kind: "max-tokens" } }
  }), true);
  fixture.agent.status = "idle";
  assert.equal(controller.status(fixture.agent, "idle"), true);
  assert.equal(scheduled.length, 2);

  scheduled.shift()();
  assert.equal(fixture.messages.length, 0);
  assert.equal(controller.state(fixture.agent).pendingContinuation, true);
  assert.equal(controller.state(fixture.agent).scheduled, true);

  scheduled.shift()();
  assert.equal(fixture.messages.length, 1);
  assert.equal(fixture.messages[0].source.summary, "Fulmar continued automatically · 1/12");
});

test("decodes the exact native catalog and freezes its values", () => {
  const decoded = configuration("deep");
  assert.equal(decoded.defaultProfile, "deep");
  assert.deepEqual(decoded.profiles.deep, {
    maxOutputTokens: 16_384
  });
  assert.equal(Object.isFrozen(decoded), true);
  assert.equal(Object.isFrozen(decoded.profiles), true);
  assert.equal(Object.isFrozen(decoded.profiles.deep), true);
});

test("rejects malformed, partial, excessive, and inconsistent native limits", () => {
  const invalidCatalogs = [
    "not-json",
    "[]",
    "{}",
    JSON.stringify({ fast: {} }),
    JSON.stringify({ fast: { maxOutputTokens: 2_048, extra: true } }),
    JSON.stringify({ fast: { maxOutputTokens: 255 } }),
    JSON.stringify({ fast: { maxOutputTokens: 65_537 } }),
    JSON.stringify({ "BAD profile": { maxOutputTokens: 2_048 } })
  ];
  for (const profiles of invalidCatalogs) {
    assert.throws(() => configuration("fast", profiles), /configuration is invalid/);
  }
  assert.throws(() => configuration("missing"), /absent from the catalog/);
});

test("recognizes only canonical performance-bound session identities", () => {
  const tagged = "local-harness-performance-v1-fast-00000000-0000-4000-8000-000000000001";
  assert.equal(taggedPerformanceProfile(tagged), "fast");
  assert.equal(taggedPerformanceProfile(tagged.toUpperCase()), undefined);
  assert.equal(taggedPerformanceProfile(`${tagged}-suffix`), undefined);
  assert.equal(taggedPerformanceProfile("ordinary-session"), undefined);
});

test("applies the selected per-session maxTokens only to the exact synchronized local route", async () => {
  const route = { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 };
  const limiter = createPerformanceLimiter(
    configuration("balanced", catalog, route),
    async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 32_768 } })
  );
  const agent = session("deep");
  const upstream = Object.freeze({ provider: "ollama", model: "qwen", maxTokens: 512 });
  const result = await limiter.request({ agent }, async () => upstream);
  assert.deepEqual(result, {
    provider: "ollama",
    model: "qwen",
    maxTokens: 16_384
  });
  assert.deepEqual(upstream, { provider: "ollama", model: "qwen", maxTokens: 512 });
  assert.deepEqual(limiter.profileFor(agent), {
    name: "deep",
    maxOutputTokens: 16_384
  });
});

test("bounds only same-turn local requests after a completed tool result", async () => {
  const route = { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 };
  const limiter = createPerformanceLimiter(
    configuration("balanced", catalog, route),
    async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 32_768 } })
  );
  const agent = session("balanced");
  limiter.created(agent);

  const initial = await limiter.request(
    { agent, turn: 4, step: 0 },
    async () => ({ provider: "ollama", model: "qwen", maxTokens: 8_192 })
  );
  assert.equal(initial.maxTokens, 8_192);

  limiter.sessionEvent(agent.session, {
    type: "tool/result",
    data: { turn: 4, step: 0 }
  });
  const postTool = await limiter.request(
    { agent, turn: 4, step: 1 },
    async () => ({ provider: "ollama", model: "qwen", maxTokens: 8_192 })
  );
  assert.equal(postTool.maxTokens, LOCAL_POST_TOOL_OUTPUT_TOKENS);

  const laterTurn = await limiter.request(
    { agent, turn: 5, step: 0 },
    async () => ({ provider: "ollama", model: "qwen", maxTokens: 8_192 })
  );
  assert.equal(laterTurn.maxTokens, 8_192);

  limiter.sessionEvent(agent.session, {
    type: "turn/end",
    data: { turn: 4, reason: { kind: "completed" } }
  });
  const staleTurn = await limiter.request(
    { agent, turn: 4, step: 2 },
    async () => ({ provider: "ollama", model: "qwen", maxTokens: 8_192 })
  );
  assert.equal(staleTurn.maxTokens, 8_192);
});

test("never applies the local post-tool cap to a cloud provider", async () => {
  const limiter = createPerformanceLimiter(configuration("deep", catalog, undefined, "deepseek"));
  const agent = session("deep");
  limiter.created(agent);
  limiter.sessionEvent(agent.session, {
    type: "tool/result",
    data: { turn: 1, step: 0 }
  });
  const cloud = Object.freeze({
    provider: "deepseek",
    model: "deepseek-chat",
    maxTokens: 16_384
  });
  assert.equal(await limiter.request({ agent, turn: 1, step: 1 }, async () => cloud), cloud);
});

test("validates the exact context-enforcement route independently from per-session output", () => {
  const route = { provider: "ollama", model: "qwen3.8:27b-mlx", contextWindowTokens: 32_768 };
  const decoded = configuration("balanced", catalog, route);
  assert.deepEqual(decoded.contextEnforcement, route);
  assert.equal(Object.isFrozen(decoded.contextEnforcement), true);

  const invalid = [
    "not-json",
    "{}",
    JSON.stringify({ provider: "", model: "qwen", contextWindowTokens: 32_768 }),
    JSON.stringify({ provider: "ollama", model: "", contextWindowTokens: 32_768 }),
    JSON.stringify({ provider: "ollama", model: "qwen", contextWindowTokens: 1_023 }),
    JSON.stringify({ provider: "ollama", model: "qwen", contextWindowTokens: 32_768, extra: true })
  ];
  for (const value of invalid) {
    assert.throws(() => decodePerformanceEnvironment({
      LOCAL_HARNESS_PERFORMANCE_PROFILE: "balanced",
      LOCAL_HARNESS_PERFORMANCE_PROFILES: catalog,
      LOCAL_HARNESS_ACTIVE_PROVIDER: "ollama",
      LOCAL_HARNESS_CONTEXT_ENFORCEMENT: value
    }), /configuration is invalid/);
  }
  assert.throws(
    () => configuration("balanced", catalog, route, "another-provider"),
    /does not match the active provider/
  );
  assert.throws(
    () => configuration("balanced", catalog, undefined, "bad\nprovider"),
    /active provider is malformed/
  );
});

test("resolves DSH exact-model context before admitting the real agent request", async () => {
  const enforcement = { provider: "ollama", model: "qwen3.8:27b-mlx", contextWindowTokens: 32_768 };
  const calls = [];
  const signal = new AbortController().signal;
  const limiter = createPerformanceLimiter(
    configuration("balanced", catalog, enforcement),
    async (provider, model, receivedSignal) => {
      calls.push({ provider, model, signal: receivedSignal });
      return { provider, id: model, context: { contextWindow: 32_768 } };
    }
  );
  const result = await limiter.request(
    { agent: session("deep"), signal },
    async () => ({ provider: "ollama", model: "qwen3.8:27b-mlx" })
  );
  assert.equal(result.maxTokens, 16_384);
  assert.deepEqual(calls, [{ provider: "ollama", model: "qwen3.8:27b-mlx", signal }]);

  await assert.rejects(
    createPerformanceLimiter(
      configuration("balanced", catalog, enforcement),
      async (provider, model) => ({ provider, id: model, context: { contextWindow: 65_536 } })
    ).request(
      { agent: session("balanced") },
      async () => ({ provider: "ollama", model: "qwen3.8:27b-mlx" })
    ),
    /unexpected context capacity/
  );

  for (const [staleRoute, message] of [
    [
      { provider: "ollama", model: "another-local-model" },
      /runtime is locked to ollama\/qwen3\.8:27b-mlx/
    ],
    [
      { provider: "openai", model: "cloud-model" },
      /runtime is locked to provider ollama/
    ]
  ]) {
    await assert.rejects(
      limiter.request(
        { agent: session("balanced", randomUUID()) },
        async () => staleRoute
      ),
      message
    );
  }
});

test("production apply wires DSH model resolution into the agent request boundary", async () => {
  const previous = {
    profile: process.env.LOCAL_HARNESS_PERFORMANCE_PROFILE,
    profiles: process.env.LOCAL_HARNESS_PERFORMANCE_PROFILES,
    activeProvider: process.env.LOCAL_HARNESS_ACTIVE_PROVIDER,
    context: process.env.LOCAL_HARNESS_CONTEXT_ENFORCEMENT
  };
  process.env.LOCAL_HARNESS_PERFORMANCE_PROFILE = "fast";
  process.env.LOCAL_HARNESS_PERFORMANCE_PROFILES = catalog;
  process.env.LOCAL_HARNESS_ACTIVE_PROVIDER = "ollama";
  process.env.LOCAL_HARNESS_CONTEXT_ENFORCEMENT = JSON.stringify({
    provider: "ollama", model: "qwen3.8:27b-mlx", contextWindowTokens: 16_384
  });
  const listeners = new Map();
  const listenerOptions = new Map();
  const calls = [];
  try {
    apply({
      llm: {
        async resolveModelInfo(provider, model, signal) {
          calls.push({ provider, model, signal });
          return { provider, id: model, context: { contextWindow: 16_384 } };
        }
      },
      on(event, listener, options) {
        listeners.set(event, listener);
        listenerOptions.set(event, options);
      }
    });
    assert.deepEqual(inject, ["llm"]);
    for (const event of ["agent/created", "agent/disposed", "agent/status", "agent/request", "session/event"]) {
      assert.deepEqual(listenerOptions.get(event), { global: true });
    }
    const signal = new AbortController().signal;
    const result = await listeners.get("agent/request")(
      { agent: session("fast"), signal },
      async () => ({ provider: "ollama", model: "qwen3.8:27b-mlx" })
    );
    assert.equal(result.maxTokens, 4_096);
    assert.deepEqual(calls, [{ provider: "ollama", model: "qwen3.8:27b-mlx", signal }]);
  } finally {
    for (const [key, value] of Object.entries({
      LOCAL_HARNESS_PERFORMANCE_PROFILE: previous.profile,
      LOCAL_HARNESS_PERFORMANCE_PROFILES: previous.profiles,
      LOCAL_HARNESS_ACTIVE_PROVIDER: previous.activeProvider,
      LOCAL_HARNESS_CONTEXT_ENFORCEMENT: previous.context
    })) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("production stream telemetry observes child agent scopes globally", async () => {
  const source = await readFile(
    new URL("../../Resources/DSHPlugins/performance-profile/index.mjs", import.meta.url),
    "utf8"
  );
  assert.match(
    source,
    /ctx\.on\("llm\/stream",[\s\S]*?\{ global: true \}\);/u
  );
});

test("uses the native default for legacy and ordinary Harness sessions", async () => {
  const route = { provider: "ollama", model: "qwen", contextWindowTokens: 16_384 };
  const limiter = createPerformanceLimiter(
    configuration("fast", catalog, route),
    async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 16_384 } })
  );
  const agent = { id: "legacy-session", session: { header: {} } };
  const result = await limiter.request({ agent }, async () => ({ provider: "ollama", model: "qwen" }));
  assert.equal(result.maxTokens, 4_096);
  assert.equal(limiter.profileFor(agent).name, "fast");
});

test("subagents and forks inherit their parent's exact performance profile", async () => {
  const route = { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 };
  const limiter = createPerformanceLimiter(
    configuration("balanced", catalog, route),
    async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 32_768 } })
  );
  const parent = session("deep");
  limiter.created(parent);

  const child = {
    id: "subagent-one",
    session: { header: { parentSession: parent.id } }
  };
  limiter.created(child);
  const nested = {
    id: "subagent-two",
    session: { header: { parentSession: child.id } }
  };
  const result = await limiter.request({ agent: nested }, async () => ({ provider: "ollama", model: "qwen" }));
  assert.equal(result.maxTokens, 16_384);
  assert.equal(limiter.profileFor(child).name, "deep");
  assert.equal(limiter.profileFor(nested).name, "deep");
});

test("unknown profile tags cannot select an unreviewed cap", async () => {
  const route = { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 };
  const limiter = createPerformanceLimiter(
    configuration("balanced", catalog, route),
    async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 32_768 } })
  );
  const agent = session("unreviewed");
  const result = await limiter.request({ agent }, async () => ({ provider: "ollama", model: "qwen" }));
  assert.equal(result.maxTokens, 8_192);
  assert.equal(limiter.profileFor(agent).name, "balanced");
});

test("disposed sessions release process-local profile state", () => {
  const limiter = createPerformanceLimiter(configuration());
  const agent = session("fast");
  limiter.created(agent);
  assert.equal(limiter.sessionCount(), 1);
  limiter.disposed(agent);
  assert.equal(limiter.sessionCount(), 0);
});

test("fails closed when upstream agent request middleware violates its contract", async () => {
  const limiter = createPerformanceLimiter(configuration());
  await assert.rejects(
    limiter.request({ agent: session("fast") }, async () => null),
    /agent\/request returned a non-object config/
  );
});

test("preserves cloud and LAN provider output limits exactly", async () => {
  // External-provider runtimes lock the provider but deliberately omit local
  // exact-model context enforcement, so models at that provider keep their cap.
  const limiter = createPerformanceLimiter(configuration("deep", catalog, undefined, "openai"), async () => {
    throw new Error("remote routes must not use local model resolution");
  });
  const cloud = Object.freeze({ provider: "openai", model: "gpt-cloud", maxTokens: 4_096 });
  const lan = Object.freeze({ provider: "custom-lan", model: "private", maxTokens: 1_024 });
  assert.equal(await limiter.request({ agent: session("deep") }, async () => cloud), cloud);
  await assert.rejects(
    limiter.request({ agent: session("deep", "00000000-0000-4000-8000-000000000002") }, async () => lan),
    /runtime is locked to provider openai/
  );
  const lanLimiter = createPerformanceLimiter(configuration("deep", catalog, undefined, "custom-lan"));
  assert.equal(await lanLimiter.request(
    { agent: session("deep", "00000000-0000-4000-8000-000000000003") },
    async () => lan
  ), lan);
});

test("preserves all routes when no synchronized local route exists", async () => {
  const limiter = createPerformanceLimiter(configuration("deep"));
  const upstream = Object.freeze({ provider: "deepseek", model: "deepseek-chat", maxTokens: 2_048 });
  const result = await limiter.request({ agent: session("deep") }, async () => upstream);
  assert.equal(result, upstream);
});

async function withTelemetryStorage(body) {
  const container = await realpath(await mkdtemp(join(tmpdir(), "local-harness-performance-")));
  const root = join(container, "Local Harness");
  const directory = join(root, "PerformanceTelemetry");
  const file = join(directory, "performance-telemetry.json");
  await mkdir(root, { mode: 0o700 });
  await mkdir(directory, { mode: 0o700 });
  await chmod(root, 0o700);
  try { await body({ root, directory, file }); }
  finally { await rm(container, { recursive: true, force: true }); }
}

async function withThermalPolicy(mode, body) {
  await withTelemetryStorage(async ({ root, directory, ...rest }) => {
    const file = join(directory, "thermal-workload-policy.json");
    await writeFile(file, JSON.stringify({
      schemaVersion: 1,
      mode,
      ecoMaxOutputTokens: 2_048,
      minimumDelayMilliseconds: 5_000
    }), { mode: 0o600 });
    await chmod(file, 0o600);
    await body({ root, directory, ...rest, file });
  });
}

test("admits only the exact private native thermal policy path", async () => {
  await withThermalPolicy("normal", async ({ root, directory, file }) => {
    const environment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_THERMAL_POLICY_FILE: file
    };
    assert.deepEqual(decodeThermalPolicyStorage(environment), { file });
    assert.equal(environment.LOCAL_HARNESS_THERMAL_POLICY_FILE, undefined);
    assert.equal(environment.LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT, root);

    const sibling = join(directory, "not-the-policy.json");
    await writeFile(sibling, "{}", { mode: 0o600 });
    await chmod(sibling, 0o600);
    assert.throws(() => decodeThermalPolicyStorage({
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_THERMAL_POLICY_FILE: sibling
    }), /adaptive thermal policy storage is unsafe/);

    const alternateRoot = join(root, "Elsewhere");
    const alternateDirectory = join(alternateRoot, "PerformanceTelemetry");
    const alternateFile = join(alternateDirectory, "thermal-workload-policy.json");
    await mkdir(alternateDirectory, { recursive: true, mode: 0o700 });
    await chmod(alternateRoot, 0o700);
    await writeFile(alternateFile, "{}", { mode: 0o600 });
    assert.throws(() => decodeThermalPolicyStorage({
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: alternateRoot,
      LOCAL_HARNESS_THERMAL_POLICY_FILE: alternateFile
    }), /adaptive thermal policy path is malformed/);
  });
});

test("malformed thermal state fails safe to the reviewed Eco cap", async () => {
  await withThermalPolicy("normal", async ({ file }) => {
    assert.deepEqual(readThermalPolicy(file), {
      mode: "normal",
      maxOutputTokens: undefined,
      minimumDelayMilliseconds: 0
    });
    await writeFile(file, "{}", { mode: 0o600 });
    await chmod(file, 0o600);
    assert.deepEqual(readThermalPolicy(file), {
      mode: "eco",
      maxOutputTokens: 2_048,
      minimumDelayMilliseconds: 5_000
    });
  });
});

test("Eco mode caps local output and inserts a real inter-generation rest", async () => {
  await withThermalPolicy("eco", async ({ file }) => {
    let now = 10_000;
    const delays = [];
    const route = { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 };
    const thermal = createThermalWorkloadController(
      { file },
      route,
      {
        clock: () => now,
        delay: async (milliseconds, signal) => { delays.push({ milliseconds, signal }); }
      }
    );
    const limiter = createPerformanceLimiter(
      configuration("deep", catalog, route),
      async () => ({ provider: "ollama", id: "qwen", context: { contextWindow: 32_768 } }),
      thermal
    );
    const signal = new AbortController().signal;
    const first = await limiter.request(
      { agent: session("deep"), signal },
      async () => ({ provider: "ollama", model: "qwen", maxTokens: 16_384 })
    );
    assert.equal(first.maxTokens, 2_048);
    assert.deepEqual(delays, []);

    thermal.completed({ provider: "ollama", model: "qwen" });
    now += 1_250;
    const second = await limiter.request(
      { agent: session("deep", "00000000-0000-4000-8000-000000000002"), signal },
      async () => ({ provider: "ollama", model: "qwen", maxTokens: 16_384 })
    );
    assert.equal(second.maxTokens, 2_048);
    assert.deepEqual(delays, [{ milliseconds: 3_750, signal }]);
  });
});

test("Eco mode never changes a cloud provider request", async () => {
  await withThermalPolicy("eco", async ({ file }) => {
    const thermal = createThermalWorkloadController(
      { file },
      { provider: "ollama", model: "qwen", contextWindowTokens: 32_768 }
    );
    const limiter = createPerformanceLimiter(
      configuration("deep", catalog, undefined, "deepseek"),
      undefined,
      thermal
    );
    const cloud = Object.freeze({
      provider: "deepseek",
      model: "deepseek-chat",
      maxTokens: 8_192
    });
    assert.equal(await limiter.request(
      { agent: session("deep") },
      async () => cloud
    ), cloud);
  });
});

test("thermal stream observation marks local completion without retaining content", async () => {
  const completions = [];
  const controller = { completed: (options) => completions.push(options) };
  const options = { provider: "ollama", model: "qwen" };
  const chunks = await collect(observeThermalWorkloadStream(
    options,
    async function* () { yield { type: "text-delta", text: "private" }; },
    controller
  ));
  assert.deepEqual(chunks, [{ type: "text-delta", text: "private" }]);
  assert.deepEqual(completions, [options]);
});

async function collect(iterable) {
  const chunks = [];
  for await (const chunk of iterable) chunks.push(chunk);
  return chunks;
}

function createTestTelemetryRecorder(file, options = {}) {
  return createPerformanceTelemetryRecorder(file, {
    lockTransaction: async (operation) => await operation(),
    ...options
  });
}

test("records exact app-wide stream metrics without retaining model output", async () => {
  await withTelemetryStorage(async ({ root, file }) => {
    const environment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: file
    };
    assert.equal(decodeTelemetryFile(environment), file);
    assert.equal(environment.LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT, undefined);
    assert.equal(environment.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE, undefined);

    const id = "12345678-1234-4abc-8def-1234567890ab";
    const recorder = createTestTelemetryRecorder(file, { now: () => 1_000_000, uuid: () => id });
    const secret = "PRIVATE_RESPONSE_CANARY_DO_NOT_PERSIST";
    const chunks = [
      { type: "block-start", index: 0, blockType: "text" },
      { type: "text-delta", index: 0, text: secret },
      { type: "usage", usage: { outputTokens: 42 } },
      { type: "finish", reason: { kind: "stop" } }
    ];
    async function* downstream() { yield* chunks; }
    const monotonic = [10, 12, 16];
    const received = await collect(observePerformanceStream(
      {
        provider: "ollama",
        model: "qwen3.8:27b-mlx",
        sessionId: "local-harness-performance-v1-balanced-00000000-0000-4000-8000-000000000001"
      },
      downstream,
      recorder,
      { wallClock: () => 1_000_000, monotonicClock: () => monotonic.shift() }
    ));
    assert.deepEqual(received, chunks);
    await recorder.flush();

    const raw = await readFile(file, "utf8");
    assert.equal(raw.includes(secret), false);
    const decoded = JSON.parse(raw);
    assert.deepEqual(Object.keys(decoded).sort(), ["records", "schemaVersion"]);
    assert.equal(decoded.schemaVersion, 1);
    assert.deepEqual(decoded.records, [{
      schemaVersion: 1,
      id,
      provider: "ollama",
      model: "qwen3.8:27b-mlx",
      profile: "balanced",
      startedAtMilliseconds: 999_994,
      completedAtMilliseconds: 1_000_000,
      firstTokenAtMilliseconds: 999_996,
      elapsedMilliseconds: 6,
      outputTokens: 42,
      outputTokenCountSource: "providerReported",
      outcome: "completed",
      failureCategory: null
    }]);
  });
});

test("cancellation, thrown errors, and no-terminal streams preserve behavior with coarse outcomes", async () => {
  await withTelemetryStorage(async ({ file }) => {
    const ids = [
      "12345678-1234-4abc-8def-1234567890a1",
      "12345678-1234-4abc-8def-1234567890a2",
      "12345678-1234-4abc-8def-1234567890a3"
    ];
    let now = 2_000_000;
    const recorder = createTestTelemetryRecorder(file, { now: () => now, uuid: () => ids.shift() });

    async function* aborted() { yield { type: "finish", reason: { kind: "aborted", failure: { code: "ABORTED" } } }; }
    let ticks = [1, 2];
    await collect(observePerformanceStream(
      { provider: "ollama", model: "qwen" }, aborted, recorder,
      { wallClock: () => now, monotonicClock: () => ticks.shift() }
    ));

    now += 100;
    const errorCanary = "SECRET_ERROR_BODY_MUST_NOT_PERSIST";
    async function* throwsSecret() { throw new Error(errorCanary); }
    ticks = [3, 4];
    await assert.rejects(
      collect(observePerformanceStream(
        { provider: "openai", model: "remote" }, throwsSecret, recorder,
        { wallClock: () => now, monotonicClock: () => ticks.shift() }
      )),
      new RegExp(errorCanary)
    );

    now += 100;
    async function* missingFinish() { yield { type: "text-delta", index: 0, text: "x" }; }
    ticks = [5, 5.5, 6];
    await collect(observePerformanceStream(
      { provider: "anthropic", model: "claude" }, missingFinish, recorder,
      { wallClock: () => now, monotonicClock: () => ticks.shift() }
    ));

    await recorder.flush();

    const raw = await readFile(file, "utf8");
    assert.equal(raw.includes(errorCanary), false);
    const records = JSON.parse(raw).records;
    assert.deepEqual(records.map((record) => record.outcome), ["failed", "failed", "cancelled"]);
    assert.deepEqual(records.map((record) => record.failureCategory), ["invalidResponse", "unknown", null]);
  });
});

test("telemetry storage is capped, self-heals corrupt data, and serializes concurrent completions", async () => {
  await withTelemetryStorage(async ({ file }) => {
    const now = 3_000_000;
    await writeFile(file, "{partial", { mode: 0o600 });
    const recorder = createTestTelemetryRecorder(file, { now: () => now, uuid: randomUUID });
    const makeRecord = (index) => ({
      schemaVersion: 1,
      id: randomUUID(),
      provider: "ollama",
      model: "qwen",
      profile: "balanced",
      startedAtMilliseconds: now - index - 1,
      completedAtMilliseconds: now - index,
      firstTokenAtMilliseconds: now - index,
      elapsedMilliseconds: 1,
      outputTokens: index,
      outputTokenCountSource: "providerReported",
      outcome: "completed",
      failureCategory: null
    });
    const results = await Promise.all(Array.from({ length: 120 }, (_, index) => recorder.record(makeRecord(index))));
    assert.equal(results.every(Boolean), true);
    const raw = await readFile(file);
    assert.ok(raw.length <= 256 * 1_024);
    const decoded = JSON.parse(raw.toString("utf8"));
    assert.equal(decoded.records.length, 100);
    assert.deepEqual(decoded.records.map((record) => record.completedAtMilliseconds),
      [...decoded.records.map((record) => record.completedAtMilliseconds)].sort((a, b) => b - a));
  });
});

test("held telemetry recording never delays terminal chunks or upstream errors", async () => {
  const never = new Promise(() => {});
  const recorder = {
    nextID: () => "12345678-1234-4abc-8def-1234567890ab",
    record: () => never
  };
  async function* finishes() { yield { type: "finish", reason: { kind: "stop" } }; }
  const completed = await Promise.race([
    collect(observePerformanceStream(
      { provider: "ollama", model: "qwen" }, finishes, recorder,
      { wallClock: () => 10, monotonicClock: () => 1 }
    )),
    new Promise((_, reject) => setTimeout(() => reject(new Error("terminal chunk waited for telemetry")), 100))
  ]);
  assert.equal(completed.at(-1)?.type, "finish");

  const canary = new Error("upstream-canary");
  async function* throwsImmediately() { throw canary; }
  await assert.rejects(
    Promise.race([
      collect(observePerformanceStream(
        { provider: "ollama", model: "qwen" }, throwsImmediately, recorder,
        { wallClock: () => 10, monotonicClock: () => 1 }
      )),
      new Promise((_, reject) => setTimeout(() => reject(new Error("upstream error waited for telemetry")), 100))
    ]),
    canary
  );
});

test("native telemetry lock has hard acquisition and post-LOCKED transaction deadlines", async () => {
  await withTelemetryStorage(async ({ root, file }) => {
    const silentHelper = join(root, "silent-helper.sh");
    await writeFile(silentHelper, "#!/bin/sh\nsleep 60\n", { mode: 0o700 });
    await chmod(silentHelper, 0o700);
    const silent = createNativeTelemetryLockTransaction(silentHelper, root, file, {
      acquisitionTimeoutMilliseconds: 20,
      transactionTimeoutMilliseconds: 60
    });
    const acquisitionStarted = Date.now();
    assert.equal(await silent(async () => true), false);
    assert.ok(Date.now() - acquisitionStarted < 500);

    const lockedHelper = join(root, "locked-helper.sh");
    await writeFile(lockedHelper, "#!/bin/sh\nprintf 'LOCKED\\n'\ncat >/dev/null\nsleep 60\n", { mode: 0o700 });
    await chmod(lockedHelper, 0o700);
    const locked = createNativeTelemetryLockTransaction(lockedHelper, root, file, {
      acquisitionTimeoutMilliseconds: 20,
      transactionTimeoutMilliseconds: 60
    });
    const transactionStarted = Date.now();
    assert.equal(await locked(async () => true), false);
    assert.ok(Date.now() - transactionStarted < 500);
  });
});

test("linked, hard-linked, permissive, and poisoned temporary telemetry nodes are never followed", async () => {
  await withTelemetryStorage(async ({ root, directory, file }) => {
    const outside = join(root, "outside");
    await writeFile(outside, "OUTSIDE_CANARY", { mode: 0o600 });

    await symlink(outside, file);
    const linkedEnvironment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: file
    };
    assert.equal(decodeTelemetryFile(linkedEnvironment), undefined);
    await rm(file);

    await link(outside, file);
    const hardLinkedEnvironment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: file
    };
    assert.equal(decodeTelemetryFile(hardLinkedEnvironment), undefined);
    await rm(file);

    await writeFile(file, JSON.stringify({ schemaVersion: 1, records: [] }), { mode: 0o644 });
    const permissiveEnvironment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: file
    };
    assert.equal(decodeTelemetryFile(permissiveEnvironment), undefined);
    await chmod(file, 0o600);

    await chmod(directory, 0o755);
    const publicDirectoryEnvironment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: file
    };
    assert.equal(decodeTelemetryFile(publicDirectoryEnvironment), undefined);
    await chmod(directory, 0o700);

    const siblingDirectory = join(root, "Sibling", "PerformanceTelemetry");
    await mkdir(siblingDirectory, { recursive: true, mode: 0o700 });
    const siblingFile = join(siblingDirectory, "performance-telemetry.json");
    const siblingEnvironment = {
      LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: root,
      LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: siblingFile
    };
    assert.equal(decodeTelemetryFile(siblingEnvironment), undefined);

    const temporary = join(directory, ".performance-telemetry.json.tmp");
    await symlink(outside, temporary);
    const recorder = createTestTelemetryRecorder(file, { now: () => 4_000_000, uuid: randomUUID });
    assert.equal(await recorder.record({
      schemaVersion: 1,
      id: randomUUID(),
      provider: "ollama",
      model: "qwen",
      profile: null,
      startedAtMilliseconds: 3_999_999,
      completedAtMilliseconds: 4_000_000,
      firstTokenAtMilliseconds: null,
      elapsedMilliseconds: 1,
      outputTokens: 0,
      outputTokenCountSource: "estimated",
      outcome: "cancelled",
      failureCategory: null
    }), false);
    assert.equal(await readFile(outside, "utf8"), "OUTSIDE_CANARY");
  });
});
