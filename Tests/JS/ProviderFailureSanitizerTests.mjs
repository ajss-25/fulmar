import assert from "node:assert/strict";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";

import { Context } from "../../VendorRuntime/node_modules/@deepseek-ai/cordis/lib/index.js";
import {
  LlmError,
  LlmRuntime
} from "../../VendorRuntime/node_modules/@deepseek-ai/dsh-llm/lib/index.js";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const pinnedHostApiProxySource = await readFile(join(
  project,
  "VendorRuntime",
  "node_modules",
  "@deepseek-ai",
  "dsh-host-apiproxy",
  "lib",
  "index.js"
), "utf8");
let root;
let apply;
let inject;
let maximumRetryAfterMilliseconds;
let providerFailureTaxonomyVersion;
let browserFailureTaxonomyVersion;
let sanitizeClientFailure;
let sanitizeClientHistoryReply;
let sanitizeFinishChunk;
let sanitizeHistoryReply;
let sanitizeProviderFailure;
let sanitizeProviderStream;

before(async () => {
  root = await mkdtemp(join(tmpdir(), "fulmar-provider-failure-sanitizer-"));
  const llmShim = join(root, "node_modules", "@deepseek-ai", "dsh-llm");
  const pluginRoot = join(root, "node_modules", "@local-harness", "dsh-client-security-bridge");
  await mkdir(llmShim, { recursive: true });
  await mkdir(pluginRoot, { recursive: true });
  const llmURL = pathToFileURL(join(
    project, "VendorRuntime", "node_modules", "@deepseek-ai", "dsh-llm", "lib", "index.js"
  )).href;
  await writeFile(join(llmShim, "package.json"), JSON.stringify({
    name: "@deepseek-ai/dsh-llm",
    version: "0.1.1-rc.1",
    type: "module",
    exports: "./index.mjs"
  }));
  await writeFile(join(llmShim, "index.mjs"), `export * from ${JSON.stringify(llmURL)};\n`);
  await copyFile(
    join(project, "Resources", "DSHPlugins", "client-security-bridge", "index.mjs"),
    join(pluginRoot, "index.mjs")
  );
  const plugin = await import(`${pathToFileURL(join(pluginRoot, "index.mjs")).href}?test=${Date.now()}`);
  ({
    apply,
    inject,
    maximumRetryAfterMilliseconds,
    providerFailureTaxonomyVersion,
    sanitizeFinishChunk,
    sanitizeHistoryReply,
    sanitizeProviderFailure,
    sanitizeProviderStream
  } = plugin);

  let registration;
  const pageWindow = {
    __ModuleLoader__: { load(value) { registration = value; } },
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval
  };
  pageWindow.window = pageWindow;
  const clientSource = await readFile(
    join(project, "Resources", "DSHPlugins", "client-security-bridge", "client.js"),
    "utf8"
  );
  runInNewContext(clientSource, pageWindow, {
    filename: "client-security-bridge-provider-parity.js",
    timeout: 2_000
  });
  const clientPlugin = registration.factory(() => {
    throw new Error("The browser bridge must remain dependency-free.");
  });
  browserFailureTaxonomyVersion = clientPlugin.providerFailureTaxonomyVersion;
  sanitizeClientFailure = clientPlugin.sanitizeClientFailure;
  sanitizeClientHistoryReply = clientPlugin.sanitizeHistoryReply;
});

after(async () => {
  if (root !== undefined) await rm(root, { recursive: true, force: true });
});

const hostile = [
  "sk-fulmar-provider-secret-never-display",
  "Bearer fulmar-authorization-never-display",
  "https://provider.invalid/v1/private?token=secret",
  "/Users/example/Library/Application Support/Fulmar/private.json",
  "DEEPSEEK_API_KEY",
  "request_id=provider-request-secret"
].join(" | ");

const cases = Object.freeze([
  ["missing credential", { code: "MISSING_CREDENTIAL" }, "MISSING_CREDENTIAL"],
  ["Keychain authorization", { code: "KEYCHAIN_AUTHORIZATION_REQUIRED" }, "KEYCHAIN_AUTHORIZATION_REQUIRED"],
  ["Keychain recovery", { code: "CREDENTIAL_RECOVERY_REQUIRED" }, "CREDENTIAL_RECOVERY_REQUIRED"],
  ["authentication code", { code: "AUTH" }, "AUTH"],
  ["HTTP 401", { code: "UNKNOWN", status: 401 }, "AUTH"],
  ["HTTP 403", { code: "UNKNOWN", status: 403 }, "AUTH"],
  ["quota code", { code: "QUOTA" }, "QUOTA"],
  ["HTTP 402", { code: "UNKNOWN", status: 402 }, "QUOTA"],
  ["quota encoded as HTTP 429", { code: "QUOTA", status: 429 }, "QUOTA"],
  ["rate limit", { code: "RATE_LIMIT", status: 429 }, "RATE_LIMIT"],
  ["HTTP 500", { code: "UNKNOWN", status: 500 }, "SERVER"],
  ["HTTP 599", { code: "UNKNOWN", status: 599 }, "SERVER"],
  ["transport", { code: "TRANSPORT" }, "TRANSPORT"],
  ["timeout", { code: "TIMEOUT" }, "TIMEOUT"],
  ["empty response", { code: "EMPTY_RESPONSE" }, "EMPTY_RESPONSE"],
  ["closed stream", { code: "STREAM_CLOSED" }, "STREAM_CLOSED"],
  ["missing adapter", { code: "NO_ADAPTER" }, "NO_ADAPTER"],
  ["unknown", { code: "PROVIDER_SUPPLIED_SECRET_CODE" }, "UNKNOWN"]
]);

function providerFailure(facts) {
  return {
    message: hostile,
    code: facts.code,
    ...(facts.status === undefined ? {} : { status: facts.status }),
    providerRetryAfterMs: 12_345,
    requestId: hostile
  };
}

function assertSafe(failure, expectedCode) {
  assert.equal(failure.code, expectedCode);
  assert.equal(failure.status === undefined || Number.isInteger(failure.status), true);
  assert.equal(failure.providerRetryAfterMs, 12_345);
  assert.equal(Object.hasOwn(failure, "requestId"), false);
  assert.equal(Object.isFrozen(failure), true);
  const serialized = JSON.stringify(failure);
  for (const fragment of hostile.split(" | ")) assert.doesNotMatch(serialized, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.ok(failure.message.length > 0 && failure.message.length < 256);
}

for (const [label, facts, expectedCode] of cases) {
  test(`maps ${label} to one finite app-owned provider failure`, () => {
    const safe = sanitizeProviderFailure(providerFailure(facts));
    assertSafe(safe, expectedCode);
    if (facts.status !== undefined) assert.equal(safe.status, facts.status);
  });
}

test("drops invalid status, unbounded retry delay, provider request id, raw code, and hostile accessors", () => {
  let messageRead = false;
  let requestRead = false;
  const failure = {};
  Object.defineProperties(failure, {
    code: { value: "UNKNOWN" },
    status: { value: 999 },
    providerRetryAfterMs: { value: maximumRetryAfterMilliseconds + 1 },
    message: { get() { messageRead = true; throw new Error(hostile); } },
    requestId: { get() { requestRead = true; throw new Error(hostile); } }
  });
  const safe = sanitizeProviderFailure(failure);
  assert.equal(safe.code, "UNKNOWN");
  assert.equal(Object.hasOwn(safe, "status"), false);
  assert.equal(Object.hasOwn(safe, "providerRetryAfterMs"), false);
  assert.equal(Object.hasOwn(safe, "requestId"), false);
  assert.equal(messageRead, false);
  assert.equal(requestRead, false);
});

test("host and browser provider taxonomies have exact semantic parity", () => {
  assert.equal(providerFailureTaxonomyVersion, 1);
  assert.equal(browserFailureTaxonomyVersion, providerFailureTaxonomyVersion);
  const parityCases = [
    ...cases.map(([, facts]) => facts),
    { code: "INVALID_API_KEY", status: 401 },
    { code: "CREDENTIAL_TRANSACTION_BUSY" },
    { code: "CREDENTIAL_STATE_UNSAFE" },
    { code: "AUTHENTICATION_FAILED" },
    { code: "INSUFFICIENT_QUOTA", status: 429 },
    { code: "TOO_MANY_REQUESTS", status: 429 },
    { code: "SERVICE_UNAVAILABLE", status: 503 },
    { code: "ECONNRESET" },
    { code: "ETIMEDOUT" },
    { code: "CONTEXT_WINDOW_EXCEEDED" },
    { code: "UNKNOWN_MODEL" },
    { code: "UNSUPPORTED_CONTENT" },
    { code: "PROVIDER_SECRET_CODE", status: 418 },
    { code: "ABORTED" }
  ];
  for (const facts of parityCases) {
    const raw = providerFailure(facts);
    const host = sanitizeProviderFailure(raw);
    const browser = sanitizeClientFailure(raw);
    assert.equal(JSON.stringify(browser), JSON.stringify(host), JSON.stringify(facts));
  }
  const hostAbort = sanitizeProviderFailure(providerFailure({ code: "TRANSPORT" }), { aborted: true });
  const browserAbort = sanitizeClientFailure(providerFailure({ code: "TRANSPORT" }), { aborted: true });
  assert.equal(JSON.stringify(browserAbort), JSON.stringify(hostAbort));
});

test("sanitizes the terminal chunk before retry and turn-end persistence consume it", () => {
  const raw = providerFailure({ code: "AUTH", status: 403 });
  const safeChunk = sanitizeFinishChunk({
    type: "finish",
    reason: { kind: "error", failure: raw }
  });
  const failure = safeChunk.reason.failure;
  const persisted = [
    { type: "assistant/chunk", data: { turn: 1, step: 1, chunk: safeChunk } },
    { type: "llm/retry", data: { turn: 1, step: 1, retry: 1, failure } },
    { type: "turn/end", data: { turn: 1, reason: { kind: "error", error: failure } } }
  ];
  const bytes = JSON.stringify(persisted);
  assert.doesNotMatch(bytes, /sk-fulmar|Bearer|provider\.invalid|\/Users\/example|DEEPSEEK_API_KEY|request_id/u);
  assert.equal(persisted[1].data.failure.code, "AUTH");
  assert.equal(persisted[2].data.reason.error.message, failure.message);
});

test("sanitizes ordinary and subagent legacy history at the Host API boundary", async () => {
  const rawFailure = providerFailure({ code: "AUTH", status: 403 });
  const response = {
    type: "response",
    rpcId: "history",
    result: {
      ok: true,
      value: {
        events: [{
          event: {
            type: "turn/end",
            seq: 1,
            time: 1,
            data: { turn: 1, reason: { kind: "error", error: rawFailure } }
          }
        }],
        hasMore: false
      }
    }
  };
  const sessionHistory = async () => response;
  const subagentHistory = async () => response;
  const effects = [];
  const apiProxy = {
    sessions: { history: sessionHistory },
    subagents: { history: subagentHistory },
    downloads: { async sessionLog() { return new Response("raw"); } }
  };
  apply({
    llm: { async prepareCall() { return { config: {} }; } },
    apiProxy,
    on() {},
    effect(execute) { effects.push(execute()); }
  });
  for (const history of [apiProxy.sessions.history, apiProxy.subagents.history]) {
    const safe = await history({});
    const error = safe.result.value.events[0].event.data.reason.error;
    assertSafe(error, "AUTH");
    assert.equal(error.status, 403);
    assert.doesNotMatch(JSON.stringify(safe), /sk-fulmar|provider\.invalid|\/Users\/example|request_id/u);
  }
  for (const dispose of effects.reverse()) dispose?.();
  assert.equal(apiProxy.sessions.history, sessionHistory);
  assert.equal(apiProxy.subagents.history, subagentHistory);

  const direct = sanitizeHistoryReply(response);
  assert.equal(direct.result.value.events[0].event.data.reason.error.code, "AUTH");
});

test("failed history replies are identical fixed safe shapes in Host and browser bridges", () => {
  const secret = "sk-history-failure /Users/example/private https://provider.invalid request-id-secret";
  let accessorCalls = 0;
  const error = {
    code: "internal",
    details: { path: secret, requestId: secret }
  };
  Object.defineProperty(error, "message", {
    enumerable: true,
    get() { accessorCalls += 1; throw new Error(secret); }
  });
  const reply = {
    type: "response",
    rpcId: "history-failed-1",
    tracePath: secret,
    result: { ok: false, error }
  };
  Object.defineProperty(reply, "toJSON", {
    get() { accessorCalls += 1; throw new Error(secret); }
  });

  const host = sanitizeHistoryReply(reply);
  const browser = sanitizeClientHistoryReply(reply);
  const expected = {
    type: "response",
    rpcId: "history-failed-1",
    result: {
      ok: false,
      error: {
        code: "internal",
        message: "Fulmar could not load this task history safely.",
        details: {}
      }
    }
  };
  assert.deepEqual(host, expected);
  assert.equal(JSON.stringify(browser), JSON.stringify(expected));
  assert.equal(accessorCalls, 0);
  assert.doesNotMatch(JSON.stringify(host), /sk-history|\/Users\/example|provider\.invalid|request-id/u);

  const malformed = {};
  Object.defineProperty(malformed, "result", {
    enumerable: true,
    get() { accessorCalls += 1; throw new Error(secret); }
  });
  assert.equal(JSON.stringify(sanitizeHistoryReply(malformed)), JSON.stringify({
    result: expected.result
  }));
  assert.equal(accessorCalls, 0);
});

test("preserves cancellation semantics while removing an untrusted abort failure", () => {
  const safe = sanitizeFinishChunk({
    type: "finish",
    reason: { kind: "aborted", failure: providerFailure({ code: "TRANSPORT" }) }
  });
  assert.equal(safe.reason.kind, "aborted");
  assert.deepEqual(safe.reason.failure, {
    code: "ABORTED",
    message: "The model request was cancelled.",
    providerRetryAfterMs: 12_345
  });
  assert.doesNotMatch(JSON.stringify(safe), /sk-fulmar|provider\.invalid|request_id/u);
});

test("turns downstream construction and iteration throws into app-owned LlmError snapshots", async (context) => {
  const thrown = new LlmError(hostile, "TRANSPORT", {
    status: 503,
    providerRetryAfterMs: 1_500,
    requestId: hostile
  });
  for (const [label, next] of [
    ["construction", () => { throw thrown; }],
    ["iteration", () => (async function* () { throw thrown; })()]
  ]) {
    await context.test(label, async () => {
      await assert.rejects(async () => {
        for await (const _chunk of sanitizeProviderStream({}, next)) { /* consume */ }
      }, (error) => {
        assert.ok(error instanceof LlmError);
        assert.equal(error.code, "SERVER");
        assert.equal(error.failure.status, 503);
        assert.equal(error.failure.providerRetryAfterMs, 1_500);
        assert.equal(Object.hasOwn(error.failure, "requestId"), false);
        assert.doesNotMatch(JSON.stringify(error.failure), /sk-fulmar|provider\.invalid|request_id/u);
        assert.equal(error.cause, undefined);
        return true;
      });
    });
  }
});

test("registers one global prepended host waterfall boundary", () => {
  const calls = [];
  const effects = [];
  const priorPrepareCall = async () => ({ config: {} });
  const llm = { prepareCall: priorPrepareCall };
  apply({
    llm,
    apiProxy: {
      sessions: { async history() {} },
      subagents: { async history() {} },
      downloads: { async sessionLog() { return new Response("raw"); } }
    },
    effect(execute) { effects.push(execute()); },
    on(event, listener, options) { calls.push({ event, listener, options }); }
  });
  assert.deepEqual(inject, ["llm", "apiProxy"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].event, "llm/stream");
  assert.deepEqual(calls[0].options, { global: true, prepend: true });
  for (const dispose of effects.reverse()) dispose?.();
  assert.equal(llm.prepareCall, priorPrepareCall);
});

test("sanitizes model-preparation failures before the agent loop can persist them", async () => {
  const effects = [];
  const priorPrepareCall = async () => {
    throw new LlmError(hostile, "UNKNOWN_MODEL", {
      status: 400,
      providerRetryAfterMs: 1_250,
      requestId: hostile
    });
  };
  const llm = { prepareCall: priorPrepareCall };
  apply({
    llm,
    apiProxy: {
      sessions: { async history() {} },
      subagents: { async history() {} },
      downloads: { async sessionLog() { return new Response("raw"); } }
    },
    effect(execute) { effects.push(execute()); },
    on() {}
  });
  await assert.rejects(
    llm.prepareCall({ provider: "hostile", model: "hostile" }),
    (error) => {
      assert.ok(error instanceof LlmError);
      assert.equal(error.code, "MODEL_CONFIGURATION");
      assert.equal(error.failure.status, 400);
      assert.equal(error.failure.providerRetryAfterMs, 1_250);
      assert.equal(Object.hasOwn(error.failure, "requestId"), false);
      assert.doesNotMatch(JSON.stringify(error.failure), /sk-fulmar|provider\.invalid|\/Users\/example|request_id/u);
      return true;
    }
  );
  for (const dispose of effects.reverse()) dispose?.();
  assert.equal(llm.prepareCall, priorPrepareCall);
});

test("fail-closes the pinned raw Harness-log export without reading or returning stored bytes", async () => {
  // Compatibility tripwires for the exact DSH surface this wrapper closes.
  // Upstream movement or semantic changes must fail qualification until the
  // boundary is reviewed again.
  assert.match(pinnedHostApiProxySource, /downloads: \{ async sessionLog\(request, signal\) \{/u);
  assert.match(pinnedHostApiProxySource, /root = await deps\.sessionPersistence\.readRaw\(request\.sessionId, signal\);/u);
  assert.match(pinnedHostApiProxySource, /yield \{\s*path: root\.filename,\s*content: root\.content\s*\};/u);
  assert.match(pinnedHostApiProxySource, /path === "\/api\/session\.export"/u);
  assert.match(pinnedHostApiProxySource, /api\.downloads\.sessionLog\(parsed\.data, req\.signal\)/u);
  let rawExportCalls = 0;
  const priorSessionLog = async () => {
    rawExportCalls += 1;
    return new Response(hostile, { status: 200 });
  };
  const effects = [];
  const downloads = { sessionLog: priorSessionLog };
  apply({
    llm: { async prepareCall() { return { config: {} }; } },
    apiProxy: {
      sessions: { async history() {} },
      subagents: { async history() {} },
      downloads
    },
    effect(execute) { effects.push(execute()); },
    on() {}
  });
  const response = await downloads.sessionLog({ sessionId: "old", includeDescendants: true });
  assert.equal(response.status, 409);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(rawExportCalls, 0);
  const body = await response.text();
  assert.match(body, /Task History transcript export/u);
  assert.doesNotMatch(body, /sk-fulmar|provider\.invalid|\/Users\/example|request_id/u);
  for (const dispose of effects.reverse()) dispose?.();
  assert.equal(downloads.sessionLog, priorSessionLog);
});

test("composes with the pinned Cordis LlmRuntime before its terminal failure escapes", async () => {
  const ctx = new Context();
  await ctx.plugin(LlmRuntime);
  ctx.provide("apiProxy", {
    sessions: { async history() {} },
    subagents: { async history() {} },
    downloads: { async sessionLog() { return new Response("raw"); } }
  });
  apply(ctx);
  try {
    const chunks = [];
    for await (const chunk of ctx.llm.stream({
      provider: "unregistered-provider",
      model: "unregistered-model",
      messages: []
    })) chunks.push(chunk);
    assert.equal(chunks.length, 1);
    assert.deepEqual(chunks[0], {
      type: "finish",
      reason: {
        kind: "error",
        failure: {
          code: "NO_ADAPTER",
          message: "This model route is unavailable. Choose another model or repair it in Models & Providers."
        }
      }
    });
  } finally {
    await ctx.fiber.dispose();
  }
});
