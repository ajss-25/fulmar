import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { apply } from "../../VendorRuntime/node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js";
import { clampMaxTokensToContext } from "../../VendorRuntime/node_modules/@earendil-works/pi-ai/dist/api/simple-options.js";
import { estimateContextTokens } from "../../VendorRuntime/node_modules/@earendil-works/pi-ai/dist/utils/estimate.js";

const model = {
  id: "fixture-model",
  name: "Fixture Model",
  input: ["text"],
  contextWindow: 8_192,
  maxTokens: 1_024
};

function captureAdapter(providers, get = () => undefined) {
  let adapter;
  const ctx = {
    get,
    inject: () => {},
    logger: { warn: () => {}, error: () => {} },
    llm: {
      registerConfigurableProviders: () => ({ replace: () => {} }),
      registerModelDiscovery: () => {},
      registerAdapter: (_routes, value) => {
        adapter = value;
        return { replace: () => {} };
      }
    }
  };
  apply(ctx, { providers });
  assert.ok(adapter, "a non-empty route set must register the adapter");
  return adapter;
}

function profile(api, baseURL, additions = {}) {
  return {
    displayName: "Private fixture",
    api,
    baseURL,
    unauthenticated: true,
    models: [model],
    ...additions
  };
}

test("configured Ollama and LM Studio-style models serialize usable context-bounded output", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push(JSON.parse(body));
      respondChat(response);
    });
  });
  try {
    const port = await listen(server);
    for (const [provider, contextWindow, inputTokens, requested, modelCap, expected] of [
      ["ollama", 8192, 6200, 2048, 2048, 1480],
      ["lmstudio", 8192, 6200, 2048, 2048, 1480],
      ["small-local", 4096, 3000, 1024, 1024, 840],
      ["lmstudio", 16384, 12000, 4096, 4096, 3360],
      ["ollama", 32768, 28000, 4096, 4096, 2720],
      ["ollama", 49152, 42000, 8192, 8192, 4080],
      ["remote-compatible", 65536, 56000, 8192, 8192, 5440],
      ["remote-compatible", 131072, 10000, 4096, 8192, 4096],
      ["small-output-cap", 8192, 1024, 4096, 512, 512],
      ["small-caller-cap", 8192, 1024, 64, 2048, 64]
    ]) {
      const adapter = captureAdapter({ [provider]: profile("openai-completions", `http://127.0.0.1:${port}/v1`, {
        models: [{ ...model, contextWindow, maxTokens: modelCap }], compat: { maxTokensField: "max_tokens" }
      }) });
      const chunks = [];
      for await (const chunk of adapter.stream({ provider, model: model.id, maxTokens: requested,
        messages: [{ role: "user", content: [{ type: "text", text: "x".repeat(inputTokens * 4) }] }]
      })) chunks.push(chunk);
      assert.ok(chunks.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "stop"));
      assert.equal(requests.at(-1).max_tokens, expected, `${provider}/${contextWindow}`);
      assert.equal(requests.at(-1).max_completion_tokens, undefined);
      assert.ok(inputTokens + expected + Math.min(4096, Math.max(256, Math.ceil(contextWindow / 16))) <= contextWindow);
    }
    const tools = [{ name: "WriteFixture", description: "Only an inert schema, never executed.",
      parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }];
    const system = "s".repeat(8000);
    const prefixTokens = estimateContextTokens({ systemPrompt: system, tools, messages: [] }).tokens;
    const adapter = captureAdapter({ ollama: profile("openai-completions", `http://127.0.0.1:${port}/v1`, {
      models: [{ ...model, contextWindow: 8192, maxTokens: 2048 }], compat: { maxTokensField: "max_tokens" }
    }) });
    for await (const _chunk of adapter.stream({ provider: "ollama", model: model.id, maxTokens: 2048, system, tools,
      messages: [{ role: "user", content: [{ type: "text", text: "x".repeat((6200 - prefixTokens) * 4) }] }]
    })) { /* The serializer, including prefix and tool schemas, is the test subject. */ }
    assert.equal(requests.at(-1).max_tokens, 1480);
    assert.equal(requests.at(-1).tools.length, 1);
  } finally {
    await close(server);
  }
});

test("exhausted model contexts fail with the typed recovery code before provider I/O", async () => {
  let requests = 0;
  const server = createServer((_request, response) => { requests += 1; respondChat(response); });
  try {
    const port = await listen(server);
    const adapter = captureAdapter({ lmstudio: profile("openai-completions", `http://127.0.0.1:${port}/v1`, {
      models: [{ ...model, contextWindow: 8192, maxTokens: 2048 }]
    }) });
    for (const remaining of [0, 1, 15, 16, 255]) {
      const chunks = [];
      for await (const chunk of adapter.stream({ provider: "lmstudio", model: model.id, maxTokens: 2048,
        messages: [{ role: "user", content: [{ type: "text", text: "x".repeat((8192 - 512 - remaining) * 4) }] }]
      })) chunks.push(chunk);
      assert.ok(chunks.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "error"
        && chunk.reason.failure.code === "CONTEXT_WINDOW_EXCEEDED"), JSON.stringify(chunks));
    }
    assert.equal(requests, 0);
  } finally {
    await close(server);
  }
});

test("budgeting includes system and tool burden and honors caller, model and protocol floors", () => {
  const configured = { ...model, api: "openai-completions", contextWindow: 8192, maxTokens: 2048 };
  const context = { systemPrompt: "s".repeat(8000), messages: [{ role: "user", content: "x".repeat(12000), timestamp: 0 }],
    tools: [{ name: "FixtureWrite", description: "inert", parameters: { type: "object", properties: { text: { type: "string" } } } }] };
  const estimate = estimateContextTokens(context).tokens;
  assert.equal(clampMaxTokensToContext(configured, context, 2048), Math.min(2048, 8192 - estimate - 512));
  for (const remaining of [256, 512, 2048]) {
    const bounded = { messages: [{ role: "user", content: "x".repeat((8192 - 512 - remaining) * 4), timestamp: 0 }] };
    assert.equal(clampMaxTokensToContext(configured, bounded, 2048), remaining);
  }
  assert.equal(clampMaxTokensToContext(configured, { messages: [] }, 1), 1, "an explicit tiny Chat cap is not raised");
  assert.throws(() => clampMaxTokensToContext({ ...configured, api: "openai-responses" }, { messages: [] }, 15),
    (error) => error.code === "FULMAR_INVALID_TOKEN_BUDGET");
  assert.throws(() => clampMaxTokensToContext({ ...configured, api: "azure-openai-responses" }, { messages: [] }, 15),
    (error) => error.code === "FULMAR_INVALID_TOKEN_BUDGET");
  for (const invalid of [0, -1, 1.5, NaN, Infinity]) {
    assert.throws(() => clampMaxTokensToContext({ ...configured, contextWindow: invalid }, { messages: [] }, 2048));
    assert.throws(() => clampMaxTokensToContext({ ...configured, maxTokens: invalid }, { messages: [] }, 2048));
    assert.throws(() => clampMaxTokensToContext(configured, { messages: [] }, invalid));
  }
  const history = {
    ...context,
    messages: [
      { role: "assistant", content: [{ type: "text", text: "retained" }], timestamp: 1, stopReason: "stop",
        usage: { input: 6000, output: 100, cacheRead: 0, cacheWrite: 0, totalTokens: 6100 } },
      { role: "user", content: "next".repeat(25), timestamp: 2 }
    ]
  };
  assert.equal(estimateContextTokens(history).tokens, 6125, "reported usage already includes the prefix/tools");
  assert.equal(clampMaxTokensToContext(configured, history, 2048), 1555);
  const cjk = { messages: [{ role: "user", content: "你好模型".repeat(1000), timestamp: 0 }] };
  assert.equal(clampMaxTokensToContext(configured, cjk, 2048), 2048);
  // The estimator is not a tokenizer. An actual provider overflow remains a
  // typed recoverable error; do not claim character-based admission guarantees fit.
});

test("Responses and Anthropic serialize bounded budgets and retain typed lazy setup failures", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push({ url: request.url, body: JSON.parse(body) });
      if (request.url.endsWith("/responses")) respondResponses(response);
      else respondAnthropic(response);
    });
  });
  try {
    const port = await listen(server);
    for (const [api, suffix, field] of [
      ["openai-responses", "/v1", "max_output_tokens"],
      ["anthropic-messages", "", "max_tokens"]
    ]) {
      const adapter = captureAdapter({ private: profile(api, `http://127.0.0.1:${port}${suffix}`, {
        models: [{ ...model, contextWindow: 8192, maxTokens: 2048 }]
      }) });
      const chunks = [];
      for await (const chunk of adapter.stream({ provider: "private", model: model.id, maxTokens: 2048,
        messages: [{ role: "user", content: [{ type: "text", text: "x".repeat(6200 * 4) }] }]
      })) chunks.push(chunk);
      assert.equal(requests.at(-1).body[field], 1480, api);
      assert.ok(chunks.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "stop"), api);
      const before = requests.length;
      const invalid = [];
      for await (const chunk of adapter.stream({ provider: "private", model: model.id,
        maxTokens: api === "openai-responses" ? 15 : 0,
        messages: [{ role: "user", content: [{ type: "text", text: "tiny" }] }]
      })) invalid.push(chunk);
      assert.equal(requests.length, before, "invalid limits must not reach the provider");
      assert.ok(invalid.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "error"
        && chunk.reason.failure.code === "INVALID_REQUEST"), JSON.stringify(invalid));
    }
    const thinking = captureAdapter({ private: profile("anthropic-messages", `http://127.0.0.1:${port}`, {
      reasoning: "medium",
      models: [{ ...model, contextWindow: 8192, maxTokens: 4096, reasoningEfforts: { off: null, medium: "medium" } }]
    }) });
    for await (const _chunk of thinking.stream({ provider: "private", model: model.id, maxTokens: 1024,
      messages: [{ role: "user", content: [{ type: "text", text: "x".repeat(5000 * 4) }] }]
    })) { /* Anthropic expands the text allowance for thinking, then must re-clamp. */ }
    assert.equal(requests.at(-1).body.max_tokens, 2680);
    assert.equal(requests.at(-1).body.thinking.budget_tokens, 1656);
    assert.ok(requests.at(-1).body.thinking.budget_tokens < requests.at(-1).body.max_tokens);
  } finally {
    await close(server);
  }
});

function openSSE(response) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive"
  });
}

function data(response, value, event) {
  if (event !== undefined) response.write(`event: ${event}\n`);
  response.write(`data: ${typeof value === "string" ? value : JSON.stringify(value)}\n\n`);
}

function respondChat(response) {
  openSSE(response);
  const chunk = (delta, finishReason = null) => ({
    id: "chatcmpl-private",
    object: "chat.completion.chunk",
    created: 1,
    model: model.id,
    choices: [{ index: 0, delta, finish_reason: finishReason }]
  });
  data(response, chunk({ role: "assistant", content: "ok" }));
  data(response, chunk({}, "stop"));
  data(response, "[DONE]");
  response.end();
}

function responseEnvelope(status, output = []) {
  return {
    id: "resp_private",
    object: "response",
    created_at: 1,
    status,
    model: model.id,
    output,
    parallel_tool_calls: true,
    error: null,
    incomplete_details: null,
    instructions: null,
    metadata: {}
  };
}

function respondResponses(response) {
  openSSE(response);
  const item = {
    id: "msg_private",
    type: "message",
    status: "completed",
    role: "assistant",
    content: [{ type: "output_text", text: "ok", annotations: [] }]
  };
  data(response, { type: "response.created", response: responseEnvelope("in_progress") }, "response.created");
  data(response, {
    type: "response.output_item.added",
    output_index: 0,
    item: { ...item, status: "in_progress", content: [] }
  }, "response.output_item.added");
  data(response, {
    type: "response.output_text.delta",
    output_index: 0,
    content_index: 0,
    item_id: item.id,
    delta: "ok"
  }, "response.output_text.delta");
  data(response, { type: "response.output_item.done", output_index: 0, item }, "response.output_item.done");
  data(response, {
    type: "response.completed",
    response: {
      ...responseEnvelope("completed", [item]),
      usage: {
        input_tokens: 1,
        input_tokens_details: { cached_tokens: 0 },
        output_tokens: 1,
        output_tokens_details: { reasoning_tokens: 0 },
        total_tokens: 2
      }
    }
  }, "response.completed");
  data(response, "[DONE]");
  response.end();
}

function anthropic(response, type, body) {
  data(response, { type, ...body }, type);
}

function respondAnthropic(response) {
  openSSE(response);
  anthropic(response, "message_start", {
    message: {
      id: "msg_private",
      type: "message",
      role: "assistant",
      model: model.id,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 0 }
    }
  });
  anthropic(response, "content_block_start", {
    index: 0,
    content_block: { type: "text", text: "" }
  });
  anthropic(response, "content_block_delta", {
    index: 0,
    delta: { type: "text_delta", text: "ok" }
  });
  anthropic(response, "content_block_stop", { index: 0 });
  anthropic(response, "message_delta", {
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: 1 }
  });
  anthropic(response, "message_stop", {});
  response.end();
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test("explicit private no-auth reaches every reviewed protocol without an auth header", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      requests.push({ url: request.url, headers: request.headers });
      if (request.url === "/v1/chat/completions") respondChat(response);
      else if (request.url === "/v1/responses") respondResponses(response);
      else if (request.url === "/v1/messages") respondAnthropic(response);
      else { response.writeHead(404); response.end(); }
    });
  });
  try {
    const port = await listen(server);
    const base = `http://127.0.0.1:${port}`;
    const adapter = captureAdapter({
      "private-chat": profile("openai-completions", `${base}/v1`),
      "private-responses": profile("openai-responses", `${base}/v1`),
      "private-anthropic": profile("anthropic-messages", base)
    });
    for (const provider of ["private-chat", "private-responses", "private-anthropic"]) {
      const chunks = [];
      for await (const chunk of adapter.stream({
        provider,
        model: model.id,
        messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }]
      })) chunks.push(chunk);
      assert.ok(
        chunks.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "stop"),
        `${provider}: ${JSON.stringify(chunks)}`
      );
    }
  } finally {
    await close(server);
  }

  assert.deepEqual(requests.map((request) => request.url), [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/messages"
  ]);
  for (const request of requests) {
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers["x-api-key"], undefined);
    assert.equal(request.headers["cf-aig-authorization"], undefined);
  }
});

test("explicit no-auth never consults stored or ambient credentials when its route collides with a catalog provider", async () => {
  const requests = [];
  const credentialLookups = [];
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      requests.push({ url: request.url, headers: request.headers });
      respondChat(response);
    });
  });
  try {
    const port = await listen(server);
    const adapter = captureAdapter({
      groq: profile("openai-completions", `http://127.0.0.1:${port}/v1`)
    }, (name) => {
      if (name === "credentials") {
        credentialLookups.push(name);
        return {
          readRecord: async () => { throw new Error("stored credential lookup must not run"); },
          resolve: async () => { throw new Error("ambient credential lookup must not run"); },
          listRecords: async () => { throw new Error("credential listing must not run"); }
        };
      }
      if (name === "launchEnvironment") {
        credentialLookups.push(name);
        return { get: () => { throw new Error("launch environment lookup must not run"); } };
      }
      return undefined;
    });
    const chunks = [];
    for await (const chunk of adapter.stream({
      provider: "groq",
      model: model.id,
      messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }]
    })) chunks.push(chunk);
    assert.ok(chunks.some((chunk) => chunk.type === "finish" && chunk.reason?.kind === "stop"));
  } finally {
    await close(server);
  }
  assert.deepEqual(credentialLookups, []);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers.authorization, undefined);
  assert.equal(requests[0].headers["x-api-key"], undefined);
  assert.equal(requests[0].headers["cf-aig-authorization"], undefined);
});

test("no-auth admission rejects cloud, hostname, public, ambiguous, and credential-bearing routes", () => {
  const reject = (candidate, expected) => assert.throws(
    () => captureAdapter({ rejected: candidate }),
    expected
  );
  reject(profile("openai-completions", "https://example.com/v1"), /literal loopback, RFC1918, or IPv6 ULA/u);
  reject(profile("openai-completions", "http://localhost:11434/v1"), /literal loopback, RFC1918, or IPv6 ULA/u);
  reject(profile("openai-completions", "https://8.8.8.8/v1"), /literal loopback, RFC1918, or IPv6 ULA/u);
  reject(profile("openai-completions", "http://127.1:11434/v1"), /literal loopback, RFC1918, or IPv6 ULA/u);
  reject(profile("openai-completions", "http://127.0.0.1:11434/v1", { apiKeyEnv: "PRIVATE_KEY" }), /cannot combine unauthenticated mode with apiKeyEnv/u);
  for (const headers of [
    { Authorization: "Bearer forbidden" },
    { "api-key": "forbidden" },
    { "x-goog-api-key": "forbidden" },
    { "x-private-token": "forbidden" },
    { "x-benign-metadata": "also forbidden in explicit no-auth mode" }
  ]) {
    reject(
      profile("openai-completions", "http://127.0.0.1:11434/v1", { headers }),
      /cannot combine unauthenticated mode with custom headers/u
    );
  }
  reject({
    ...profile("anthropic-messages", "https://api.anthropic.com/v1"),
    unauthenticated: false,
    apiKeyEnv: "ANTHROPIC_API_KEY"
  }, /baseURL must stop before \/v1/u);

  assert.doesNotThrow(() => captureAdapter({
    privateIPv4: profile("openai-completions", "http://192.168.1.5:11434/v1"),
    privateIPv6: profile("openai-completions", "http://[fd00::1]:11434/v1")
  }));
});

test("ordinary keyless pi-ai requests still fail closed", async () => {
  const adapter = captureAdapter({
    keyless: {
      displayName: "Keyless fixture",
      api: "openai-completions",
      baseURL: "http://127.0.0.1:1/v1",
      models: [model]
    }
  });
  const chunks = [];
  for await (const chunk of adapter.stream({
      provider: "keyless",
      model: model.id,
      messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }]
  })) chunks.push(chunk);
  assert.ok(
    chunks.some((chunk) => chunk.type === "finish"
      && chunk.reason?.kind === "error"
      && /No API key for provider/u.test(chunk.reason.failure?.message ?? "")),
    JSON.stringify(chunks)
  );
});
