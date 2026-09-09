import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { apply } from "../../VendorRuntime/node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js";

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
