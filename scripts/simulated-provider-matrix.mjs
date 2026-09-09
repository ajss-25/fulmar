import http from "node:http";
import { appendFileSync, writeFileSync } from "node:fs";

const [readyPath, logPath] = process.argv.slice(2);
if (!readyPath || !logPath) throw new Error("provider-matrix fixture paths are required");

const host = "127.0.0.1";
const maximumRequestBytes = 1_048_576;
const oversizedResponseBytes = 131_072;
const openResponses = new Set();
const attempts = new Map();
const harnessMode = process.env.MATRIX_HARNESS_MODE === "1";

const routes = Object.freeze({
  deepseek: Object.freeze({
    id: "deepseek",
    protocol: "chat-completions",
    basePath: "/deepseek/v1",
    path: "/deepseek/v1/chat/completions",
    key: process.env.MATRIX_DEEPSEEK_KEY,
    model: "matrix-deepseek-model",
    token: "DEEPSEEK"
  }),
  responses: Object.freeze({
    id: "responses",
    protocol: "openai-responses",
    basePath: "/responses/v1",
    path: "/responses/v1/responses",
    key: process.env.MATRIX_RESPONSES_KEY,
    model: "matrix-responses-model",
    token: "RESPONSES"
  }),
  anthropic: Object.freeze({
    id: "anthropic",
    protocol: "anthropic-messages",
    // Anthropic's SDK appends `/v1/messages` to its configured origin. Unlike
    // OpenAI-compatible clients, its base URL therefore stops before `/v1`.
    basePath: "/anthropic",
    path: "/anthropic/v1/messages",
    key: process.env.MATRIX_ANTHROPIC_KEY,
    model: "matrix-anthropic-model",
    token: "ANTHROPIC"
  }),
  custom: Object.freeze({
    id: "custom",
    protocol: "chat-completions",
    basePath: "/custom/v1",
    path: "/custom/v1/chat/completions",
    key: process.env.MATRIX_CUSTOM_KEY,
    model: "matrix-custom-model",
    token: "CUSTOM"
  })
});

for (const route of Object.values(routes)) {
  if (typeof route.key !== "string" || route.key.length < 16) {
    throw new Error(`provider-matrix credential is missing for ${route.id}`);
  }
}

const routesByPath = new Map(Object.values(routes).map((route) => [route.path, route]));

function log(event) {
  appendFileSync(
    logPath,
    `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
}

function json(response, status, body, headers = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(bytes.length),
    ...headers
  });
  response.end(bytes);
}

function openSSE(response) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive"
  });
}

function sseData(response, value, event) {
  if (event) response.write(`event: ${event}\n`);
  response.write(`data: ${typeof value === "string" ? value : JSON.stringify(value)}\n\n`);
}

function recursivelyCollectStrings(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) for (const entry of value) recursivelyCollectStrings(entry, output);
  else if (value && typeof value === "object") for (const entry of Object.values(value)) recursivelyCollectStrings(entry, output);
  return output;
}

const markers = Object.freeze([
  "MATRIX_SIMPLE",
  "MATRIX_TOOL_IDENTITY_OMITTED",
  "MATRIX_TOOL_IDENTITY_NULL",
  "MATRIX_TOOL_IDENTITY_EMPTY",
  "MATRIX_TOOL_IDENTITY_REPEATED",
  "MATRIX_TOOL_IDENTITY_CONFLICTING",
  "MATRIX_TOOL",
  "MATRIX_CANCEL",
  "MATRIX_ERROR_401",
  "MATRIX_ERROR_402",
  "MATRIX_ERROR_429",
  "MATRIX_ERROR_500",
  "MATRIX_RETRY_SUCCESS_429",
  "MATRIX_MALFORMED",
  "MATRIX_OVERSIZED_CHUNKED",
  "MATRIX_OVERSIZED"
]);

function markerOf(body) {
  const all = recursivelyCollectStrings(body).join("\n");
  return markers.find((marker) => all.includes(marker)) ?? "MATRIX_SIMPLE";
}

function toolNames(route, body) {
  if (!Array.isArray(body.tools)) return [];
  return body.tools.map((tool) => {
    if (route.protocol === "chat-completions") return tool?.function?.name;
    return tool?.name;
  }).filter((name) => typeof name === "string");
}

function hasToolResult(route, body) {
  if (route.protocol === "chat-completions") {
    return Array.isArray(body.messages) && body.messages.some((message) => message?.role === "tool");
  }
  if (route.protocol === "openai-responses") {
    return Array.isArray(body.input) && body.input.some((item) => item?.type === "function_call_output");
  }
  return Array.isArray(body.messages) && body.messages.some((message) =>
    Array.isArray(message?.content) && message.content.some((part) => part?.type === "tool_result")
  );
}

function requestShape(route, request, body) {
  const contentType = String(request.headers["content-type"] ?? "").toLowerCase();
  const userAgent = String(request.headers["user-agent"] ?? "");
  const common = {
    json: contentType.startsWith("application/json"),
    attributed: userAgent.startsWith("deepseek-harness/"),
    model: body.model === route.model,
    stream: body.stream === true,
    tools: toolNames(route, body),
    hasToolResult: hasToolResult(route, body),
    bodyKeys: Object.keys(body).sort(),
    messageCount: Array.isArray(body.messages) ? body.messages.length : undefined,
    inputCount: Array.isArray(body.input) ? body.input.length : undefined,
    roles: (Array.isArray(body.messages) ? body.messages : Array.isArray(body.input) ? body.input : [])
      .map((entry) => entry?.role ?? entry?.type).filter((value) => typeof value === "string"),
    assistantToolCalls: route.protocol === "chat-completions" && Array.isArray(body.messages)
      ? body.messages.flatMap((message) => Array.isArray(message?.tool_calls)
        ? message.tool_calls.map((call) => ({ id: call?.id, name: call?.function?.name }))
        : [])
      : [],
    toolResultCallIds: route.protocol === "chat-completions" && Array.isArray(body.messages)
      ? body.messages.filter((message) => message?.role === "tool")
        .map((message) => message?.tool_call_id)
      : [],
    outputCapValue: body.max_tokens ?? body.max_output_tokens,
    privateIdentifiersAbsent:
      request.headers["x-deepseek-harness-user-id"] === undefined
      && request.headers["x-deepseek-harness-session-id"] === undefined
  };
  if (route.protocol === "openai-responses") {
    return {
      ...common,
      input: Array.isArray(body.input),
      storeDisabled: body.store === false,
      outputCap: Number.isSafeInteger(body.max_output_tokens) && body.max_output_tokens > 0
    };
  }
  if (route.protocol === "anthropic-messages") {
    return {
      ...common,
      messages: Array.isArray(body.messages),
      outputCap: Number.isSafeInteger(body.max_tokens) && body.max_tokens > 0,
      anthropicVersion: typeof request.headers["anthropic-version"] === "string"
        && request.headers["anthropic-version"].length > 0
    };
  }
  return {
    ...common,
    messages: Array.isArray(body.messages),
    streamUsage: body.stream_options?.include_usage === true,
    outputCap: Number.isSafeInteger(body.max_tokens) && body.max_tokens > 0,
    ...(route.id === "deepseek" ? {
      thinkingDisabled: body.thinking?.type === "disabled" && body.reasoning_effort === undefined
    } : {})
  };
}

function validShape(route, shape) {
  const common = shape.json && shape.attributed && shape.model && shape.stream
    && shape.privateIdentifiersAbsent;
  if (!common) return false;
  if (route.protocol === "openai-responses") {
    return shape.input && shape.storeDisabled && shape.outputCap;
  }
  if (route.protocol === "anthropic-messages") {
    return shape.messages && shape.outputCap && shape.anthropicVersion;
  }
  return shape.messages && shape.streamUsage && shape.outputCap
    && (route.id !== "deepseek" || (shape.thinkingDisabled && shape.privateIdentifiersAbsent));
}

function isAuthorized(route, request) {
  if (route.protocol === "anthropic-messages") {
    return request.headers["x-api-key"] === route.key;
  }
  return request.headers.authorization === `Bearer ${route.key}`;
}

function errorBody(route, status, message) {
  if (route.protocol === "anthropic-messages") {
    return {
      type: "error",
      error: {
        type: status === 401 ? "authentication_error" : status === 429 ? "rate_limit_error" : "api_error",
        message
      }
    };
  }
  return {
    error: {
      message,
      type: status === 401
        ? "authentication_error"
        : status === 402
          ? "insufficient_balance"
          : status === 429
            ? "rate_limit_error"
            : "server_error",
      code: status === 402 ? "insufficient_balance" : status === 429 ? "rate_limit" : undefined
    }
  };
}

function writeChatCompletion(route, response, text) {
  openSSE(response);
  const id = `chatcmpl-matrix-${route.id}`;
  const chunk = (delta, finishReason = null, usage) => ({
    id,
    object: "chat.completion.chunk",
    created: 1,
    model: route.model,
    choices: usage ? [] : [{ index: 0, delta, finish_reason: finishReason }],
    ...(usage ? { usage } : {})
  });
  const midpoint = Math.max(1, Math.floor(text.length / 2));
  sseData(response, chunk({ role: "assistant", content: text.slice(0, midpoint) }));
  sseData(response, chunk({ content: text.slice(midpoint) }));
  sseData(response, chunk({}, "stop"));
  sseData(response, chunk({}, null, {
    prompt_tokens: 4,
    completion_tokens: 2,
    total_tokens: 6
  }));
  sseData(response, "[DONE]");
  response.end();
}

function writeChatToolCall(route, response, toolName, identityMode = "standard") {
  openSSE(response);
  const id = `chatcmpl-matrix-${route.id}`;
  const callID = `call_matrix_${route.id}`;
  const suffix = identityMode === "standard" ? "" : `-identity-${identityMode}`;
  const filename = `matrix-${route.id}-tool${suffix}.txt`;
  const redirect = identityMode === "standard" ? ">" : ">>";
  const argumentsJSON = JSON.stringify({
    command: `printf '${route.token}_TOOL_FILE_OK\\n' ${redirect} ${filename}`,
    description: `Write the ${route.id} protocol-matrix canary`
  });
  const frame = (delta, finishReason = null) => ({
    id,
    object: "chat.completion.chunk",
    created: 1,
    model: route.model,
    choices: [{ index: 0, delta, finish_reason: finishReason }]
  });
  const firstBoundary = Math.max(1, Math.floor(argumentsJSON.length / 3));
  const secondBoundary = Math.max(firstBoundary + 1, Math.floor(argumentsJSON.length * 2 / 3));
  sseData(response, frame({
    role: "assistant",
    tool_calls: [{
      index: 0,
      id: callID,
      type: "function",
      function: { name: toolName, arguments: argumentsJSON.slice(0, firstBoundary) }
    }]
  }));
  let continuationIdentity = {};
  if (identityMode === "null") continuationIdentity = { id: null, name: null };
  else if (identityMode === "empty") continuationIdentity = { id: "", name: "" };
  else if (identityMode === "repeated") continuationIdentity = { id: callID, name: toolName };
  else if (identityMode === "conflicting") {
    continuationIdentity = { id: "call_matrix_untrusted_retarget", name: "Read" };
  }
  for (const fragment of [
    argumentsJSON.slice(firstBoundary, secondBoundary),
    argumentsJSON.slice(secondBoundary)
  ]) {
    sseData(response, frame({
      tool_calls: [{
        index: 0,
        ...Object.hasOwn(continuationIdentity, "id") ? { id: continuationIdentity.id } : {},
        function: {
          ...Object.hasOwn(continuationIdentity, "name") ? { name: continuationIdentity.name } : {},
          arguments: fragment
        }
      }]
    }));
  }
  sseData(response, frame({}, "tool_calls"));
  sseData(response, "[DONE]");
  response.end();
}

function responseEnvelope(route, status, output = [], usage) {
  return {
    id: `resp_matrix_${route.id}`,
    object: "response",
    created_at: 1,
    status,
    model: route.model,
    output,
    parallel_tool_calls: true,
    error: null,
    incomplete_details: null,
    instructions: null,
    metadata: {},
    ...(usage ? { usage } : {})
  };
}

function writeResponsesText(route, response, text) {
  openSSE(response);
  const item = {
    id: `msg_matrix_${route.id}`,
    type: "message",
    status: "completed",
    role: "assistant",
    content: [{ type: "output_text", text, annotations: [] }]
  };
  const inProgress = { ...item, status: "in_progress", content: [] };
  const midpoint = Math.max(1, Math.floor(text.length / 2));
  sseData(response, { type: "response.created", response: responseEnvelope(route, "in_progress") }, "response.created");
  sseData(response, { type: "response.output_item.added", output_index: 0, item: inProgress }, "response.output_item.added");
  sseData(response, { type: "response.output_text.delta", output_index: 0, content_index: 0, item_id: item.id, delta: text.slice(0, midpoint) }, "response.output_text.delta");
  sseData(response, { type: "response.output_text.delta", output_index: 0, content_index: 0, item_id: item.id, delta: text.slice(midpoint) }, "response.output_text.delta");
  sseData(response, { type: "response.output_item.done", output_index: 0, item }, "response.output_item.done");
  sseData(response, {
    type: "response.completed",
    response: responseEnvelope(route, "completed", [item], {
      input_tokens: 4,
      input_tokens_details: { cached_tokens: 0 },
      output_tokens: 2,
      output_tokens_details: { reasoning_tokens: 0 },
      total_tokens: 6
    })
  }, "response.completed");
  sseData(response, "[DONE]");
  response.end();
}

function writeResponsesToolCall(route, response, toolName) {
  openSSE(response);
  const argumentsJSON = JSON.stringify({
    command: `printf '${route.token}_TOOL_FILE_OK\\n' > matrix-${route.id}-tool.txt`,
    description: `Write the ${route.id} protocol-matrix canary`
  });
  const midpoint = Math.max(1, Math.floor(argumentsJSON.length / 2));
  const item = {
    id: `fc_matrix_${route.id}`,
    type: "function_call",
    status: "completed",
    call_id: `call_matrix_${route.id}`,
    name: toolName,
    arguments: argumentsJSON
  };
  sseData(response, { type: "response.created", response: responseEnvelope(route, "in_progress") }, "response.created");
  sseData(response, {
    type: "response.output_item.added",
    output_index: 0,
    item: { ...item, status: "in_progress", arguments: "" }
  }, "response.output_item.added");
  sseData(response, { type: "response.function_call_arguments.delta", output_index: 0, item_id: item.id, delta: argumentsJSON.slice(0, midpoint) }, "response.function_call_arguments.delta");
  sseData(response, { type: "response.function_call_arguments.delta", output_index: 0, item_id: item.id, delta: argumentsJSON.slice(midpoint) }, "response.function_call_arguments.delta");
  sseData(response, { type: "response.function_call_arguments.done", output_index: 0, item_id: item.id, arguments: argumentsJSON }, "response.function_call_arguments.done");
  sseData(response, { type: "response.output_item.done", output_index: 0, item }, "response.output_item.done");
  sseData(response, {
    type: "response.completed",
    response: responseEnvelope(route, "completed", [item], {
      input_tokens: 4,
      input_tokens_details: { cached_tokens: 0 },
      output_tokens: 2,
      output_tokens_details: { reasoning_tokens: 0 },
      total_tokens: 6
    })
  }, "response.completed");
  sseData(response, "[DONE]");
  response.end();
}

function anthropicEvent(response, type, body) {
  sseData(response, { type, ...body }, type);
}

function writeAnthropicStart(route, response) {
  anthropicEvent(response, "message_start", {
    message: {
      id: `msg_matrix_${route.id}`,
      type: "message",
      role: "assistant",
      model: route.model,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 4, output_tokens: 0 }
    }
  });
}

function writeAnthropicText(route, response, text) {
  openSSE(response);
  writeAnthropicStart(route, response);
  anthropicEvent(response, "content_block_start", { index: 0, content_block: { type: "text", text: "" } });
  const midpoint = Math.max(1, Math.floor(text.length / 2));
  anthropicEvent(response, "content_block_delta", { index: 0, delta: { type: "text_delta", text: text.slice(0, midpoint) } });
  anthropicEvent(response, "content_block_delta", { index: 0, delta: { type: "text_delta", text: text.slice(midpoint) } });
  anthropicEvent(response, "content_block_stop", { index: 0 });
  anthropicEvent(response, "message_delta", { delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 2 } });
  anthropicEvent(response, "message_stop", {});
  response.end();
}

function writeAnthropicToolCall(route, response, toolName) {
  openSSE(response);
  writeAnthropicStart(route, response);
  const argumentsJSON = JSON.stringify({
    command: `printf '${route.token}_TOOL_FILE_OK\\n' > matrix-${route.id}-tool.txt`,
    description: `Write the ${route.id} protocol-matrix canary`
  });
  const midpoint = Math.max(1, Math.floor(argumentsJSON.length / 2));
  anthropicEvent(response, "content_block_start", {
    index: 0,
    content_block: { type: "tool_use", id: `call_matrix_${route.id}`, name: toolName, input: {} }
  });
  anthropicEvent(response, "content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: argumentsJSON.slice(0, midpoint) } });
  anthropicEvent(response, "content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: argumentsJSON.slice(midpoint) } });
  anthropicEvent(response, "content_block_stop", { index: 0 });
  anthropicEvent(response, "message_delta", { delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 2 } });
  anthropicEvent(response, "message_stop", {});
  response.end();
}

function writeText(route, response, text) {
  if (route.protocol === "chat-completions") writeChatCompletion(route, response, text);
  else if (route.protocol === "openai-responses") writeResponsesText(route, response, text);
  else writeAnthropicText(route, response, text);
}

function writeToolCall(route, response, toolName, identityMode = "standard") {
  if (route.protocol === "chat-completions") writeChatToolCall(route, response, toolName, identityMode);
  else if (route.protocol === "openai-responses") writeResponsesToolCall(route, response, toolName);
  else writeAnthropicToolCall(route, response, toolName);
}

function writeCancellationStart(route, response) {
  if (route.protocol === "chat-completions") {
    openSSE(response);
    sseData(response, {
      id: `chatcmpl-cancel-${route.id}`,
      object: "chat.completion.chunk",
      created: 1,
      model: route.model,
      choices: [{ index: 0, delta: { role: "assistant", content: `WAITING_${route.token}` }, finish_reason: null }]
    });
  } else if (route.protocol === "openai-responses") {
    openSSE(response);
    const item = { id: `msg_cancel_${route.id}`, type: "message", status: "in_progress", role: "assistant", content: [] };
    sseData(response, { type: "response.created", response: responseEnvelope(route, "in_progress") }, "response.created");
    sseData(response, { type: "response.output_item.added", output_index: 0, item }, "response.output_item.added");
    sseData(response, { type: "response.output_text.delta", output_index: 0, content_index: 0, item_id: item.id, delta: `WAITING_${route.token}` }, "response.output_text.delta");
  } else {
    openSSE(response);
    writeAnthropicStart(route, response);
    anthropicEvent(response, "content_block_start", { index: 0, content_block: { type: "text", text: "" } });
    anthropicEvent(response, "content_block_delta", { index: 0, delta: { type: "text_delta", text: `WAITING_${route.token}` } });
  }
  openResponses.add(response);
  response.on("close", () => {
    if (!openResponses.delete(response)) return;
    log({ kind: "cancelled", route: route.id, protocol: route.protocol });
  });
}

function writeMalformed(route, response) {
  openSSE(response);
  if (route.protocol === "openai-responses") response.write("event: response.output_text.delta\n");
  else if (route.protocol === "anthropic-messages") response.write("event: message_start\n");
  response.end("data: {\"malformed\"\n\n");
}

function writeOversized(response) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "content-length": String(oversizedResponseBytes),
    "cache-control": "no-cache"
  });
  response.end(Buffer.alloc(oversizedResponseBytes, 0x78));
}

function writeOversizedChunked(response) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache"
  });
  const chunk = Buffer.alloc(16_384, 0x78);
  for (let written = 0; written < oversizedResponseBytes; written += chunk.length) {
    response.write(chunk.subarray(0, Math.min(chunk.length, oversizedResponseBytes - written)));
  }
  response.end();
}

const server = http.createServer((request, response) => {
  const route = routesByPath.get(request.url ?? "");
  if (!route || request.method !== "POST") {
    json(response, 404, { error: { message: "not found" } });
    return;
  }

  if (!isAuthorized(route, request)) {
    log({ kind: "unauthorized", route: route.id, protocol: route.protocol, method: request.method, path: request.url });
    json(response, 401, errorBody(route, 401, "invalid matrix credential"));
    return;
  }

  const chunks = [];
  let size = 0;
  let rejected = false;
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > maximumRequestBytes) {
      rejected = true;
      request.destroy();
    } else {
      chunks.push(chunk);
    }
  });
  request.on("end", () => {
    if (rejected) return;
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      json(response, 400, errorBody(route, 400, "invalid json"));
      return;
    }

    const marker = markerOf(body);
    const shape = requestShape(route, request, body);
    // The full DSH composition performs one concurrent context-injection call
    // without model-facing tools and one agent call with the reviewed tool
    // catalog. Keep their retry chains independent so the fixture can prove
    // exact adapter retry bounds rather than conflating two consumers.
    const phase = harnessMode && shape.tools.length === 0 && !shape.hasToolResult ? "context" : "agent";
    const key = `${route.id}:${marker}:${phase}`;
    const attempt = (attempts.get(key) ?? 0) + 1;
    attempts.set(key, attempt);
    log({
      kind: "request",
      route: route.id,
      protocol: route.protocol,
      marker,
      phase,
      attempt,
      authorized: true,
      shape
    });

    if (!validShape(route, shape)) {
      json(response, 422, errorBody(route, 422, "request did not match the protocol contract"));
      return;
    }
    if (phase === "context") {
      writeText(route, response, `${route.token}_CONTEXT_OK`);
      return;
    }
    if (marker === "MATRIX_ERROR_401") {
      json(response, 401, errorBody(route, 401, "matrix authentication failure"));
      return;
    }
    if (marker === "MATRIX_ERROR_402") {
      json(response, 402, errorBody(route, 402, "matrix insufficient balance"));
      return;
    }
    if (marker === "MATRIX_ERROR_429" || (marker === "MATRIX_RETRY_SUCCESS_429" && attempt <= 2)) {
      json(response, 429, errorBody(route, 429, "matrix rate limit"), { "retry-after": "0.01", "x-request-id": `matrix-${route.id}-429-${attempt}` });
      return;
    }
    if (marker === "MATRIX_ERROR_500") {
      json(response, 503, errorBody(route, 503, "matrix server failure"), { "retry-after": "0.01", "x-request-id": `matrix-${route.id}-503-${attempt}` });
      return;
    }
    if (marker === "MATRIX_CANCEL") {
      writeCancellationStart(route, response);
      return;
    }
    if (marker === "MATRIX_MALFORMED") {
      writeMalformed(route, response);
      return;
    }
    if (marker === "MATRIX_OVERSIZED") {
      writeOversized(response);
      return;
    }
    if (marker === "MATRIX_OVERSIZED_CHUNKED") {
      writeOversizedChunked(response);
      return;
    }
    if (marker === "MATRIX_TOOL" || marker.startsWith("MATRIX_TOOL_IDENTITY_")) {
      if (shape.hasToolResult) {
        writeText(route, response, `${route.token}_TOOL_OK`);
        return;
      }
      const toolName = shape.tools.find((name) => name.toLowerCase() === "bash");
      if (!toolName) {
        json(response, 400, errorBody(route, 400, "Bash tool was not offered"));
        return;
      }
      const identityMode = marker.startsWith("MATRIX_TOOL_IDENTITY_")
        ? marker.slice("MATRIX_TOOL_IDENTITY_".length).toLowerCase()
        : "standard";
      writeToolCall(route, response, toolName, identityMode);
      return;
    }
    writeText(route, response, `${route.token}_SIMPLE_OK`);
  });
});

function shutdown() {
  for (const response of openResponses) response.destroy();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1_000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
server.listen(0, host, () => {
  const address = server.address();
  const origin = `http://${host}:${address.port}`;
  writeFileSync(readyPath, `${JSON.stringify({
    host,
    port: address.port,
    origin,
    oversizedResponseBytes,
    routes: Object.fromEntries(Object.values(routes).map((route) => [route.id, {
      protocol: route.protocol,
      model: route.model,
      url: `${origin}${route.path}`,
      baseURL: `${origin}${route.basePath}`
    }]))
  })}\n`, { mode: 0o600, flag: "wx" });
  log({ kind: "ready", host, port: address.port, routes: Object.keys(routes) });
});
