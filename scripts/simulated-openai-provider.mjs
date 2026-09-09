import http from "node:http";
import { appendFileSync, writeFileSync } from "node:fs";

const [readyPath, logPath, expectedKey, model = "simulated-tool-model"] = process.argv.slice(2);
if (!readyPath || !logPath || !expectedKey) throw new Error("simulated provider arguments are incomplete");
const host = "127.0.0.1";
const openResponses = new Set();

function log(event) {
  appendFileSync(logPath, `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`, { encoding: "utf8", mode: 0o600 });
}

function json(response, status, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  response.writeHead(status, { "content-type": "application/json", "content-length": String(bytes.length) });
  response.end(bytes);
}

function sse(response, chunks, finishReason = "stop") {
  response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
  const id = `chatcmpl-${Date.now()}`;
  for (const delta of chunks) {
    response.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: 1, model, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
  }
  response.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: 1, model, choices: [{ index: 0, delta: {}, finish_reason: finishReason }] })}\n\n`);
  response.end("data: [DONE]\n\n");
}

function messageText(messages) {
  return messages.flatMap((message) => {
    if (typeof message?.content === "string") return [message.content];
    if (Array.isArray(message?.content)) return message.content.flatMap((part) => typeof part?.text === "string" ? [part.text] : []);
    return [];
  }).join("\n");
}

const server = http.createServer((request, response) => {
  const authorized = request.headers.authorization === `Bearer ${expectedKey}`;
  if (!authorized) {
    log({ kind: "unauthorized", method: request.method, url: request.url });
    json(response, 401, { error: { message: "invalid simulated credential", type: "invalid_request_error" } });
    return;
  }
  if (request.method === "GET" && request.url === "/v1/models") {
    log({ kind: "catalog", authorized: true });
    json(response, 200, { object: "list", data: [{ id: model, object: "model", created: 1, owned_by: "local-harness-contract" }] });
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
    json(response, 404, { error: { message: "not found" } });
    return;
  }
  const chunks = [];
  let size = 0;
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > 1_048_576) request.destroy();
    else chunks.push(chunk);
  });
  request.on("end", () => {
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { json(response, 400, { error: { message: "invalid json" } }); return; }
    const messages = Array.isArray(body.messages) ? body.messages : [];
    const text = messageText(messages);
    const toolDefinitions = Array.isArray(body.tools) ? body.tools : [];
    const tools = toolDefinitions.map((tool) => tool?.function?.name).filter(Boolean);
    const mcpTool = toolDefinitions.find((tool) => tool?.function?.name === "mcp__security_canary__security_canary");
    const toolMessages = messages
      .filter((message) => message?.role === "tool")
      .map((message) => ({ toolCallId: message.tool_call_id, content: message.content }));
    const maxTokenFields = ["max_tokens", "max_completion_tokens"]
      .filter((field) => Object.hasOwn(body, field));
    log({
      kind: "chat",
      authorized: true,
      model: body.model,
      stream: body.stream,
      maxTokens: maxTokenFields.length === 1 ? body[maxTokenFields[0]] : undefined,
      maxTokensField: maxTokenFields.length === 1 ? maxTokenFields[0] : undefined,
      maxTokensFieldCount: maxTokenFields.length,
      reasoningEffort: body.reasoning_effort,
      tools,
      text,
      ...(mcpTool === undefined ? {} : { mcpTool: mcpTool.function }),
      ...(toolMessages.length === 0 ? {} : { toolMessages })
    });
    if (body.model !== model) {
      json(response, 400, { error: { message: "wrong exact model route", type: "invalid_request_error" } });
      return;
    }
    if (text.includes("CONTRACT_ERROR")) {
      json(response, 429, { error: { message: "simulated rate limit", type: "rate_limit_error", code: "rate_limit" } });
      return;
    }
    if (text.includes("CONTRACT_AUTO_CONTINUE")) {
      if (!text.includes("Continue the unfinished user task from exactly where the previous response stopped.")) {
        sse(response, [{ role: "assistant" }, { content: "SIMULATED_AUTOCONTINUE_PARTIAL" }], "length");
        return;
      }
      sse(response, [{ role: "assistant" }, { content: "SIMULATED_AUTOCONTINUE_OK" }]);
      return;
    }
    if (text.includes("CONTRACT_CANCEL")) {
      response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      response.write(`data: ${JSON.stringify({ id: "chatcmpl-cancel", object: "chat.completion.chunk", created: 1, model, choices: [{ index: 0, delta: { role: "assistant", content: "WAITING" }, finish_reason: null }] })}\n\n`);
      openResponses.add(response);
      const closed = () => {
        if (!openResponses.delete(response)) return;
        log({ kind: "cancelled", model });
      };
      response.on("close", closed);
      return;
    }
    if (text.includes("CONTRACT_MCP_DENY") || text.includes("CONTRACT_MCP_ALLOW")) {
      const hasToolResult = messages.some((message) => message?.role === "tool");
      const toolName = "mcp__security_canary__security_canary";
      if (!hasToolResult) {
        if (tools.filter((name) => name === toolName).length !== 1) {
          json(response, 400, { error: { message: "The exact reviewed MCP tool was not offered once", type: "invalid_request_error" } });
          return;
        }
        const callId = text.includes("CONTRACT_MCP_DENY") ? "call_mcp_deny_1" : "call_mcp_allow_1";
        sse(response, [{
          role: "assistant",
          tool_calls: [{
            index: 0,
            id: callId,
            type: "function",
            function: { name: toolName, arguments: "{}" }
          }]
        }], "tool_calls");
        return;
      }
      const marker = text.includes("CONTRACT_MCP_DENY")
        ? "SIMULATED_MCP_DENY_OK"
        : "SIMULATED_MCP_ALLOW_OK";
      sse(response, [{ role: "assistant" }, { content: marker }]);
      return;
    }
    if (text.includes("CONTRACT_WEB_FETCH")) {
      const hasToolResult = messages.some((message) => message?.role === "tool");
      const toolName = "web_fetch";
      if (!hasToolResult) {
        if (tools.filter((name) => name === toolName).length !== 1 || tools.includes("web_search")) {
          json(response, 400, { error: { message: "The exact fetch-only web tool was not offered once", type: "invalid_request_error" } });
          return;
        }
        sse(response, [{
          role: "assistant",
          tool_calls: [{
            index: 0,
            id: "call_web_fetch_1",
            type: "function",
            function: { name: toolName, arguments: JSON.stringify({ url: "https://www.darkbloom.dev/" }) }
          }]
        }], "tool_calls");
        return;
      }
      sse(response, [{ role: "assistant" }, { content: "SIMULATED_WEB_FETCH_OK" }]);
      return;
    }
    if (text.includes("CONTRACT_TOOL")) {
      const hasToolResult = messages.some((message) => message?.role === "tool");
      if (!hasToolResult) {
        const bashName = tools.find((name) => String(name).toLowerCase() === "bash");
        if (!bashName) {
          json(response, 400, { error: { message: "Bash tool was not offered", type: "invalid_request_error" } });
          return;
        }
        const argumentsJSON = JSON.stringify({
          command: "printf 'SIMULATED_TOOL_FILE_OK\\n' > simulated-provider-tool.txt",
          description: "Write the simulated provider contract canary"
        });
        sse(response, [{ role: "assistant", tool_calls: [{ index: 0, id: "call_contract_1", type: "function", function: { name: bashName, arguments: argumentsJSON } }] }], "tool_calls");
        return;
      }
      sse(response, [{ role: "assistant" }, { content: "SIMULATED_TOOL_OK" }]);
      return;
    }
    if (text.includes("CONTRACT_FRESH_B")) {
      sse(response, [{ role: "assistant" }, { content: text.includes("PRIVATE_OLD_CONTEXT") ? "SIMULATED_FRESH_LEAK" : "SIMULATED_FRESH_OK" }]);
      return;
    }
    if (text.includes("CONTRACT_FRESH_A")) {
      sse(response, [{ role: "assistant" }, { content: "SIMULATED_FRESH_A_OK" }]);
      return;
    }
    sse(response, [{ role: "assistant" }, { content: "SIMULATED_SIMPLE_OK" }]);
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
  writeFileSync(readyPath, `${JSON.stringify({ host, port: address.port, origin: `http://${host}:${address.port}` })}\n`, { mode: 0o600, flag: "wx" });
  log({ kind: "ready", host, port: address.port, model });
});
