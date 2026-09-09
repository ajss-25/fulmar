import assert from "node:assert/strict";
import test from "node:test";

import { DeepSeekAdapter } from "../../VendorRuntime/node_modules/@deepseek-ai/dsh-llm-deepseek/lib/index.js";

const CALL_ID = "call_fulmar_identity_1";
const TOOL_NAME = "Bash";
const ARGUMENTS = JSON.stringify({
  command: "printf 'FULMAR_STREAM_IDENTITY_OK\\n'",
  description: "Exercise the streamed tool identity boundary"
});

const scenarios = Object.freeze({
  omitted: Object.freeze([
    Object.freeze({ index: 0, function: Object.freeze({ arguments: ARGUMENTS.slice(31) }) })
  ]),
  null: Object.freeze([
    Object.freeze({ index: 0, id: null, function: Object.freeze({ name: null, arguments: ARGUMENTS.slice(31) }) })
  ]),
  empty: Object.freeze([
    Object.freeze({ index: 0, id: "", function: Object.freeze({ name: "", arguments: ARGUMENTS.slice(31) }) })
  ]),
  "repeated identity across fragmented arguments": Object.freeze([
    Object.freeze({
      index: 0,
      id: CALL_ID,
      function: Object.freeze({ name: TOOL_NAME, arguments: ARGUMENTS.slice(31, 67) })
    }),
    Object.freeze({
      index: 0,
      id: CALL_ID,
      function: Object.freeze({ name: TOOL_NAME, arguments: ARGUMENTS.slice(67) })
    })
  ]),
  "conflicting non-empty identity across fragmented arguments": Object.freeze([
    Object.freeze({
      index: 0,
      id: "call_untrusted_retarget",
      function: Object.freeze({ name: "Read", arguments: ARGUMENTS.slice(31, 67) })
    }),
    Object.freeze({
      index: 0,
      id: "call_second_untrusted_retarget",
      function: Object.freeze({ name: "Write", arguments: ARGUMENTS.slice(67) })
    })
  ])
});

function data(payload) {
  return `data: ${typeof payload === "string" ? payload : JSON.stringify(payload)}\n\n`;
}

function frame(delta, finishReason = null) {
  return {
    id: "chatcmpl-fulmar-identity",
    object: "chat.completion.chunk",
    created: 1,
    model: "fixture-deepseek-model",
    choices: [{ index: 0, delta, finish_reason: finishReason }]
  };
}

function toolResponse(continuations) {
  const initialEnd = 31;
  return new Response([
    data(frame({
      role: "assistant",
      tool_calls: [{
        index: 0,
        id: CALL_ID,
        type: "function",
        function: { name: TOOL_NAME, arguments: ARGUMENTS.slice(0, initialEnd) }
      }]
    })),
    ...continuations.map((call) => data(frame({ tool_calls: [call] }))),
    data(frame({}, "tool_calls")),
    data("[DONE]")
  ].join(""), {
    status: 200,
    headers: { "content-type": "text/event-stream" }
  });
}

function finalResponse() {
  return new Response([
    data(frame({ role: "assistant", content: "FULMAR_STREAM_IDENTITY_OK" })),
    data(frame({}, "stop")),
    data("[DONE]")
  ].join(""), {
    status: 200,
    headers: { "content-type": "text/event-stream" }
  });
}

function adapter() {
  const connection = Object.freeze({
    apiKeyEnv: "FULMAR_TEST_DEEPSEEK_KEY",
    baseURL: "https://fixture.deepseek.invalid/v1",
    defaults: Object.freeze({ thinking: "disabled" }),
    maxTokens: 128,
    defaultContextWindow: 4_096,
    models: Object.freeze([]),
    streamIdleTimeoutMs: 2_000,
    maxRequestImageBytes: 1_024,
    retryPolicy: Object.freeze({ mode: "normal", maxRetries: 0 })
  });
  return new DeepSeekAdapter({
    options: () => connection,
    resolveApiKey: async () => "fixture-credential-value"
  });
}

function userMessage(text) {
  return { role: "user", content: [{ type: "text", text }] };
}

async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return chunks;
}

for (const [scenario, continuations] of Object.entries(scenarios)) {
  test(`DeepSeek adapter preserves one valid tool identity when continuation identity is ${scenario}`, async () => {
    const originalFetch = globalThis.fetch;
    const requests = [];
    let fetchCount = 0;
    globalThis.fetch = async (url, init) => {
      requests.push({ url: String(url), body: JSON.parse(String(init?.body)) });
      fetchCount += 1;
      return fetchCount === 1 ? toolResponse(continuations) : finalResponse();
    };

    try {
      const client = adapter();
      const initialMessages = [userMessage(`Direct adapter scenario: ${scenario}`)];
      const first = await collect(client.stream({
        provider: "deepseek-official",
        model: "fixture-deepseek-model",
        messages: initialMessages,
        tools: [{ name: TOOL_NAME, description: "Run a command", parameters: { type: "object" } }]
      }));

      assert.equal(fetchCount, 1, "one provider request produced the tool call");
      const starts = first.filter((chunk) => chunk.type === "block-start" && chunk.blockType === "tool-call");
      const deltas = first.filter((chunk) => chunk.type === "tool-call-delta");
      const ends = first.filter((chunk) => chunk.type === "block-end" && chunk.block.type === "tool-call");
      const finishes = first.filter((chunk) => chunk.type === "finish");
      assert.equal(starts.length, 1, "the adapter opened exactly one tool call");
      assert.equal(ends.length, 1, "the adapter closed exactly one tool call");
      assert.equal(finishes.length, 1, "the stream terminated exactly once");
      assert.deepEqual(finishes[0].reason, { kind: "tool-calls" });
      assert.ok(deltas.length >= 2, "arguments were genuinely fragmented across stream frames");
      assert.ok(deltas.every((chunk) => chunk.id === CALL_ID && chunk.name === TOOL_NAME));

      const tool = ends[0].block;
      assert.deepEqual(tool, {
        type: "tool-call",
        id: CALL_ID,
        name: TOOL_NAME,
        arguments: ARGUMENTS
      });
      assert.deepEqual(JSON.parse(tool.arguments), JSON.parse(ARGUMENTS));

      const second = await collect(client.stream({
        provider: "deepseek-official",
        model: "fixture-deepseek-model",
        messages: [
          ...initialMessages,
          { role: "assistant", content: [tool] },
          {
            role: "user",
            content: [{
              type: "tool-result",
              toolCallId: tool.id,
              content: [{ type: "text", text: "FULMAR_TOOL_RESULT_OK" }]
            }]
          }
        ]
      }));

      assert.equal(fetchCount, 2, "the composed tool exchange required exactly one follow-up request");
      const followUp = requests[1].body.messages;
      const durableCalls = followUp.flatMap((message) => message.tool_calls ?? []);
      const durableResults = followUp.filter((message) => message.role === "tool");
      assert.equal(durableCalls.length, 1, "history contains exactly one tool call");
      assert.equal(durableResults.length, 1, "history contains exactly one matching tool result");
      assert.equal(durableCalls[0].id, CALL_ID);
      assert.equal(durableCalls[0].function.name, TOOL_NAME);
      assert.equal(durableCalls[0].function.arguments, ARGUMENTS);
      assert.equal(durableResults[0].tool_call_id, CALL_ID);
      assert.ok(second.some((chunk) => chunk.type === "block-end"
        && chunk.block.type === "text"
        && chunk.block.text === "FULMAR_STREAM_IDENTITY_OK"));
      assert.deepEqual(second.at(-1), { type: "finish", reason: { kind: "stop" } });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}
