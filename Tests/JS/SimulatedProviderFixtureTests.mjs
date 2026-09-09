import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { assertSimulatedProviderLog } from "../../scripts/verify-simulated-provider-log.mjs";

const project = resolve(import.meta.dirname, "../..");
const serverScript = join(project, "scripts/simulated-openai-provider.mjs");

test("provider log audit separates title generation from the exact tool request and result", () => {
  const model = "fixture-exact-model";
  const chat = (additions) => ({ kind: "chat", authorized: true, model, stream: true, tools: [], text: "", ...additions });
  const rows = [
    { kind: "catalog", authorized: true },
    chat({ text: "CONTRACT_TOOL", tools: [] }),
    chat({ text: "CONTRACT_SIMPLE" }),
    chat({ text: "CONTRACT_FRESH_A" }),
    chat({ text: "CONTRACT_FRESH_B" }),
    chat({ text: "CONTRACT_TOOL", tools: ["Bash"] }),
    chat({ text: "CONTRACT_TOOL", tools: ["Bash"], toolMessages: [{ toolCallId: "call_contract_1", content: "" }] })
  ];
  assert.doesNotThrow(() => assertSimulatedProviderLog(rows, model));
  assert.throws(
    () => assertSimulatedProviderLog([...rows, chat({ text: "CONTRACT_TOOL", tools: ["Bash"] })], model),
    /tool-request-topology/u
  );
});

async function waitFor(predicate, timeoutMilliseconds = 3_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  throw new Error("timed out waiting for the simulated-provider fixture");
}

test("simulated OpenAI-compatible provider covers catalog, stream, tool, error, fresh context, and cancel", { timeout: 15_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "local-harness-provider-fixture-"));
  const readyPath = join(root, "ready.json");
  const logPath = join(root, "events.jsonl");
  const key = "fixture-key-that-must-never-be-logged";
  const model = "fixture-exact-model";
  const child = spawn(process.execPath, [serverScript, readyPath, logPath, key, model], {
    env: { HOME: root, PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "ignore", "pipe"]
  });
  const errors = [];
  child.stderr.on("data", (chunk) => errors.push(chunk));
  const closed = new Promise((resolveClose) => child.on("close", (code, signal) => resolveClose({ code, signal })));
  try {
    await waitFor(async () => {
      try { return JSON.parse(await readFile(readyPath, "utf8")).port > 0; }
      catch { return false; }
    });
    const ready = JSON.parse(await readFile(readyPath, "utf8"));
    assert.equal(ready.host, "127.0.0.1");
    assert.equal(ready.origin, `http://127.0.0.1:${ready.port}`);
    const headers = { authorization: `Bearer ${key}`, "content-type": "application/json" };

    const unauthorized = await fetch(`${ready.origin}/v1/models`);
    assert.equal(unauthorized.status, 401);
    const catalog = await fetch(`${ready.origin}/v1/models`, { headers });
    assert.equal(catalog.status, 200);
    assert.deepEqual((await catalog.json()).data.map((entry) => entry.id), [model]);

    async function chat(marker, additions = {}) {
      return await fetch(`${ready.origin}/v1/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          stream: true,
          messages: [{ role: "user", content: marker }],
          ...additions
        })
      });
    }

    const simple = await chat("CONTRACT_SIMPLE", { max_tokens: 2_048 });
    assert.equal(simple.status, 200);
    assert.match(await simple.text(), /SIMULATED_SIMPLE_OK/);

    const wrongModel = await fetch(`${ready.origin}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ model: `${model}-wrong`, stream: true, messages: [{ role: "user", content: "CONTRACT_SIMPLE" }] })
    });
    assert.equal(wrongModel.status, 400);
    assert.match(JSON.stringify(await wrongModel.json()), /wrong exact model route/);

    const rateLimit = await chat("CONTRACT_ERROR");
    assert.equal(rateLimit.status, 429);
    assert.match(JSON.stringify(await rateLimit.json()), /rate_limit/);

    const toolDefinition = [{ type: "function", function: { name: "Bash", parameters: { type: "object" } } }];
    const toolStart = await chat("CONTRACT_TOOL", { tools: toolDefinition });
    const toolStartText = await toolStart.text();
    assert.match(toolStartText, /call_contract_1/);
    assert.match(toolStartText, /SIMULATED_TOOL_FILE_OK/);
    const toolFinish = await fetch(`${ready.origin}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model,
        stream: true,
        tools: toolDefinition,
        messages: [
          { role: "user", content: "CONTRACT_TOOL" },
          { role: "tool", tool_call_id: "call_contract_1", content: "ok" }
        ]
      })
    });
    assert.match(await toolFinish.text(), /SIMULATED_TOOL_OK/);

    const fresh = await chat("CONTRACT_FRESH_B");
    const freshText = await fresh.text();
    assert.match(freshText, /SIMULATED_FRESH_OK/);
    assert.doesNotMatch(freshText, /SIMULATED_FRESH_LEAK|PRIVATE_OLD_CONTEXT/);

    const abortController = new AbortController();
    const cancellation = await fetch(`${ready.origin}/v1/chat/completions`, {
      method: "POST",
      headers,
      signal: abortController.signal,
      body: JSON.stringify({ model, stream: true, messages: [{ role: "user", content: "CONTRACT_CANCEL" }] })
    });
    assert.match(Buffer.from((await cancellation.body.getReader().read()).value).toString("utf8"), /WAITING/);
    abortController.abort();
    await waitFor(async () => {
      try { return (await readFile(logPath, "utf8")).includes('"kind":"cancelled"'); }
      catch { return false; }
    });

    const log = await readFile(logPath, "utf8");
    assert.doesNotMatch(log, new RegExp(key));
    const rows = log.trim().split("\n").map(JSON.parse);
    assert(rows.some((row) => row.kind === "catalog" && row.authorized === true));
    assert(rows.some((row) => row.kind === "unauthorized"));
    assert(rows.some((row) => row.kind === "chat" && row.model === model && row.stream === true));
    assert(rows.some((row) => row.kind === "chat"
      && row.maxTokens === 2_048
      && row.maxTokensField === "max_tokens"
      && row.maxTokensFieldCount === 1
      && row.reasoningEffort === undefined));
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    const outcome = await Promise.race([
      closed,
      new Promise((resolveWait) => setTimeout(() => resolveWait(undefined), 2_000))
    ]);
    if (outcome === undefined && child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
      await closed;
    }
    await rm(root, { recursive: true, force: true });
    assert.equal(Buffer.concat(errors).toString("utf8"), "");
  }
});
