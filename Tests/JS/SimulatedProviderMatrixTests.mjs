import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  fixtureAuthToken, fixtureInstanceNonce, openRuntimeAuthenticationInput
} from "../Fixtures/RuntimeAuthenticationInput.mjs";

const project = resolve(import.meta.dirname, "../..");
const serverScript = join(project, "scripts/simulated-provider-matrix.mjs");
const securityPreload = join(project, "Resources/RuntimeSecurityPreload.mjs");
const secrets = Object.freeze({
  deepseek: "matrix-deepseek-secret-never-log",
  responses: "matrix-responses-secret-never-log",
  anthropic: "matrix-anthropic-secret-never-log",
  custom: "matrix-custom-secret-never-log"
});

async function waitFor(predicate, timeoutMilliseconds = 3_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  throw new Error("timed out waiting for the provider-matrix fixture");
}

function headersFor(route, key = secrets[route]) {
  const headers = {
    "content-type": "application/json",
    "user-agent": "deepseek-harness/matrix-test (+https://example.invalid)"
  };
  if (route === "anthropic") {
    headers["x-api-key"] = key;
    headers["anthropic-version"] = "2023-06-01";
  } else {
    headers.authorization = `Bearer ${key}`;
  }
  return headers;
}

function toolFor(route) {
  if (route === "anthropic") {
    return { name: "Bash", description: "Run a bounded command", input_schema: { type: "object", properties: {} } };
  }
  if (route === "responses") {
    return { type: "function", name: "Bash", description: "Run a bounded command", parameters: { type: "object", properties: {} } };
  }
  return { type: "function", function: { name: "Bash", description: "Run a bounded command", parameters: { type: "object", properties: {} } } };
}

function payloadFor(route, model, marker, { includeTool = false, toolResult = false } = {}) {
  if (route === "responses") {
    return {
      model,
      input: [
        { role: "user", content: [{ type: "input_text", text: marker }] },
        ...(toolResult ? [{ type: "function_call_output", call_id: `call_matrix_${route}`, output: "ok" }] : [])
      ],
      stream: true,
      store: false,
      max_output_tokens: 64,
      ...(includeTool ? { tools: [toolFor(route)] } : {})
    };
  }
  if (route === "anthropic") {
    return {
      model,
      messages: [{
        role: "user",
        content: toolResult
          ? [{ type: "text", text: marker }, { type: "tool_result", tool_use_id: `call_matrix_${route}`, content: "ok" }]
          : marker
      }],
      stream: true,
      max_tokens: 64,
      ...(includeTool ? { tools: [toolFor(route)] } : {})
    };
  }
  return {
    model,
    messages: [
      { role: "user", content: marker },
      ...(toolResult ? [{ role: "tool", tool_call_id: `call_matrix_${route}`, content: "ok" }] : [])
    ],
    stream: true,
    stream_options: { include_usage: true },
    max_tokens: 64,
    ...(route === "deepseek" ? { thinking: { type: "disabled" } } : {}),
    ...(includeTool ? { tools: [toolFor(route)] } : {})
  };
}

async function post(ready, route, marker, options = {}) {
  const info = ready.routes[route];
  return await fetch(info.url, {
    method: "POST",
    headers: headersFor(route, options.key ?? secrets[route]),
    signal: options.signal,
    body: JSON.stringify(payloadFor(route, info.model, marker, options))
  });
}

async function runPreloadResponseProbe(ready, marker, mode, probeRoot, probeRuntimeRoot) {
  const route = ready.routes.custom;
  const script = `
    (async()=>{
      const [url,model,marker,mode]=process.argv.slice(1);
      const fs=require("node:fs");
      const key=fs.readFileSync(3,"utf8");
      fs.closeSync(3);
      const payload={
        model,
        messages:[{role:"user",content:marker}],
        stream:true,
        stream_options:{include_usage:true},
        max_tokens:64
      };
      try {
        const response=await fetch(url,{
          method:"POST",
          headers:{
            authorization:\`Bearer \${key}\`,
            "content-type":"application/json",
            "user-agent":"deepseek-harness/preload-matrix",
            "x-deepseek-harness-user-id":"must-be-stripped-user",
            "x-deepseek-harness-session-id":"must-be-stripped-session"
          },
          body:JSON.stringify(payload)
        });
        if(mode==="simple"){
          const clone=response.clone();
          const [body,copy]=await Promise.all([response.text(),clone.text()]);
          const checks=[
            response.status===200,
            response.url===url,
            response.redirected===false,
            String(response.headers.get("content-type")).startsWith("text/event-stream"),
            body===copy,
            body.includes("CUSTOM_S")&&body.includes("IMPLE_OK"),
            response.bodyUsed,
            process.env.LOCAL_HARNESS_MAX_PROVIDER_RESPONSE_BYTES===undefined
          ];
          const failed=checks.indexOf(false);
          process.exit(failed===-1?0:30+failed);
        }
        await response.arrayBuffer();
        process.exit(21);
      }catch(error){
        const diagnostic=String(error?.stack??error);
        const safe=error?.code==="EMSGSIZE"&&!diagnostic.includes(key)
          && diagnostic.includes("65536-byte limit");
        process.exit(safe?0:22);
      }
    })().catch(()=>process.exit(23));
  `;
  const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
  let child;
  try {
    child = spawn(process.execPath, [
      "--import", securityPreload, "-e", script,
      route.url, route.model, marker, mode
    ], {
      env: {
        HOME: probeRoot,
        PATH: "/usr/bin:/bin",
        DSH_HOME: probeRoot,
        LOCAL_HARNESS_STRICT_LOCAL: "0",
        LOCAL_HARNESS_SANDBOX_HELPER: "/usr/bin/false",
        LOCAL_HARNESS_PROVIDER_ORIGINS: JSON.stringify([{
          scheme: "http",
          host: "127.0.0.1",
          port: ready.port,
          boundary: "onDevice"
        }]),
        LOCAL_HARNESS_MAX_PROVIDER_RESPONSE_BYTES: "65536",
        LOCAL_HARNESS_RUNTIME_ROOT: probeRuntimeRoot
      },
      stdio: [authenticationInput, "pipe", "pipe", "pipe"]
    });
  } finally {
    closeSync(authenticationInput);
  }
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  child.stdio[3].end(secrets.custom);
  const outcome = await new Promise((resolveClose) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolveClose({ code: undefined, signal: "TIMEOUT" });
    }, 5_000);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolveClose({ code, signal });
    });
  });
  const output = Buffer.concat([...stdout, ...stderr]).toString("utf8");
  assert.doesNotMatch(output, new RegExp(secrets.custom));
  assert.equal(output, "");
  assert.deepEqual(outcome, { code: 0, signal: null }, `${mode} preload response probe`);
}

async function readUntil(reader, pattern, maximumBytes = 64 * 1_024) {
  let text = "";
  while (!pattern.test(text)) {
    const { value, done } = await reader.read();
    if (done) break;
    text += Buffer.from(value).toString("utf8");
    if (Buffer.byteLength(text, "utf8") > maximumBytes) throw new Error("stream prefix exceeded its fixture bound");
  }
  return text;
}

function assertStreamingDialect(route, text, expected) {
  const midpoint = Math.max(1, Math.floor(expected.length / 2));
  assert.ok(text.includes(expected.slice(0, midpoint)));
  assert.ok(text.includes(expected.slice(midpoint)));
  if (route === "deepseek" || route === "custom") {
    assert.ok((text.match(/chat\.completion\.chunk/g) ?? []).length >= 4);
    assert.match(text, /data: \[DONE\]/);
  } else if (route === "responses") {
    assert.match(text, /event: response\.created/);
    assert.ok((text.match(/event: response\.output_text\.delta/g) ?? []).length >= 2);
    assert.match(text, /event: response\.completed/);
  } else {
    assert.match(text, /event: message_start/);
    assert.ok((text.match(/"type":"text_delta"/g) ?? []).length >= 2);
    assert.match(text, /event: message_stop/);
  }
}

function toolArgumentsFromStream(route, text) {
  const payloads = text.split("\n")
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice("data: ".length)));
  if (route === "deepseek" || route === "custom") {
    return payloads.flatMap((payload) => payload.choices?.[0]?.delta?.tool_calls ?? [])
      .map((call) => call.function?.arguments ?? "").join("");
  }
  if (route === "responses") {
    return payloads.filter((payload) => payload.type === "response.function_call_arguments.delta")
      .map((payload) => payload.delta).join("");
  }
  return payloads.filter((payload) => payload.type === "content_block_delta" && payload.delta?.type === "input_json_delta")
    .map((payload) => payload.delta.partial_json).join("");
}

test("pinned DeepSeek adapter omits stable user and internal session identifiers", async () => {
  const packageRoot = join(project, "VendorRuntime/node_modules/@deepseek-ai/dsh-llm-deepseek");
  const [adapter, declarations, readme, chineseReadme, packageText] = await Promise.all([
    readFile(join(packageRoot, "lib/index.js"), "utf8"),
    readFile(join(packageRoot, "lib/types/adapter.d.ts"), "utf8"),
    readFile(join(packageRoot, "README.md"), "utf8"),
    readFile(join(packageRoot, "README.zh.md"), "utf8"),
    readFile(join(packageRoot, "package.json"), "utf8")
  ]);
  assert.doesNotMatch(adapter, /getOrCreateAnonymousUserId|x-deepseek-harness-user-id|x-deepseek-harness-session-id/);
  assert.doesNotMatch(declarations, /AnonymousUserId|resolveUserId/);
  assert.match(readme, /Fulmar privacy patch \(revision 1\)/);
  assert.match(chineseReadme, /Fulmar 隐私补丁（修订版 1）/);
  const packageManifest = JSON.parse(packageText);
  assert.equal(packageManifest.peerDependencies?.["@deepseek-ai/dsh-anonymous-user-id"], undefined);
  assert.equal(packageManifest.devDependencies?.["@deepseek-ai/dsh-anonymous-user-id"], undefined);
  assert.equal(packageManifest.localHarnessPatch?.revision, 2);
  assert.match(packageManifest.localHarnessPatch?.purpose, /first non-empty streamed tool-call identity/);
  assert.match(adapter, /block\.callId === void 0 && typeof call\.id === "string" && call\.id\.length > 0/);
  assert.match(adapter, /block\.name === void 0 && typeof call\.function\?\.name === "string" && call\.function\.name\.length > 0/);
});

test("loopback provider matrix covers every claimed dialect and hostile transport outcome", { timeout: 30_000 }, async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "local-harness-provider-matrix-")));
  const readyPath = join(root, "ready.json");
  const logPath = join(root, "events.jsonl");
  const probeRuntimeRoot = join(root, "probe-runtime");
  for (const packageName of [
    "dsh-credentials-keychain",
    "dsh-mcp-guarded",
    "dsh-client-security-bridge",
    "dsh-performance-profile",
    "dsh-fs-confined",
    "dsh-web-fetch-safe"
  ]) {
    const directory = join(probeRuntimeRoot, "node_modules", "@local-harness", packageName);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "index.mjs"), "export {};\n", { mode: 0o600 });
  }
  const child = spawn(process.execPath, [serverScript, readyPath, logPath], {
    env: {
      HOME: root,
      PATH: "/usr/bin:/bin",
      MATRIX_DEEPSEEK_KEY: secrets.deepseek,
      MATRIX_RESPONSES_KEY: secrets.responses,
      MATRIX_ANTHROPIC_KEY: secrets.anthropic,
      MATRIX_CUSTOM_KEY: secrets.custom
    },
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
    assert.deepEqual(Object.keys(ready.routes), ["deepseek", "responses", "anthropic", "custom"]);

    // Exercise the actual preload wrapper independently of any SDK: it must
    // preserve normal Response semantics, reject a declared oversize before a
    // consumer sees it, and stop a chunked stream at the aggregate byte cap.
    await runPreloadResponseProbe(ready, "MATRIX_SIMPLE", "simple", root, probeRuntimeRoot);
    await runPreloadResponseProbe(ready, "MATRIX_OVERSIZED", "declared", root, probeRuntimeRoot);
    await runPreloadResponseProbe(ready, "MATRIX_OVERSIZED_CHUNKED", "streamed", root, probeRuntimeRoot);

    for (const route of Object.keys(ready.routes)) {
      const unauthorized = await post(ready, route, "MATRIX_SIMPLE", { key: "wrong-matrix-key-value" });
      assert.equal(unauthorized.status, 401, `${route} must reject the wrong auth header`);

      const simple = await post(ready, route, "MATRIX_SIMPLE");
      assert.equal(simple.status, 200, `${route} simple request`);
      assertStreamingDialect(route, await simple.text(), `${route.toUpperCase()}_SIMPLE_OK`);

      const toolStart = await post(ready, route, "MATRIX_TOOL", { includeTool: true });
      assert.equal(toolStart.status, 200, `${route} tool start`);
      const toolText = await toolStart.text();
      assert.match(toolText, new RegExp(`call_matrix_${route}`));
      const framedArguments = JSON.parse(toolArgumentsFromStream(route, toolText));
      assert.match(framedArguments.command, new RegExp(`matrix-${route}-tool\\.txt`));
      assert.match(framedArguments.description, new RegExp(`${route} protocol-matrix canary`));
      if (route === "responses") {
        assert.ok((toolText.match(/response\.function_call_arguments\.delta/g) ?? []).length >= 2);
        assert.match(toolText, /response\.function_call_arguments\.done/);
      } else if (route === "anthropic") {
        assert.ok((toolText.match(/input_json_delta/g) ?? []).length >= 2);
        assert.match(toolText, /"stop_reason":"tool_use"/);
      } else {
        assert.ok((toolText.match(/"tool_calls"/g) ?? []).length >= 2);
        assert.match(toolText, /"finish_reason":"tool_calls"/);
      }

      const toolFinish = await post(ready, route, "MATRIX_TOOL", { includeTool: true, toolResult: true });
      assert.equal(toolFinish.status, 200, `${route} tool finish`);
      assertStreamingDialect(route, await toolFinish.text(), `${route.toUpperCase()}_TOOL_OK`);

      const errorCases = [
        ["MATRIX_ERROR_401", 401, /matrix authentication failure/u],
        ["MATRIX_ERROR_429", 429, /matrix rate limit/u],
        ["MATRIX_ERROR_500", 503, /matrix server failure/u],
        ...(route === "deepseek"
          ? [["MATRIX_ERROR_402", 402, /matrix insufficient balance/u]]
          : [])
      ];
      for (const [marker, status, messagePattern] of errorCases) {
        const failed = await post(ready, route, marker);
        assert.equal(failed.status, status, `${route} ${marker}`);
        assert.match(String(failed.headers.get("content-type")), /application\/json/);
        const failure = JSON.stringify(await failed.json());
        assert.match(failure, messagePattern);
        if (status === 402) assert.match(failure, /insufficient_balance/u);
        for (const secret of Object.values(secrets)) assert.doesNotMatch(failure, new RegExp(secret));
      }

      const malformed = await post(ready, route, "MATRIX_MALFORMED");
      assert.equal(malformed.status, 200);
      assert.match(await malformed.text(), /data: \{"malformed"/);

      const oversized = await post(ready, route, "MATRIX_OVERSIZED");
      assert.equal(oversized.status, 200);
      assert.equal(Number(oversized.headers.get("content-length")), ready.oversizedResponseBytes);
      assert.ok(ready.oversizedResponseBytes > 65_536);
      await oversized.body.cancel();

      const chunkedOversized = await post(ready, route, "MATRIX_OVERSIZED_CHUNKED");
      assert.equal(chunkedOversized.status, 200);
      assert.equal(chunkedOversized.headers.get("content-length"), null);
      assert.equal((await chunkedOversized.arrayBuffer()).byteLength, ready.oversizedResponseBytes);

      const abortController = new AbortController();
      const cancellation = await post(ready, route, "MATRIX_CANCEL", { signal: abortController.signal });
      assert.equal(cancellation.status, 200);
      const reader = cancellation.body.getReader();
      assert.match(await readUntil(reader, new RegExp(`WAITING_${route.toUpperCase()}`)), new RegExp(`WAITING_${route.toUpperCase()}`));
      abortController.abort();
      await waitFor(async () => {
        try {
          const log = await readFile(logPath, "utf8");
          return log.includes(`"kind":"cancelled","route":"${route}"`);
        } catch {
          return false;
        }
      });
    }

    for (const identityMode of ["OMITTED", "NULL", "EMPTY", "REPEATED", "CONFLICTING"]) {
      const marker = `MATRIX_TOOL_IDENTITY_${identityMode}`;
      const response = await post(ready, "deepseek", marker, { includeTool: true });
      assert.equal(response.status, 200, `deepseek ${identityMode.toLowerCase()} identity fixture`);
      const text = await response.text();
      const payloads = text.split("\n")
        .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
        .map((line) => JSON.parse(line.slice("data: ".length)));
      const calls = payloads.flatMap((payload) => payload.choices?.[0]?.delta?.tool_calls ?? []);
      assert.equal(calls.length, 3, `${marker} genuinely fragments one tool call over three frames`);
      assert.equal(calls[0].id, "call_matrix_deepseek");
      assert.equal(calls[0].function.name, "Bash");
      const continuations = calls.slice(1);
      if (identityMode === "OMITTED") {
        assert.ok(continuations.every((call) => !Object.hasOwn(call, "id") && !Object.hasOwn(call.function, "name")));
      } else if (identityMode === "NULL") {
        assert.ok(continuations.every((call) => call.id === null && call.function.name === null));
      } else if (identityMode === "EMPTY") {
        assert.ok(continuations.every((call) => call.id === "" && call.function.name === ""));
      } else if (identityMode === "REPEATED") {
        assert.ok(continuations.every((call) => call.id === "call_matrix_deepseek" && call.function.name === "Bash"));
      } else {
        assert.ok(continuations.every((call) => call.id === "call_matrix_untrusted_retarget" && call.function.name === "Read"));
      }
      const argumentsJSON = JSON.parse(toolArgumentsFromStream("deepseek", text));
      assert.match(argumentsJSON.command, new RegExp(`matrix-deepseek-tool-identity-${identityMode.toLowerCase()}\\.txt`));
    }

    async function boundedRetry(marker, maximumRetries) {
      let response;
      for (let retry = 0; retry <= maximumRetries; retry += 1) {
        response = await post(ready, "custom", marker);
        if (response.status !== 429 && response.status < 500) return response;
      }
      return response;
    }
    const eventual = await boundedRetry("MATRIX_RETRY_SUCCESS_429", 2);
    assert.equal(eventual.status, 200);
    assertStreamingDialect("custom", await eventual.text(), "CUSTOM_SIMPLE_OK");
    const exhausted = await boundedRetry("MATRIX_ERROR_500", 2);
    assert.equal(exhausted.status, 503);

    const log = await readFile(logPath, "utf8");
    for (const secret of Object.values(secrets)) assert.doesNotMatch(log, new RegExp(secret));
    const rows = log.trim().split("\n").map(JSON.parse);
    for (const route of Object.keys(ready.routes)) {
      assert(rows.some((row) => row.kind === "unauthorized" && row.route === route));
      assert(rows.some((row) => row.kind === "cancelled" && row.route === route));
      const simple = rows.find((row) => row.kind === "request" && row.route === route && row.marker === "MATRIX_SIMPLE");
      assert.ok(simple?.authorized);
      assert.ok(simple?.shape?.json && simple.shape.attributed && simple.shape.model && simple.shape.stream);
      assert.equal(simple.protocol, ready.routes[route].protocol);
      const tool = rows.find((row) => row.kind === "request" && row.route === route && row.marker === "MATRIX_TOOL" && !row.shape.hasToolResult);
      assert.ok(tool?.shape?.tools.includes("Bash"));
    }
    assert.deepEqual(
      rows.filter((row) => row.kind === "request" && row.route === "custom" && row.marker === "MATRIX_RETRY_SUCCESS_429").map((row) => row.attempt),
      [1, 2, 3]
    );
    assert.equal(
      rows.filter((row) => row.kind === "request" && row.route === "custom" && row.marker === "MATRIX_ERROR_500").length,
      4,
      "one direct status probe plus three bounded retry attempts are logged without hidden retries"
    );
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
    const stderr = Buffer.concat(errors).toString("utf8");
    for (const secret of Object.values(secrets)) assert.doesNotMatch(stderr, new RegExp(secret));
    assert.equal(stderr, "");
    await rm(root, { recursive: true, force: true });
  }
});
