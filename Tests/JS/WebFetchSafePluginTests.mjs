import assert from "node:assert/strict";
import { chmod, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const bridgeSymbol = Symbol.for("com.fulmar.runtime.approved-web-fetch.v1");
let root;
let plugin;
let nextResponse;
let nextFailure;
let dshHome;
let previousDSHHome;

async function writeWorkspacePolicy(mode, reason) {
  await writeFile(
    join(dshHome, ".fulmar-workspace-mutation-policy.json"),
    `${JSON.stringify({ schemaVersion: 1, mode, reason })}\n`,
    { mode: 0o600 }
  );
  await chmod(join(dshHome, ".fulmar-workspace-mutation-policy.json"), 0o600);
}

function normalize(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.port || url.username || url.password
      || !url.hostname.includes(".") || url.hostname === "localhost") throw new Error("blocked URL");
  url.hash = "";
  return url.href;
}

before(async () => {
  root = await mkdtemp(join(tmpdir(), "fulmar-web-fetch-plugin."));
  previousDSHHome = process.env.DSH_HOME;
  dshHome = join(root, "dsh-home");
  await mkdir(dshHome, { mode: 0o700 });
  await chmod(dshHome, 0o700);
  process.env.DSH_HOME = dshHome;
  await writeWorkspacePolicy("readWrite", "protectedCheckpoint");
  const packageRoot = join(root, "node_modules", "@local-harness", "dsh-web-fetch-safe");
  const webRoot = join(root, "node_modules", "@deepseek-ai", "dsh-web");
  await mkdir(packageRoot, { recursive: true });
  await mkdir(webRoot, { recursive: true });
  await copyFile(join(project, "Resources", "DSHPlugins", "web-fetch-safe", "index.mjs"), join(packageRoot, "index.mjs"));
  await writeFile(join(packageRoot, "package.json"), '{"type":"module","exports":"./index.mjs"}\n');
  await writeFile(join(webRoot, "package.json"), '{"type":"module","exports":"./index.mjs"}\n');
  await writeFile(join(webRoot, "index.mjs"), `
    export class WebError extends Error {
      constructor(message, code, options) { super(message, options); this.code = code; this.name = "WebError"; }
    }
  `);
  Object.defineProperty(globalThis, bridgeSymbol, {
    configurable: true,
    value: Object.freeze({
      normalize,
      async fetch(url, signal) {
        if (signal?.aborted) throw signal.reason;
        if (nextFailure) { const failure = nextFailure; nextFailure = undefined; throw failure; }
        const response = nextResponse;
        nextResponse = undefined;
        if (!response) throw new Error(`missing test response for ${url}`);
        return response;
      }
    })
  });
  plugin = await import(pathToFileURL(join(packageRoot, "index.mjs")).href);
});

after(async () => {
  Reflect.deleteProperty(globalThis, bridgeSymbol);
  if (root) await rm(root, { recursive: true, force: true });
  if (previousDSHHome === undefined) delete process.env.DSH_HOME;
  else process.env.DSH_HOME = previousDSHHome;
});

test("registers one usable provider, one approval gate, and fail-safe prompt guidance", () => {
  let provider;
  const gates = [];
  const prompts = [];
  plugin.apply({
    web: { registerFetchProvider(value) { provider = value; } },
    on(event, handler, options) {
      assert.equal(event, "tools/pre-execute");
      gates.push({ handler, options });
    },
    systemPrompt: { section(value) { prompts.push(value); } }
  });
  assert.equal(provider.id, plugin.PROVIDER_ID);
  assert.equal(provider.available(), true);
  assert.deepEqual(gates.map(({ options }) => options), [
    { prepend: true, global: true },
    { prepend: true }
  ]);
  assert.match(prompts.map((value) => value.text).join("\n"), /Never retry web access through Bash/u);
  assert.match(prompts.map((value) => value.text).join("\n"), /cite the exact returned URL/u);
  assert.match(prompts.map((value) => value.text).join("\n"), /distinguish your own inference/u);
  assert.match(prompts.map((value) => value.text).join("\n"), /global tool pre-execute boundary/u);
  assert.equal(globalThis[bridgeSymbol], undefined);

  const untouched = Symbol("next");
  assert.equal(gates[0].handler({ name: "bash", arguments: {} }, () => untouched), untouched);
  return gates[1].handler({ name: "web_fetch", arguments: { url: "https://Example.com/a#fragment" } }, () => untouched)
    .then((decision) => {
      assert.equal(decision.kind, "ask");
      assert.match(decision.reason, /https:\/\/example\.com\/a$/u);
    });
});

test("owner-only read-only policy allows reads/search and denies every mutation and subagent seam", async () => {
  await writeWorkspacePolicy("readOnly", "recoverabilityLimit");
  for (const safe of ["read", "read_image", "glob", "grep", "web_fetch", "web_search"]) {
    assert.deepEqual(plugin.workspaceMutationDecision(safe), { kind: "allow" });
  }
  for (const denied of [
    "bash", "pwsh", "write", "edit", "str_replace_editor", "task", "workflow",
    "mcp_mutate", "todo_write", "create_goal", "job_kill", "unknown-future-tool"
  ]) {
    const decision = plugin.workspaceMutationDecision(denied);
    assert.equal(decision.kind, "deny");
    assert.match(decision.reason, /read-only/u);
    assert.match(decision.reason, /subagent\/mutation tools are blocked/u);
  }

  await chmod(join(dshHome, ".fulmar-workspace-mutation-policy.json"), 0o644);
  assert.equal(plugin.workspaceMutationDecision("write").kind, "deny");
  assert.equal(plugin.workspaceMutationDecision("read").kind, "allow");
  await writeWorkspacePolicy("readWrite", "protectedCheckpoint");
});

test("retrieves supported HTTPS text and preserves status without redirects", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  nextResponse = new Response("<h1>Fulmar fetch works</h1>", {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" }
  });
  assert.deepEqual(await provider.fetch({ url: "https://example.com/page#ignored" }), {
    url: "https://example.com/page",
    statusCode: 200,
    body: { kind: "html", content: "<h1>Fulmar fetch works</h1>" },
    truncated: false
  });

  nextResponse = new Response('{"missing":true}', {
    status: 404,
    headers: { "content-type": "application/json" }
  });
  const missing = await provider.fetch({ url: "https://example.com/missing" });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.body.kind, "text");
});

test("bounds bodies and rejects redirects, binary content, blocked URLs, and transport errors", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  nextResponse = new Response(new Uint8Array(plugin.MAXIMUM_BODY_BYTES + 64).fill(65), {
    headers: { "content-type": "text/plain" }
  });
  const large = await provider.fetch({ url: "https://example.com/large" });
  assert.equal(Buffer.byteLength(large.body.content), plugin.MAXIMUM_BODY_BYTES);
  assert.equal(large.truncated, true);

  nextResponse = new Response(null, { status: 302, headers: { location: "https://other.example/" } });
  await assert.rejects(
    provider.fetch({ url: "https://example.com/redirect" }),
    (error) => error.code === "WEB_FETCH_REDIRECT_BLOCKED"
  );

  nextResponse = new Response(new Uint8Array([0, 1, 2]), { headers: { "content-type": "image/png" } });
  await assert.rejects(
    provider.fetch({ url: "https://example.com/image" }),
    (error) => error.code === "WEB_FETCH_CONTENT_TYPE"
  );
  await assert.rejects(
    provider.fetch({ url: "http://example.com/" }),
    (error) => error.code === "WEB_FETCH_BLOCKED_URL"
  );
  nextFailure = new Error("network unavailable");
  await assert.rejects(
    provider.fetch({ url: "https://example.com/failure" }),
    (error) => error.code === "WEB_PROVIDER_ERROR" && /network unavailable/u.test(error.message)
  );
});

function trackedReadableResponse({
  contentType = "text/plain",
  chunks = [],
  status = 200,
  close = true
} = {}) {
  const cancellations = [];
  const body = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      if (close) controller.close();
    },
    cancel(reason) { cancellations.push(reason); }
  });
  const headers = new Headers();
  if (contentType !== null) headers.set("content-type", contentType);
  return {
    response: { status, headers, body },
    cancellations
  };
}

function failingTrackedReadableResponse({ signalController, failure }) {
  const cancellations = [];
  const tracked = new ReadableStream({
    start() {},
    cancel(reason) { cancellations.push(reason); }
  });
  const trackedReader = tracked.getReader();
  let readCount = 0;
  const body = {
    getReader() {
      return {
        async read() {
          readCount += 1;
          signalController?.abort(failure);
          throw failure;
        },
        cancel(reason) { return trackedReader.cancel(reason); },
        releaseLock() { trackedReader.releaseLock(); }
      };
    }
  };
  return {
    response: { status: 200, headers: new Headers({ "content-type": "text/plain" }), body },
    cancellations,
    readCount: () => readCount
  };
}

test("cancels tracked response bodies on MIME rejection without poisoning a later success", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  const rejected = trackedReadableResponse({ contentType: "image/png", close: false });
  nextResponse = rejected.response;
  await assert.rejects(
    provider.fetch({ url: "https://example.com/rejected-image" }),
    (error) => error.code === "WEB_FETCH_CONTENT_TYPE"
  );
  assert.equal(rejected.cancellations.length, 1);

  const success = trackedReadableResponse({
    chunks: [new TextEncoder().encode("subsequent fetch works")]
  });
  nextResponse = success.response;
  const result = await provider.fetch({ url: "https://example.com/after-rejection" });
  assert.equal(result.body.content, "subsequent fetch works");
  assert.deepEqual(success.cancellations, []);
});

test("fails closed and cancels bodies for missing, blank, and malformed MIME declarations", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  for (const contentType of [null, "   ", "not-a-media-type", "text/plain, application/json"]) {
    const rejected = trackedReadableResponse({
      contentType,
      chunks: [new Uint8Array([0, 1, 2])],
      close: false
    });
    nextResponse = rejected.response;
    await assert.rejects(
      provider.fetch({ url: "https://example.com/undeclared-content" }),
      (error) => error.code === "WEB_FETCH_CONTENT_TYPE"
    );
    assert.equal(rejected.cancellations.length, 1, String(contentType));
  }

  for (const contentType of [
    "text/plain; charset=utf-8", "text/csv", "text/html",
    "application/json", "application/problem+json", "application/xml", "application/rss+xml"
  ]) {
    assert.ok(["text", "html"].includes(plugin.responseKind(contentType)), contentType);
  }
});

test("cancels a tracked body when an in-flight read is aborted", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  const controller = new AbortController();
  const failure = new Error("cancelled while reading");
  const tracked = failingTrackedReadableResponse({ signalController: controller, failure });
  nextResponse = tracked.response;

  await assert.rejects(
    provider.fetch({ url: "https://example.com/abort" }, controller.signal),
    (error) => error === failure
  );
  assert.equal(controller.signal.aborted, true);
  assert.equal(tracked.readCount(), 1);
  assert.equal(tracked.cancellations.length, 1);
});

test("cancels a tracked body when its reader fails", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  const failure = new Error("stream read failed");
  const tracked = failingTrackedReadableResponse({ failure });
  nextResponse = tracked.response;

  await assert.rejects(
    provider.fetch({ url: "https://example.com/read-failure" }),
    (error) => error === failure
  );
  assert.equal(tracked.readCount(), 1);
  assert.equal(tracked.cancellations.length, 1);
});

test("successful tracked bodies remain uncancelled while body-limit truncation cancels", async () => {
  const provider = new plugin.FulmarApprovedFetchProvider();
  const success = trackedReadableResponse({
    chunks: [new TextEncoder().encode("complete")]
  });
  nextResponse = success.response;
  assert.equal(
    (await provider.fetch({ url: "https://example.com/complete" })).body.content,
    "complete"
  );
  assert.deepEqual(success.cancellations, []);

  const limited = trackedReadableResponse({
    chunks: [new Uint8Array(plugin.MAXIMUM_BODY_BYTES + 1).fill(65)],
    close: false
  });
  nextResponse = limited.response;
  const result = await provider.fetch({ url: "https://example.com/truncated" });
  assert.equal(result.truncated, true);
  assert.equal(Buffer.byteLength(result.body.content), plugin.MAXIMUM_BODY_BYTES);
  assert.equal(limited.cancellations.length, 1);
});
