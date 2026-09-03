import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { once } from "node:events";

const [appDirectory, testRoot] = process.argv.slice(2);
if (!appDirectory || !testRoot) throw new Error("usage: verify-mcp-guard-runtime.mjs <app> <test-root>");
const runtimeRoot = realpathSync(join(appDirectory, "Contents/Resources/Runtime/dsh"));
const runnerPath = realpathSync(join(
  runtimeRoot,
  "node_modules/@local-harness/dsh-mcp-guarded/stdio-guard-runner.mjs"
));
const core = await import(pathToFileURL(join(
  runtimeRoot,
  "node_modules/@local-harness/dsh-mcp-guarded/catalog-core.mjs"
)).href);
const projectPath = realpathSync(join(testRoot, "workspace"));
const sandboxTemp = realpathSync(join(testRoot, "sandbox-temp"));
const outsideSentinel = realpathSync(join(testRoot, "outside-sentinel.txt"));
const serverPath = join(projectPath, "reviewed-mcp-server.mjs");

writeFileSync(serverPath, [
  'import { createInterface } from "node:readline";',
  'import { readFileSync, writeFileSync } from "node:fs";',
  'import { join } from "node:path";',
  `const outside = ${JSON.stringify(outsideSentinel)};`,
  'const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });',
  'for await (const line of lines) {',
  '  const message = JSON.parse(line);',
  '  let result;',
  '  if (message.method === "initialize") result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "local-harness-canary", version: "1" } };',
  '  else if (message.method === "tools/list") result = { tools: [{ name: "security_canary", description: "Read the MCP sandbox contract", inputSchema: { type: "object", additionalProperties: false } }] };',
  '  else if (message.method === "tools/call") {',
  '    let writeDenied = false; let outsideReadDenied = false;',
  '    try { writeFileSync(join(process.cwd(), "MCP_WRITE_MUST_FAIL"), "bad"); } catch { writeDenied = true; }',
  '    try { readFileSync(outside); } catch { outsideReadDenied = true; }',
  '    result = { content: [{ type: "text", text: JSON.stringify({ names: Object.keys(process.env).sort(), writeDenied, outsideReadDenied }) }] };',
  '  } else continue;',
  '  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\\n");',
  '}'
].join("\n"), { mode: 0o600 });
chmodSync(serverPath, 0o600);

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function fileAudit(path, executable) {
  const canonicalPath = realpathSync(path);
  const bytes = readFileSync(canonicalPath);
  const metadata = lstatSync(canonicalPath);
  const value = {
    declaredPath: canonicalPath,
    canonicalPath,
    contentSHA256: digest(bytes),
    byteCount: bytes.length,
    ownerUID: metadata.uid,
    permissions: metadata.mode & 0o7777
  };
  if (executable) value.fingerprint = core.executableFingerprint(value);
  return value;
}

const projectMetadata = lstatSync(projectPath);
const project = {
  canonicalPath: projectPath,
  ownerUID: projectMetadata.uid,
  deviceID: projectMetadata.dev,
  inode: projectMetadata.ino,
  fingerprint: ""
};
project.fingerprint = core.projectFingerprint(project);
const executable = fileAudit(process.execPath, true);
const entrypoint = fileAudit(serverPath, false);
const plan = core.validateActivationPlan({
  serverID: "packaged-security-canary",
  reviewFingerprint: "a".repeat(64),
  executable,
  reviewedArgumentFiles: [{ argumentIndex: 0, ...entrypoint }],
  project,
  dsh: {
    pluginID: "mcp-security_canary",
    packageName: "@deepseek-ai/dsh-mcp-client",
    transport: "stdio",
    serverName: "security_canary",
    command: process.execPath,
    arguments: [serverPath],
    environment: [{ variableName: "MCP_TEST_KEY", credential: "MCP_TEST_KEY" }],
    workingDirectory: projectPath,
    toolCallTimeoutMilliseconds: 5_000,
    failOnStartupError: true,
    reconnect: { enabled: false, initialDelayMilliseconds: 100, maximumDelayMilliseconds: 100, maximumAttempts: 1 }
  },
  wrapper: {
    startupTimeoutMilliseconds: 5_000,
    maximumDiscoveredTools: 2,
    maximumOutputBytes: 8_192,
    inheritAmbientEnvironment: false
  },
  disclosure: {
    mcpServer: { boundary: "onDevice", dataKinds: ["authenticationMetadata", "toolArguments", "toolResults"] },
    modelProvider: "deepseek",
    modelBoundary: "cloud"
  }
});

const roots = JSON.stringify([projectPath]);
const environment = {
  ...process.env,
  HOME: process.env.HOME,
  USER: process.env.USER,
  LOGNAME: process.env.LOGNAME,
  PATH: process.env.PATH,
  LANG: process.env.LANG,
  TMPDIR: sandboxTemp,
  MCP_TEST_KEY: "configured-test-credential",
  HOST_SHOULD_NOT_LEAK: "not-reviewed",
  OLLAMA_API_KEY: "ambient-not-reviewed",
  LOCAL_HARNESS_MCP_GUARD_CHILD: "1",
  LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS: roots,
  LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP: sandboxTemp,
  LOCAL_HARNESS_MCP_GUARD_PLAN: core.encodeGuardRunnerPlan(plan)
};
const launchOptions = {
  env: environment,
  stdio: ["pipe", "pipe", "inherit"],
  shell: false,
  windowsHide: false,
  cwd: projectPath
};

assert.throws(
  () => spawn("/usr/bin/false", [runnerPath], launchOptions),
  (error) => error?.code === "EACCES" && /exact bundled Node runner contract/.test(error.message)
);
assert.throws(
  () => spawn(process.execPath, [runnerPath, "--unreviewed"], launchOptions),
  (error) => error?.code === "EACCES" && /exact bundled Node runner contract/.test(error.message)
);
assert.throws(
  () => spawn(process.execPath, [runnerPath], {
    ...launchOptions,
    env: { ...environment, LOCAL_HARNESS_MCP_GUARD_PLAN: "not-canonical+base64" }
  }),
  (error) => error?.code === "EACCES" && /plan metadata is invalid/.test(error.message)
);
assert.throws(
  () => spawnSync(process.execPath, [runnerPath], launchOptions),
  (error) => error?.code === "EACCES" && /only by the reviewed asynchronous stdio launch/.test(error.message)
);

const child = spawn(process.execPath, [runnerPath], launchOptions);
const closed = once(child, "close").then(([code, signal]) => ({ code, signal }));
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
async function request(message) {
  const answer = once(lines, "line").then(([line]) => JSON.parse(line));
  child.stdin.write(`${JSON.stringify(message)}\n`);
  return Promise.race([
    answer,
    closed.then(({ code, signal }) => { throw new Error(`guard exited before replying (${code ?? signal})`); })
  ]);
}
const rpc = (id, method, params) => ({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });

const initialized = await request(rpc(1, "initialize", {
  protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "release-canary", version: "1" }
}));
assert.equal(initialized.result.serverInfo.name, "local-harness-canary");
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
const listed = await request(rpc(2, "tools/list"));
assert.equal(listed.result.tools[0].name, "security_canary");
const called = await request(rpc(3, "tools/call", { name: "security_canary", arguments: {} }));
const result = JSON.parse(called.result.content[0].text);
assert.equal(result.writeDenied, true);
assert.equal(result.outsideReadDenied, true);
assert.deepEqual(
  result.names.filter((name) => name !== "__CF_USER_TEXT_ENCODING"),
  ["HOME", "LANG", "LOGNAME", "MCP_TEST_KEY", "PATH", "TMPDIR", "USER"]
);
assert.equal(result.names.includes("HOST_SHOULD_NOT_LEAK"), false);
assert.equal(result.names.includes("OLLAMA_API_KEY"), false);
assert.equal(result.names.some((name) => name.startsWith("LOCAL_HARNESS_")), false);
child.stdin.end();
const outcome = await closed;
assert.equal(outcome.code, 0, `guard stopped by ${outcome.signal ?? "exit"}`);
assert.equal(lstatSync(projectPath).isDirectory(), true);

// Exercise the exact pinned DSH MCP client and SDK stdio spawn contract as a
// second generation. This proves the native preloader accepts the real
// cross-spawn option shape, while the local proxy still owns registration and
// per-call approval.
const projectDirectory = realpathSync(join(new URL("..", import.meta.url).pathname));
const upstream = await import(pathToFileURL(join(
  projectDirectory,
  "VendorRuntime/node_modules/@deepseek-ai/dsh-mcp-client/lib/index.js"
)).href);
const guardedRuntime = await import(pathToFileURL(join(
  runtimeRoot,
  "node_modules/@local-harness/dsh-mcp-guarded/guarded-runtime.mjs"
)).href);
const definitions = [];
const disposers = [];
const approvals = [];
const context = {
  root: {},
  logger: { info() {}, warn() {}, error() {} },
  tools: {
    register(definition) {
      definitions.push(definition);
      return () => {
        const index = definitions.indexOf(definition);
        if (index >= 0) definitions.splice(index, 1);
      };
    }
  },
  approval: {
    async request(request) {
      approvals.push(request);
      return "allowed-once";
    }
  },
  effect(factory) {
    const dispose = factory();
    disposers.push(dispose);
    return dispose;
  }
};
const guardedContext = guardedRuntime.createGuardedContext(context, plan);
const guardedEnvironment = guardedRuntime.buildGuardChildEnvironment({
  plan,
  credentials: { MCP_TEST_KEY: "configured-test-credential" },
  sandboxTemp,
  ambient: process.env
});
await upstream.apply(guardedContext, {
  transport: "stdio",
  serverName: plan.dsh.serverName,
  command: process.execPath,
  args: [runnerPath],
  env: guardedEnvironment,
  cwd: plan.dsh.workingDirectory,
  toolCallTimeoutMs: plan.dsh.toolCallTimeoutMilliseconds,
  failOnStartupError: true,
  reconnect: { enabled: false, initialDelayMs: 100, maxDelayMs: 100, maxAttempts: 1 }
});
assert.equal(definitions.length, 1);
assert.equal(definitions[0].name, "mcp__security_canary__security_canary");
const execution = await definitions[0].execute({}, {
  callId: "release-upstream-canary",
  signal: new AbortController().signal,
  agent: {
    options: { provider: "deepseek" },
    session: {
      header: { cwd: projectPath },
      requestHeader: () => ({ config: { provider: "deepseek" } })
    }
  }
});
assert.equal(approvals.length, 1);
assert.match(approvals[0].reason, /Arguments \(exact JSON\): \{\}/);
assert.match(JSON.stringify(execution), /writeDenied/);
for (const dispose of disposers.reverse()) await dispose?.();
assert.equal(definitions.length, 0);
