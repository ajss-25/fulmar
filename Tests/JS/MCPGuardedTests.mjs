import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import test from "node:test";
import {
  decodeGuardRunnerPlan,
  encodeGuardRunnerPlan,
  executableFingerprint,
  loadApprovedCatalog,
  projectFingerprint,
  validateActivationPlan,
  validateCatalogValue
} from "../../Resources/DSHPlugins/mcp-guarded/catalog-core.mjs";
import {
  MCPToolApprovalError,
  buildGuardChildEnvironment,
  buildStrictServerEnvironment,
  createGuardedContext,
  resolveCredentialEnvironment
} from "../../Resources/DSHPlugins/mcp-guarded/guarded-runtime.mjs";
import {
  BoundedJSONLineDecoder,
  MCPWireGuard,
  MCPWireViolation
} from "../../Resources/DSHPlugins/mcp-guarded/wire-guard.mjs";

const currentUID = process.getuid();

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fileAudit(path, executable = false) {
  const canonicalPath = realpathSync.native(path);
  const bytes = readFileSync(canonicalPath);
  const metadata = lstatSync(canonicalPath);
  const result = {
    declaredPath: canonicalPath,
    canonicalPath,
    contentSHA256: digest(bytes),
    byteCount: bytes.length,
    ownerUID: metadata.uid,
    permissions: metadata.mode & 0o7777
  };
  if (executable) result.fingerprint = executableFingerprint(result);
  return result;
}

function fixture({ maximumDiscoveredTools = 2, maximumOutputBytes = 4096, environment = [] } = {}) {
  const temporary = realpathSync.native(mkdtempSync(join(tmpdir(), "local-harness-mcp-test-")));
  chmodSync(temporary, 0o700);
  const projectPath = join(temporary, "project");
  mkdirSync(projectPath, { mode: 0o700 });
  const executablePath = join(projectPath, "reviewed-mcp-server");
  const executableBytes = Buffer.from("reviewed local MCP fixture\n", "utf8");
  writeFileSync(executablePath, executableBytes, { mode: 0o700 });
  chmodSync(executablePath, 0o700);
  const executableMetadata = lstatSync(executablePath);
  const executable = {
    declaredPath: executablePath,
    canonicalPath: executablePath,
    contentSHA256: digest(executableBytes),
    byteCount: executableBytes.length,
    ownerUID: executableMetadata.uid,
    permissions: executableMetadata.mode & 0o7777,
    fingerprint: ""
  };
  executable.fingerprint = executableFingerprint(executable);
  const projectMetadata = lstatSync(projectPath);
  const project = {
    canonicalPath: projectPath,
    ownerUID: projectMetadata.uid,
    deviceID: projectMetadata.dev,
    inode: projectMetadata.ino,
    fingerprint: ""
  };
  project.fingerprint = projectFingerprint(project);
  const plan = {
    serverID: "fixture-server",
    reviewFingerprint: "a".repeat(64),
    executable,
    reviewedArgumentFiles: [],
    project,
    dsh: {
      pluginID: "mcp-fixture",
      packageName: "@deepseek-ai/dsh-mcp-client",
      transport: "stdio",
      serverName: "fixture",
      command: executablePath,
      arguments: ["--stdio"],
      environment,
      workingDirectory: projectPath,
      toolCallTimeoutMilliseconds: 5000,
      failOnStartupError: true,
      reconnect: {
        enabled: true,
        initialDelayMilliseconds: 500,
        maximumDelayMilliseconds: 5000,
        maximumAttempts: 3
      }
    },
    wrapper: {
      startupTimeoutMilliseconds: 5000,
      maximumDiscoveredTools,
      maximumOutputBytes,
      inheritAmbientEnvironment: false
    },
    disclosure: {
      mcpServer: {
        boundary: "onDevice",
        dataKinds: environment.length > 0
          ? ["authenticationMetadata", "toolArguments", "toolResults"]
          : ["toolArguments", "toolResults"]
      },
      modelProvider: "ollama",
      modelBoundary: "onDevice"
    }
  };
  return {
    temporary,
    projectPath,
    executablePath,
    plan,
    cleanup() { rmSync(temporary, { recursive: true, force: true }); }
  };
}

function withFixture(options, body) {
  const value = fixture(options);
  try { return body(value); }
  finally { value.cleanup(); }
}

function wire(limits = {}) {
  return new MCPWireGuard({
    maximumDiscoveredTools: 2,
    maximumOutputBytes: 1024,
    maximumInventoryBytes: 4096,
    ...limits
  });
}

function rpc(id, method, params) {
  return { jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) };
}

function response(id, result) {
  return { jsonrpc: "2.0", id, result };
}

test("validates native activation plans and round-trips a secret-free guard plan", () => {
  withFixture({}, ({ plan }) => {
    const validated = validateActivationPlan(plan);
    assert.equal(validated.dsh.transport, "stdio");
    const encoded = encodeGuardRunnerPlan(validated);
    assert.equal(encoded.includes("reviewed local MCP fixture"), false);
    const decoded = decodeGuardRunnerPlan(encoded);
    assert.equal(decoded.command, plan.dsh.command);
    assert.deepEqual(decoded.credentialVariables, []);
  });
});

test("rejects HTTP transport, cloud MCP disclosure, ambient env inheritance, and unknown fields", () => {
  withFixture({}, ({ plan }) => {
    assert.throws(() => validateActivationPlan({ ...plan, dsh: { ...plan.dsh, transport: "streamable-http" } }), /transport must be stdio/);
    assert.throws(() => validateActivationPlan({
      ...plan,
      disclosure: { ...plan.disclosure, mcpServer: { ...plan.disclosure.mcpServer, boundary: "cloud", destinationName: "Internet" } }
    }), /network or cloud MCP servers/);
    assert.throws(() => validateActivationPlan({ ...plan, wrapper: { ...plan.wrapper, inheritAmbientEnvironment: true } }), /must remain false/);
    assert.throws(() => validateActivationPlan({ ...plan, apiKey: "must-never-be-persisted" }), /not an approved field/);
  });
});

test("rejects shell commands, inline runtime source, credential values, and unsafe credential names", () => {
  withFixture({}, ({ plan }) => {
    assert.throws(() => validateActivationPlan({
      ...plan,
      executable: { ...plan.executable, canonicalPath: "/bin/sh" },
      dsh: { ...plan.dsh, command: "/bin/sh" }
    }), /shell or environment launcher/);
    assert.throws(() => validateActivationPlan({ ...plan, dsh: { ...plan.dsh, arguments: ["--api-key=secret"] } }), /credential-shaped/);
    assert.throws(() => validateActivationPlan({ ...plan, dsh: { ...plan.dsh, arguments: ["server.mjs"] } }), /relative executable content/);
    assert.throws(() => validateActivationPlan({
      ...plan,
      dsh: { ...plan.dsh, environment: [{ variableName: "PATH", credential: "MCP_PATH" }] },
      disclosure: {
        ...plan.disclosure,
        mcpServer: { ...plan.disclosure.mcpServer, dataKinds: ["authenticationMetadata"] }
      }
    }), /not allowed/);
  });
});

test("catalog rejects duplicate namespaces and unsupported versions", () => {
  withFixture({}, ({ plan }) => {
    assert.throws(() => validateCatalogValue({ schemaVersion: 2, plans: [] }), /unsupported/);
    assert.throws(() => validateCatalogValue({ schemaVersion: 1, plans: [plan, plan] }), /duplicates/);
    const plans = [0, 1, 2].map((index) => ({
      ...plan,
      serverID: `fixture-${index}`,
      dsh: { ...plan.dsh, pluginID: `mcp-fixture${index}`, serverName: `fixture${index}` },
      wrapper: { ...plan.wrapper, maximumDiscoveredTools: 100 }
    }));
    assert.throws(() => validateCatalogValue({ schemaVersion: 1, plans }), /aggregate tool-count budget/);
  });
});

test("loads only an owner-only regular activation catalog and revalidates reviewed bytes", () => {
  withFixture({}, ({ temporary, plan }) => {
    const catalogDirectory = join(temporary, "catalog");
    mkdirSync(catalogDirectory, { mode: 0o700 });
    const catalogPath = join(catalogDirectory, "mcp-activation-v1.json");
    writeFileSync(catalogPath, JSON.stringify({ schemaVersion: 1, plans: [plan] }), { mode: 0o600 });
    chmodSync(catalogPath, 0o600);
    const loaded = loadApprovedCatalog(catalogPath);
    assert.equal(loaded.plans[0].serverID, "fixture-server");
  });
});

test("catalog permissions, links, and executable fingerprint changes fail closed", () => {
  withFixture({}, ({ temporary, executablePath, plan }) => {
    const catalogDirectory = join(temporary, "catalog");
    mkdirSync(catalogDirectory, { mode: 0o700 });
    const catalogPath = join(catalogDirectory, "mcp-activation-v1.json");
    writeFileSync(catalogPath, JSON.stringify({ schemaVersion: 1, plans: [plan] }), { mode: 0o600 });
    chmodSync(catalogPath, 0o644);
    assert.throws(() => loadApprovedCatalog(catalogPath), /owner-only regular file/);
    chmodSync(catalogPath, 0o600);
    const moved = join(catalogDirectory, "catalog-real.json");
    renameSync(catalogPath, moved);
    symlinkSync(moved, catalogPath);
    assert.throws(() => loadApprovedCatalog(catalogPath), /regular file|symbolic link/);
    rmSync(catalogPath);
    renameSync(moved, catalogPath);
    writeFileSync(executablePath, "tampered executable\n", { mode: 0o700 });
    assert.throws(() => loadApprovedCatalog(catalogPath), /executable bytes changed|fingerprint changed/);
  });
});

test("guard child environment contains only the base contract, markers, and exact resolved credentials", () => {
  withFixture({ environment: [{ variableName: "MCP_ACCESS_KEY", credential: "MCP_ACCESS_KEY" }] }, ({ temporary, plan }) => {
    const sandboxTemp = join(temporary, "sandbox-temp");
    mkdirSync(sandboxTemp, { mode: 0o700 });
    const ambient = {
      HOME: "/Users/test",
      USER: "test",
      LOGNAME: "test",
      PATH: "/usr/bin:/bin",
      LANG: "en_GB.UTF-8",
      TMPDIR: sandboxTemp,
      SECRET_TOKEN: "must-not-leak"
    };
    const environment = buildGuardChildEnvironment({
      plan: validateActivationPlan(plan),
      credentials: { MCP_ACCESS_KEY: "credential-value" },
      sandboxTemp,
      ambient
    });
    assert.equal(environment.SECRET_TOKEN, undefined);
    assert.equal(environment.MCP_ACCESS_KEY, "credential-value");
    assert.equal(environment.LOCAL_HARNESS_MCP_GUARD_CHILD, "1");
    assert.deepEqual(JSON.parse(environment.LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS), [plan.project.canonicalPath]);
  });
});

test("actual MCP server environment strips all wrapper and ambient metadata", () => {
  const ambient = {
    HOME: "/Users/test",
    USER: "test",
    LOGNAME: "test",
    PATH: "/usr/bin:/bin",
    LANG: "en_GB.UTF-8",
    TMPDIR: "/private/tmp/local-harness",
    MCP_ACCESS_KEY: "credential-value",
    LOCAL_HARNESS_AUTH_TOKEN: "must-not-leak",
    LOCAL_HARNESS_MCP_GUARD_PLAN: "must-not-leak",
    DEEPSEEK_API_KEY: "must-not-leak"
  };
  const result = buildStrictServerEnvironment(ambient, ["MCP_ACCESS_KEY"]);
  assert.deepEqual(Object.keys(result).sort(), ["HOME", "LANG", "LOGNAME", "MCP_ACCESS_KEY", "PATH", "TMPDIR", "USER"]);
  assert.equal(result.LOCAL_HARNESS_AUTH_TOKEN, undefined);
  assert.equal(result.DEEPSEEK_API_KEY, undefined);
  assert.throws(() => buildStrictServerEnvironment(ambient, ["HOME"]), /collides/);
});

test("credential references resolve only through the DSH credential service and never ambient discovery", async () => {
  const value = fixture({ environment: [{ variableName: "MCP_ACCESS_KEY", credential: "MCP_KEYCHAIN_REF" }] });
  try {
    const plan = validateActivationPlan(value.plan);
    const references = [];
    const resolved = await resolveCredentialEnvironment({
      credentials: {
        async resolve(reference) {
          references.push(reference);
          return { value: "service-only-value", source: "test credential service" };
        }
      }
    }, plan, (reference) => `ref:${reference}`);
    assert.deepEqual(references, ["ref:MCP_KEYCHAIN_REF"]);
    assert.equal(resolved.MCP_ACCESS_KEY, "service-only-value");
    await assert.rejects(
      resolveCredentialEnvironment({ credentials: { resolve: async () => undefined } }, plan, (reference) => reference),
      /not configured/
    );
  } finally { value.cleanup(); }
});

function toolHarness(plan, outcomes = ["allowed-once"]) {
  const registered = [];
  const approvals = [];
  let executeCount = 0;
  const ctx = {
    tools: {
      register(definition) {
        registered.push(definition);
        return () => {
          const index = registered.indexOf(definition);
          if (index >= 0) registered.splice(index, 1);
        };
      }
    },
    approval: {
      async request(request) {
        approvals.push(request);
        return outcomes.shift() ?? "unavailable";
      }
    }
  };
  const guarded = createGuardedContext(ctx, plan);
  const definition = {
    name: "mcp__fixture__echo",
    description: "Echo one value",
    parameters: { type: "object", properties: { value: { type: "string" } } },
    output: { schema: { type: "object" }, render() { return []; } },
    async execute(value) { executeCount += 1; return value; }
  };
  const dispose = guarded.tools.register(definition);
  const exec = {
    callId: "call-1",
    signal: new AbortController().signal,
    agent: {
      options: { provider: plan.disclosure.modelProvider },
      session: {
        header: { cwd: plan.project.canonicalPath },
        requestHeader() { return { config: { provider: plan.disclosure.modelProvider } }; }
      }
    }
  };
  return { registered, approvals, dispose, exec, get executeCount() { return executeCount; } };
}

test("every MCP invocation requires native one-shot approval with visible exact arguments", async () => {
  const value = fixture();
  try {
    const plan = validateActivationPlan(value.plan);
    const harness = toolHarness(plan, ["allowed-once", "allowed-once"]);
    const first = await harness.registered[0].execute({ value: "first" }, harness.exec);
    harness.exec.callId = "call-2";
    const second = await harness.registered[0].execute({ value: "second" }, harness.exec);
    assert.deepEqual(first, { value: "first" });
    assert.deepEqual(second, { value: "second" });
    assert.equal(harness.executeCount, 2);
    assert.equal(harness.approvals.length, 2);
    assert.equal(harness.approvals[0].callId, "call-1");
    assert.match(harness.approvals[0].reason, /Arguments \(exact JSON\): \{"value":"first"\}/);
    harness.dispose();
  } finally { value.cleanup(); }
});

test("on-device MCP remains available to an exactly approved cloud model route", async () => {
  const value = fixture();
  try {
    value.plan.disclosure = {
      ...value.plan.disclosure,
      modelProvider: "deepseek",
      modelBoundary: "cloud"
    };
    const plan = validateActivationPlan(value.plan);
    const harness = toolHarness(plan, ["allowed-once"]);
    await harness.registered[0].execute({ private: "reviewed" }, harness.exec);
    assert.equal(harness.executeCount, 1);
    assert.match(harness.approvals[0].reason, /deepseek \(cloud\)/);

    const mismatch = toolHarness(plan, ["allowed-once"]);
    mismatch.exec.agent.options.provider = "ollama";
    mismatch.exec.agent.session.requestHeader = () => ({ config: { provider: "ollama" } });
    await assert.rejects(
      mismatch.registered[0].execute({}, mismatch.exec),
      /not approved for the model provider/
    );
    assert.equal(mismatch.executeCount, 0);
    assert.equal(mismatch.approvals.length, 0);
  } finally { value.cleanup(); }
});

test("approval denial, missing route binding, and oversized arguments never reach the MCP server", async () => {
  const value = fixture();
  try {
    const plan = validateActivationPlan(value.plan);
    const denied = toolHarness(plan, ["rejected"]);
    await assert.rejects(denied.registered[0].execute({ value: "no" }, denied.exec), MCPToolApprovalError);
    assert.equal(denied.executeCount, 0);
    const wrongProvider = toolHarness(plan, ["allowed-once"]);
    wrongProvider.exec.agent.options.provider = "deepseek";
    wrongProvider.exec.agent.session.requestHeader = () => ({ config: { provider: "deepseek" } });
    await assert.rejects(wrongProvider.registered[0].execute({}, wrongProvider.exec), /not approved for the model provider/);
    assert.equal(wrongProvider.approvals.length, 0);
    const oversized = toolHarness(plan, ["allowed-once"]);
    await assert.rejects(
      oversized.registered[0].execute({ value: "x".repeat(70 * 1024) }, oversized.exec),
      /exceed the size/
    );
    assert.equal(oversized.approvals.length, 0);
  } finally { value.cleanup(); }
});

test("guarded registry enforces namespace and current-generation tool count", () => {
  withFixture({ maximumDiscoveredTools: 1 }, ({ plan }) => {
    const validated = validateActivationPlan(plan);
    const registrations = [];
    const guarded = createGuardedContext({
      tools: { register(definition) { registrations.push(definition); return () => registrations.splice(registrations.indexOf(definition), 1); } },
      approval: { request: async () => "allowed-once" }
    }, validated);
    assert.throws(() => guarded.tools.register({
      name: "outside_namespace",
      description: "bad",
      parameters: {},
      output: { schema: {} },
      execute: async () => ({})
    }), /escape its reviewed tool namespace/);
    const definition = {
      name: "mcp__fixture__one",
      description: "one",
      parameters: {},
      output: { schema: {} },
      execute: async () => ({})
    };
    const dispose = guarded.tools.register(definition);
    assert.throws(() => guarded.tools.register({ ...definition, name: "mcp__fixture__two" }), /tool-count limit/);
    dispose();
    assert.doesNotThrow(() => guarded.tools.register({ ...definition, name: "mcp__fixture__two" }));
  });
});

test("wire guard permits tools-only startup and bounded calls", () => {
  const guard = wire();
  guard.inspectClient(rpc(1, "initialize", {}));
  guard.inspectServer(response(1, { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "fixture", version: "1" } }));
  guard.inspectClient({ jsonrpc: "2.0", method: "notifications/initialized" });
  guard.inspectClient(rpc(2, "tools/list"));
  const listed = guard.inspectServer(response(2, { tools: [{ name: "echo", inputSchema: { type: "object" } }] }));
  assert.equal(listed.startupComplete, true);
  guard.inspectClient(rpc(3, "tools/call", { name: "echo", arguments: { value: "hi" } }));
  const called = guard.inspectServer(response(3, { content: [{ type: "text", text: "hi" }] }));
  assert.equal(called.method, "tools/call");
});

test("tool count and duplicate identities are capped across paginated discovery", () => {
  const guard = wire({ maximumDiscoveredTools: 2 });
  guard.inspectClient(rpc(1, "tools/list"));
  guard.inspectServer(response(1, { tools: [{ name: "one" }], nextCursor: "page-2" }));
  guard.inspectClient(rpc(2, "tools/list", { cursor: "page-2" }));
  assert.throws(() => guard.inspectServer(response(2, { tools: [{ name: "two" }, { name: "three" }] })), MCPWireViolation);
  const duplicate = wire({ maximumDiscoveredTools: 4 });
  duplicate.inspectClient(rpc(1, "tools/list"));
  duplicate.inspectServer(response(1, { tools: [{ name: "same" }], nextCursor: "next" }));
  duplicate.inspectClient(rpc(2, "tools/list", { cursor: "next" }));
  assert.throws(() => duplicate.inspectServer(response(2, { tools: [{ name: "same" }] })), /duplicate tool identity/);
});

test("tool results and inventory bytes are capped before reaching DSH", () => {
  const output = wire({ maximumOutputBytes: 64 });
  output.inspectClient(rpc(1, "tools/call", { name: "echo", arguments: {} }));
  assert.throws(() => output.inspectServer(response(1, { content: [{ type: "text", text: "x".repeat(100) }] })), /output-size limit/);
  const inventory = wire({ maximumInventoryBytes: 80 });
  inventory.inspectClient(rpc(1, "tools/list"));
  assert.throws(() => inventory.inspectServer(response(1, {
    tools: [{ name: "echo", description: "x".repeat(100), inputSchema: {} }]
  })), /schema-size limit/);
});

test("network transports, server-initiated requests, unknown responses, and overlapping list sequences fail closed", () => {
  const guard = wire();
  assert.throws(() => guard.inspectClient(rpc(1, "resources/list")), /tools-only MCP profile/);
  assert.throws(() => guard.inspectServer(rpc(9, "sampling\/createMessage", {})), /server-initiated requests/);
  assert.throws(() => guard.inspectServer(response(999, {})), /unknown JSON-RPC request id/);
  const overlap = wire();
  overlap.inspectClient(rpc(1, "tools/list"));
  assert.throws(() => overlap.inspectClient(rpc(2, "tools/list")), /overlapping/);
});

test("cancellation is identified for process-level quiescence", () => {
  const guard = wire();
  const started = guard.inspectClient(rpc("call", "tools/call", { name: "echo", arguments: {} }));
  const cancelled = guard.inspectClient({
    jsonrpc: "2.0",
    method: "notifications/cancelled",
    params: { requestId: "call", reason: "user" }
  });
  assert.equal(cancelled.cancelledToolCallKey, started.requestKey);
});

test("tool-list change notifications are rate limited before they can queue unbounded resync work", () => {
  const guard = wire();
  for (let index = 0; index < 8; index += 1) {
    assert.equal(guard.inspectServer({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }).forward, true);
  }
  assert.throws(
    () => guard.inspectServer({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }),
    /notification rate limit/
  );
});

test("bounded decoder rejects oversized, unterminated, invalid UTF-8, and batch frames", () => {
  const oversized = new BoundedJSONLineDecoder(1024);
  assert.throws(() => oversized.append(Buffer.alloc(1025, 0x61)), /unterminated.*byte limit/);
  const invalid = new BoundedJSONLineDecoder(1024);
  assert.throws(() => invalid.append(Buffer.from([0xff, 0x0a])), /invalid UTF-8/);
  const guard = wire();
  assert.throws(() => guard.inspectClient([{ jsonrpc: "2.0", id: 1, method: "ping" }]), /invalid JSON-RPC/);
  const partial = new BoundedJSONLineDecoder(1024);
  partial.append(Buffer.from("{\"jsonrpc\":\"2.0\"}"));
  assert.throws(() => partial.finish(), /unterminated/);
});

test("stdio guard runs a reviewed server end-to-end with no ambient environment leakage", { timeout: 20_000 }, async () => {
  const value = fixture({ environment: [{ variableName: "MCP_ACCESS_KEY", credential: "MCP_ACCESS_KEY" }] });
  let child;
  try {
    const serverPath = join(value.projectPath, "fixture-server.mjs");
    writeFileSync(serverPath, [
      'import { createInterface } from "node:readline";',
      'const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });',
      'for await (const line of lines) {',
      '  const message = JSON.parse(line);',
      '  let result;',
      '  if (message.method === "initialize") result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } };',
      '  else if (message.method === "tools/list") result = { tools: [{ name: "environment", description: "List environment names", inputSchema: { type: "object" } }] };',
      '  else if (message.method === "tools/call") result = { content: [{ type: "text", text: JSON.stringify(Object.keys(process.env).sort()) }] };',
      '  else continue;',
      '  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }) + "\\n");',
      '}'
    ].join("\n"), { mode: 0o600 });
    chmodSync(serverPath, 0o600);
    const nodeExecutable = fileAudit(process.execPath, true);
    const entryPoint = fileAudit(serverPath, false);
    value.plan.executable = nodeExecutable;
    value.plan.reviewedArgumentFiles = [{ argumentIndex: 0, ...entryPoint }];
    value.plan.dsh.command = nodeExecutable.canonicalPath;
    value.plan.dsh.arguments = [serverPath];
    const plan = validateActivationPlan(value.plan);
    const sandboxTemp = join(value.temporary, "sandbox-temp");
    mkdirSync(sandboxTemp, { mode: 0o700 });
    const guardPlan = encodeGuardRunnerPlan(plan);
    const roots = JSON.stringify([plan.project.canonicalPath]);
    const environment = {
      HOME: process.env.HOME,
      USER: process.env.USER,
      LOGNAME: process.env.LOGNAME,
      PATH: "/usr/bin:/bin",
      LANG: process.env.LANG ?? "en_US.UTF-8",
      TMPDIR: sandboxTemp,
      MCP_ACCESS_KEY: "configured-for-test",
      LOCAL_HARNESS_MCP_GUARD_CHILD: "1",
      LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS: roots,
      LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP: sandboxTemp,
      LOCAL_HARNESS_MCP_GUARD_PLAN: guardPlan,
      LOCAL_HARNESS_STRICT_LOCAL: "1",
      LOCAL_HARNESS_WORKSPACE_ROOTS: roots,
      LOCAL_HARNESS_READONLY_ROOTS: "[]",
      LOCAL_HARNESS_SANDBOX_TEMP: sandboxTemp
    };
    const runnerPath = realpathSync.native(join(
      process.cwd(),
      "Resources/DSHPlugins/mcp-guarded/stdio-guard-runner.mjs"
    ));
    child = spawn(process.execPath, [runnerPath], {
      cwd: value.projectPath,
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    const closeOutcome = once(child, "close").then(([code, signal]) => ({ code, signal }));
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const request = async (message) => {
      const answer = once(lines, "line").then(([line]) => line);
      child.stdin.write(`${JSON.stringify(message)}\n`);
      const line = await Promise.race([
        answer,
        closeOutcome.then(({ code, signal }) => {
          throw new Error(`guard exited before replying (${code ?? signal}): ${stderr.trim()}`);
        })
      ]);
      return JSON.parse(line);
    };
    const initialized = await request(rpc(1, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test", version: "1" }
    }));
    assert.equal(initialized.result.serverInfo.name, "fixture");
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    const listed = await request(rpc(2, "tools/list"));
    assert.equal(listed.result.tools[0].name, "environment");
    const called = await request(rpc(3, "tools/call", { name: "environment", arguments: {} }));
    const names = JSON.parse(called.result.content[0].text);
    assert.deepEqual(
      names.filter((name) => name !== "__CF_USER_TEXT_ENCODING"),
      ["HOME", "LANG", "LOGNAME", "MCP_ACCESS_KEY", "PATH", "TMPDIR", "USER"]
    );
    assert.equal(names.every((name) => [
      "HOME", "LANG", "LOGNAME", "MCP_ACCESS_KEY", "PATH", "TMPDIR", "USER", "__CF_USER_TEXT_ENCODING"
    ].includes(name)), true);
    child.stdin.end();
    const outcome = await closeOutcome;
    assert.equal(outcome.code, 0, stderr);
  } finally {
    if (child && child.exitCode === null) child.kill("SIGKILL");
    value.cleanup();
  }
});
