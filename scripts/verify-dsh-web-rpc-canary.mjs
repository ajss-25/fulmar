#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { closeSync } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";

import { readAttestedRegularFile } from "./attested-regular-file.mjs";
import { snapshotLocalTree } from "./local-tree-snapshot.mjs";
import { openRuntimeAuthenticationInput } from "../Tests/Fixtures/RuntimeAuthenticationInput.mjs";

export const EXPECTED_PROVIDER = "ollama";
export const EXPECTED_MODEL = "qwen3.8:27b-mlx";
export const UPSTREAM_PROVIDER = "deepseek-official";
export const UPSTREAM_MODEL = "deepseek-v4-flash";
export const EXPECTED_CONTEXT_WINDOW = 49_152;
export const EXPECTED_MAX_TOKENS = 8_192;
export const MCP_TOOL_NAME = "mcp__security_canary__security_canary";
export const MCP_MAX_OUTPUT_BYTES = 2_048;
export const MCP_OUTPUT_PADDING_LENGTH = 1_024;
export const WEB_FETCH_TOOL_NAME = "web_fetch";
export const WEB_FETCH_CANARY_URL = "https://www.darkbloom.dev/";
export const TELEMETRY_MAXIMUM_FILE_BYTES = 256 * 1_024;
export const TELEMETRY_MAXIMUM_RECORDS = 100;
export const THERMAL_POLICY_MAXIMUM_FILE_BYTES = 1_024;

const TELEMETRY_RECORD_KEYS = Object.freeze([
  "schemaVersion", "id", "provider", "model", "profile", "startedAtMilliseconds",
  "completedAtMilliseconds", "firstTokenAtMilliseconds", "elapsedMilliseconds",
  "outputTokens", "outputTokenCountSource", "outcome", "failureCategory"
]);
const TELEMETRY_FORBIDDEN_MARKERS = Object.freeze([
  "LOCAL_HARNESS_WEB_RPC_SIMPLE",
  "SIMULATED_SIMPLE_OK",
  "CONTRACT_AUTO_CONTINUE",
  "SIMULATED_AUTOCONTINUE_PARTIAL",
  "SIMULATED_AUTOCONTINUE_OK",
  "CONTRACT_CANCEL",
  "WAITING",
  "CONTRACT_WEB_FETCH",
  "SIMULATED_WEB_FETCH_OK",
  "https://www.darkbloom.dev/",
  "CONTRACT_MCP_DENY",
  "CONTRACT_MCP_ALLOW",
  "SIMULATED_MCP_DENY_OK",
  "SIMULATED_MCP_ALLOW_OK",
  "MCP_ALLOWED_ONCE_OK",
  "MCP_APPROVAL_DENIED",
  "The MCP tool call was not approved",
  "simulated rate limit",
  "local-ollama",
  "OLLAMA_API_KEY",
  "DEEPSEEK_API_KEY"
]);

const PROJECT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TEMP_PREFIX = "/private/tmp/local-harness-web-rpc-canary.";
const AUTH_HEADER = "X-Local-Harness-Token";
const MAX_LOG_BYTES = 4 * 1024 * 1024;
const ACTIVE_CHILDREN = new Set();
const ACTIVE_ROOTS = new Set();
let signalCleanupStarted = false;
const LOCAL_PLUGIN_PACKAGES = Object.freeze([
  "dsh-credentials-keychain",
  "dsh-mcp-guarded",
  "dsh-client-security-bridge",
  "dsh-performance-profile",
  "dsh-fs-confined",
  "dsh-web-fetch-safe"
]);
const REQUIRED_TYPED_METHODS = Object.freeze([
  "host.describe",
  "llm.models",
  "llm.providers",
  "session.cancel",
  "session.create",
  "session.fork",
  "session.history",
  "session.list",
  "session.models",
  "session.prompt",
  "session.rename",
  "session.selectModel",
  "settings.describe",
  "settings.mutate",
  "workspace.archiveSession",
  "workspace.create",
  "workspace.list"
]);

export class DSHCompatibilityError extends Error {
  constructor(message) {
    super(`Pinned DSH web/RPC compatibility mismatch: ${message}`);
    this.name = "DSHCompatibilityError";
  }
}

export function hasSuccessfulWebFetchToolResult(value, expectedURL = WEB_FETCH_CANARY_URL) {
  const text = JSON.stringify(value);
  const prefix = `Fetched ${expectedURL} (HTTP `;
  let offset = text.indexOf(prefix);
  while (offset >= 0) {
    const statusStart = offset + prefix.length;
    const status = text.slice(statusStart, statusStart + 3);
    if (/^2\d\d$/u.test(status) && text[statusStart + 3] === ")") return true;
    offset = text.indexOf(prefix, offset + prefix.length);
  }
  return false;
}

export function assertExactWebFetchApprovalReason(reason, expectedURL = WEB_FETCH_CANARY_URL) {
  const expectedReason = `Allow Fulmar to retrieve this exact public page once? ${expectedURL}`;
  if (reason !== expectedReason) {
    compatibilityFailure("the approved-page permission omitted its exact one-shot URL disclosure");
  }
  return reason;
}

function compatibilityFailure(message) {
  throw new DSHCompatibilityError(message);
}

function isPlainRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sameRoute(value, provider = EXPECTED_PROVIDER, model = EXPECTED_MODEL) {
  return isPlainRecord(value) && value.provider === provider && value.model === model;
}

function namespace(description, name) {
  const matches = description?.namespaces?.filter((entry) => entry?.ns === name) ?? [];
  if (matches.length !== 1) compatibilityFailure(`settings.describe exposed ${matches.length} ${JSON.stringify(name)} namespaces`);
  return matches[0];
}

export function assertFreshRuntimeState(settingsDescription, sessionList, settingsExistedBeforeLaunch = false) {
  if (settingsExistedBeforeLaunch) compatibilityFailure("the isolated DSH_HOME was not clean before launch");
  if (settingsDescription?.writable !== true) compatibilityFailure("settings.describe did not expose a writable provider");
  if (!Array.isArray(sessionList?.items) || sessionList.items.length !== 0) {
    compatibilityFailure("the isolated DSH_HOME contained a session before the canary created one");
  }
  const defaults = namespace(settingsDescription, "agent-default-model");
  if (!sameRoute(defaults.value, UPSTREAM_PROVIDER, UPSTREAM_MODEL)) {
    compatibilityFailure(`the clean pinned DSH default is no longer ${UPSTREAM_PROVIDER}/${UPSTREAM_MODEL}`);
  }
  namespace(settingsDescription, "llm-pi-ai");
  return defaults;
}

function exactLoopbackProviderOrigin(providerOrigin) {
  let parsed;
  try {
    parsed = new URL(providerOrigin);
  } catch {
    compatibilityFailure("the local provider fixture returned an invalid origin");
  }
  if (
    parsed.protocol !== "http:"
    || parsed.hostname !== "127.0.0.1"
    || parsed.port === ""
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    compatibilityFailure("the provider fixture origin is not an exact ephemeral IPv4 loopback origin");
  }
  return providerOrigin;
}

export function localProviderProfile() {
  return {
    apiKeyEnv: "OLLAMA_API_KEY",
    displayName: "Ollama (Local)",
    api: "openai-completions",
    baseURL: "http://127.0.0.1:11434/v1",
    reasoning: "off",
    compat: { maxTokensField: "max_tokens", supportsReasoningEffort: true },
    models: [{
      id: EXPECTED_MODEL,
      name: "Qwen 3.8 27B MLX (Local)",
      contextWindow: EXPECTED_CONTEXT_WINDOW,
      maxTokens: EXPECTED_MAX_TOKENS,
      input: ["text"],
      reasoningEfforts: { off: "none", high: "high" }
    }]
  };
}

export function providerFixtureBaseURL(providerOrigin) {
  return `${exactLoopbackProviderOrigin(providerOrigin)}/v1`;
}

export function providerFixtureSecurityEnvironment(providerReady) {
  if (providerReady === undefined) {
    return { ollamaHost: "127.0.0.1:11434", providerOrigins: [] };
  }
  const parsed = new URL(exactLoopbackProviderOrigin(providerReady?.origin));
  const port = Number(parsed.port);
  return {
    ollamaHost: `${parsed.hostname}:${parsed.port}`,
    providerOrigins: [{ scheme: "http", host: parsed.hostname, port, boundary: "onDevice" }]
  };
}

export function assertExactLocalDefault(namespaceView) {
  if (namespaceView?.ns !== "agent-default-model") compatibilityFailure("default-model mutation returned the wrong namespace");
  if (!sameRoute(namespaceView.value)) compatibilityFailure(`default-model mutation did not retain ${EXPECTED_PROVIDER}/${EXPECTED_MODEL}`);
  if (namespaceView.value.reasoningEffort !== undefined) compatibilityFailure("default-model mutation retained an unexpected reasoning effort");
}

export function assertLocalCatalog(providerDirectory, modelCatalog) {
  const providers = providerDirectory?.providers?.filter((entry) => entry?.provider === EXPECTED_PROVIDER) ?? [];
  if (providers.length !== 1) compatibilityFailure(`llm.providers exposed ${providers.length} exact Ollama routes`);
  const provider = providers[0];
  if (provider.active !== true || provider.settingsNs !== "llm-pi-ai") {
    compatibilityFailure("the exact Ollama settings route is not active through llm-pi-ai");
  }
  const models = (modelCatalog?.groups ?? [])
    .filter((group) => group?.id === EXPECTED_PROVIDER)
    .flatMap((group) => group.models ?? [])
    .filter((model) => model?.id === EXPECTED_MODEL);
  if (models.length !== 1) compatibilityFailure(`llm.models exposed ${models.length} exact Qwen routes`);
  const failures = (modelCatalog?.failures ?? []).filter((failure) => failure?.id === EXPECTED_PROVIDER);
  if (failures.length !== 0) compatibilityFailure("llm.models reported an Ollama catalog failure");
}

export function assertBlankLocalSession(sessionModels, summary) {
  if (!sameRoute(sessionModels?.current)) compatibilityFailure("the first fresh session did not inherit the exact local default");
  if (sessionModels?.routable !== true) compatibilityFailure("the first fresh session reports its exact local route as unroutable");
  if (summary?.blank !== true || summary?.running !== false) compatibilityFailure("the first fresh session was not a stopped blank session before prompting");
}

export function assertMCPToolAdvertisement(tool) {
  if (!isPlainRecord(tool) || tool.name !== MCP_TOOL_NAME) {
    compatibilityFailure("the model did not receive the exact reviewed MCP tool namespace");
  }
  if (!isPlainRecord(tool.parameters) || tool.parameters.type !== "object" || tool.parameters.additionalProperties !== false) {
    compatibilityFailure("the reviewed MCP tool reached the model with a changed input schema");
  }
  const match = /^Fulmar inert MCP canary; server_pid=([1-9][0-9]*); guard_pid=([1-9][0-9]*)$/u.exec(tool.description ?? "");
  const serverPID = Number(match?.[1]);
  const guardPID = Number(match?.[2]);
  if (
    !Number.isSafeInteger(serverPID)
    || !Number.isSafeInteger(guardPID)
    || serverPID <= 1
    || guardPID <= 1
    || serverPID === guardPID
    || serverPID === process.pid
    || guardPID === process.pid
  ) compatibilityFailure("the reviewed MCP advertisement omitted distinct exact subprocess identities");
  return { serverPID, guardPID };
}

export function assertMCPAllowedOutput(output, subprocesses) {
  if (typeof output !== "string") compatibilityFailure("the allowed MCP result was not text");
  const prefix = `MCP_ALLOWED_ONCE_OK|call_count=1|server_pid=${subprocesses.serverPID}|guard_pid=${subprocesses.guardPID}|padding=`;
  if (!output.startsWith(prefix)) compatibilityFailure("the allowed MCP result did not retain its exact execution identity and one-call count");
  const padding = output.slice(prefix.length);
  if (padding !== "x".repeat(MCP_OUTPUT_PADDING_LENGTH)) {
    compatibilityFailure("the allowed MCP result did not retain its reviewed bounded payload");
  }
  const resultBytes = Buffer.byteLength(JSON.stringify({ content: [{ type: "text", text: output }] }), "utf8");
  if (resultBytes > MCP_MAX_OUTPUT_BYTES) compatibilityFailure("the allowed MCP result exceeded its reviewed output bound");
  return resultBytes;
}

export function assertPerformanceTelemetryDocument(document) {
  if (
    !isPlainRecord(document)
    || Object.keys(document).sort().join("\0") !== ["records", "schemaVersion"].join("\0")
    || document.schemaVersion !== 1
    || !Array.isArray(document.records)
    || document.records.length < 1
    || document.records.length > TELEMETRY_MAXIMUM_RECORDS
  ) compatibilityFailure("performance telemetry did not retain its exact bounded document schema");
  const expectedRecordKeys = [...TELEMETRY_RECORD_KEYS].sort().join("\0");
  const outcomes = new Set(["completed", "cancelled", "failed"]);
  const tokenSources = new Set(["providerReported", "estimated"]);
  const failureCategories = new Set([
    "providerUnavailable", "timedOut", "invalidResponse", "toolFailure", "resourcePressure", "unknown"
  ]);
  for (const record of document.records) {
    const integerFields = [
      record?.startedAtMilliseconds,
      record?.completedAtMilliseconds,
      record?.elapsedMilliseconds,
      record?.outputTokens
    ];
    if (
      !isPlainRecord(record)
      || Object.keys(record).sort().join("\0") !== expectedRecordKeys
      || record.schemaVersion !== 1
      || typeof record.id !== "string"
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(record.id)
      || record.provider !== EXPECTED_PROVIDER
      || record.model !== EXPECTED_MODEL
      || (record.profile !== null && record.profile !== "balanced")
      || !integerFields.every((value) => Number.isSafeInteger(value) && value >= 0)
      || record.completedAtMilliseconds < record.startedAtMilliseconds
      || record.completedAtMilliseconds - record.startedAtMilliseconds !== record.elapsedMilliseconds
      || (record.firstTokenAtMilliseconds !== null
        && (!Number.isSafeInteger(record.firstTokenAtMilliseconds)
          || record.firstTokenAtMilliseconds < record.startedAtMilliseconds
          || record.firstTokenAtMilliseconds > record.completedAtMilliseconds))
      || !tokenSources.has(record.outputTokenCountSource)
      || !outcomes.has(record.outcome)
      || (record.outcome === "failed"
        ? !failureCategories.has(record.failureCategory)
        : record.failureCategory !== null)
    ) compatibilityFailure("performance telemetry contained an invalid, content-shaped, or wrong-route record");
  }
  return document.records.length;
}

export function assertPerformanceTelemetryContentAbsent(value) {
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : value;
  if (typeof text !== "string") compatibilityFailure("performance telemetry bytes were unavailable for privacy inspection");
  for (const marker of TELEMETRY_FORBIDDEN_MARKERS) {
    if (text.includes(marker)) compatibilityFailure(`performance telemetry retained private turn content marker ${JSON.stringify(marker)}`);
  }
}

function canonicalCandidateLayout(appDir) {
  if (typeof appDir !== "string" || !path.isAbsolute(appDir) || !appDir.endsWith(".app") || appDir.includes("\0")) {
    compatibilityFailure("the candidate application path is invalid");
  }
  const runtime = path.join(appDir, "Contents", "Resources", "Runtime");
  const dsh = path.join(runtime, "dsh");
  return Object.freeze({
    appDir,
    runtime,
    dsh,
    node: path.join(runtime, "node"),
    cli: path.join(dsh, "lib", "bin.js"),
    preload: path.join(appDir, "Contents", "Resources", "RuntimeSecurityPreload.mjs"),
    patch: path.join(appDir, "Contents", "Resources", "LocalHarness.patch.yml"),
    credentialPlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-credentials-keychain", "index.mjs"),
    mcpPlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-mcp-guarded", "index.mjs"),
    mcpCatalogCore: path.join(dsh, "node_modules", "@local-harness", "dsh-mcp-guarded", "catalog-core.mjs"),
    clientSecurityPlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-client-security-bridge", "index.mjs"),
    clientSecurityClient: path.join(dsh, "node_modules", "@local-harness", "dsh-client-security-bridge", "client.js"),
    performancePlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-performance-profile", "index.mjs"),
    fsPlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-fs-confined", "index.mjs"),
    webFetchPlugin: path.join(dsh, "node_modules", "@local-harness", "dsh-web-fetch-safe", "index.mjs"),
    credentialHelper: path.join(appDir, "Contents", "MacOS", "LocalHarnessCredentialHelper"),
    sandboxHelper: path.join(appDir, "Contents", "MacOS", "LocalHarnessSandboxRunner"),
    apiClient: path.join(dsh, "node_modules", "@deepseek-ai", "dsh-host-apiproxy", "lib", "types", "fetch", "client.js"),
    apiSchemas: path.join(dsh, "node_modules", "@deepseek-ai", "dsh-host-apiproxy", "lib", "types", "api", "rpc.schema.js"),
    eventSchemas: path.join(dsh, "node_modules", "@deepseek-ai", "dsh-host-apiproxy", "lib", "types", "api", "events.schema.js")
  });
}

async function assertRegularFile(file, executable = false) {
  const info = await lstat(file).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink()) compatibilityFailure(`candidate component is missing or not regular: ${path.basename(file)}`);
  if (executable && (info.mode & 0o111) === 0) compatibilityFailure(`candidate component is not executable: ${path.basename(file)}`);
}

async function validateCandidate(layout) {
  await Promise.all([
    assertRegularFile(layout.node, true),
    assertRegularFile(layout.cli),
    assertRegularFile(layout.preload),
    assertRegularFile(layout.patch),
    assertRegularFile(layout.credentialPlugin),
    assertRegularFile(layout.mcpPlugin),
    assertRegularFile(layout.mcpCatalogCore),
    assertRegularFile(layout.clientSecurityPlugin),
    assertRegularFile(layout.clientSecurityClient),
    assertRegularFile(layout.performancePlugin),
    assertRegularFile(layout.fsPlugin),
    assertRegularFile(layout.credentialHelper, true),
    assertRegularFile(layout.sandboxHelper, true),
    assertRegularFile(layout.apiClient),
    assertRegularFile(layout.apiSchemas),
    assertRegularFile(layout.eventSchemas),
    assertRegularFile(path.join(PROJECT_DIR, "scripts", "simulated-openai-provider.mjs")),
    assertRegularFile(path.join(PROJECT_DIR, "Tests", "Fixtures", "CanaryCredentialHelper.sh"), true)
  ]);
  const [runningNode, candidateNode] = await Promise.all([realpath(process.execPath), realpath(layout.node)]);
  if (runningNode !== candidateNode) compatibilityFailure("the canary was not executed by the candidate's bundled Node runtime");
}

function processExit(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

function trackExactChild(child) {
  ACTIVE_CHILDREN.add(child);
  child.once("close", () => ACTIVE_CHILDREN.delete(child));
  return child;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(predicate, { child, label, timeoutMs = 20_000, intervalMs = 50 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child?.canarySpawnError) {
      compatibilityFailure(`${label} failed to spawn: ${child.canarySpawnError.message}`);
    }
    if (child && (child.exitCode !== null || child.signalCode !== null)) {
      compatibilityFailure(`${label} exited before its contract became ready`);
    }
    try {
      const value = await predicate();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await delay(intervalMs);
  }
  const suffix = lastError instanceof Error ? ` (${lastError.message})` : "";
  compatibilityFailure(`${label} timed out${suffix}`);
}

async function stopExactChild(child, label) {
  if (!child) return;
  const exit = processExit(child);
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  const graceful = await Promise.race([exit.then(() => true), delay(5_000).then(() => false)]);
  if (!graceful && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  const result = await Promise.race([exit, delay(5_000).then(() => undefined)]);
  if (result === undefined) compatibilityFailure(`${label} PID ${child.pid} did not terminate after SIGKILL`);
}

async function boundedFile(file, maximum = MAX_LOG_BYTES, options = {}) {
  try {
    return await readAttestedRegularFile(file, {
      label: options.label ?? path.basename(file),
      minimumBytes: options.minimumBytes ?? 0,
      maximumBytes: maximum,
      requireCurrentUser: options.requireCurrentUser === true,
      requirePrivateMode: options.requirePrivateMode === true,
      requireSingleLink: options.requireSingleLink !== false
    });
  } catch {
    compatibilityFailure(`${path.basename(file)} is missing, unstable, or exceeds its canary bound`);
  }
}

async function boundedText(file, maximum = MAX_LOG_BYTES, options = {}) {
  const { bytes } = await boundedFile(file, maximum, options);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) {
    compatibilityFailure(`${path.basename(file)} is not canonical UTF-8 text`);
  }
  return text;
}

async function boundedJSONSnapshot(file, maximum = 64 * 1024, options = {}) {
  const snapshot = await boundedFile(file, maximum, options);
  const text = snapshot.bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(snapshot.bytes)) {
    compatibilityFailure(`${path.basename(file)} is not canonical UTF-8 text`);
  }
  try {
    return Object.freeze({ ...snapshot, value: JSON.parse(text) });
  } catch {
    compatibilityFailure(`${path.basename(file)} is not valid JSON`);
  }
}

async function boundedJSON(file, maximum = 64 * 1024, options = {}) {
  return (await boundedJSONSnapshot(file, maximum, options)).value;
}

async function auditedMCPFile(file, executable, core) {
  const canonicalPath = await realpath(file);
  if (canonicalPath !== file) compatibilityFailure("an MCP activation input was not a canonical path");
  const [bytes, metadata] = await Promise.all([readFile(canonicalPath), lstat(canonicalPath)]);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    compatibilityFailure("an MCP activation input was linked or not a regular single-link file");
  }
  const value = {
    declaredPath: canonicalPath,
    canonicalPath,
    contentSHA256: createHash("sha256").update(bytes).digest("hex"),
    byteCount: bytes.length,
    ownerUID: metadata.uid,
    permissions: metadata.mode & 0o7777
  };
  if (executable) value.fingerprint = core.executableFingerprint(value);
  return value;
}

async function prepareReviewedMCPActivation(layout, state) {
  const core = await import(pathToFileURL(layout.mcpCatalogCore).href);
  // `/Applications` is intentionally rejected by the generic MCP executable
  // trust policy because its admin group can replace descendants. The candidate
  // host itself is protected by code signing, but the inert MCP fixture must use
  // the same private, owner-only topology required of any reviewed MCP command.
  // Copy the already inventory-verified bundled Node binary into this disposable
  // 0700 canary Workspace, which is also inside the host's admitted read boundary,
  // rather than weakening either production trust boundary.
  const serverRuntimePath = path.join(state.workspace, "reviewed-mcp-node");
  await copyFile(layout.node, serverRuntimePath);
  await chmod(serverRuntimePath, 0o700);
  const serverPath = path.join(state.workspace, "reviewed-inert-mcp-server.mjs");
  const serverSource = [
    'import { createInterface } from "node:readline";',
    `const outputPaddingLength = ${MCP_OUTPUT_PADDING_LENGTH};`,
    'const description = `Fulmar inert MCP canary; server_pid=${process.pid}; guard_pid=${process.ppid}`;',
    'let callCount = 0;',
    'const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });',
    'for await (const line of lines) {',
    '  const message = JSON.parse(line);',
    '  let result;',
    '  if (message.method === "initialize") {',
    '    result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "local-harness-inert-canary", version: "1" } };',
    '  } else if (message.method === "ping") {',
    '    result = {};',
    '  } else if (message.method === "tools/list") {',
    '    result = { tools: [{ name: "security_canary", description, inputSchema: { type: "object", properties: {}, additionalProperties: false } }] };',
    '  } else if (message.method === "tools/call") {',
    '    callCount += 1;',
    '    const text = `MCP_ALLOWED_ONCE_OK|call_count=${callCount}|server_pid=${process.pid}|guard_pid=${process.ppid}|padding=${"x".repeat(outputPaddingLength)}`;',
    '    result = { content: [{ type: "text", text }] };',
    '  } else {',
    '    continue;',
    '  }',
    '  if (Object.hasOwn(message, "id")) process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\\n`);',
    '}'
  ].join("\n") + "\n";
  await writeFile(serverPath, serverSource, { mode: 0o600, flag: "wx" });
  await chmod(serverPath, 0o600);

  const projectPath = await realpath(state.workspace);
  if (projectPath !== state.workspace) compatibilityFailure("the MCP canary project is not canonical");
  const projectMetadata = await lstat(projectPath);
  const project = {
    canonicalPath: projectPath,
    ownerUID: projectMetadata.uid,
    deviceID: projectMetadata.dev,
    inode: projectMetadata.ino,
    fingerprint: ""
  };
  project.fingerprint = core.projectFingerprint(project);
  const executable = await auditedMCPFile(serverRuntimePath, true, core);
  const entrypoint = await auditedMCPFile(serverPath, false, core);
  const reviewFingerprint = createHash("sha256").update(JSON.stringify({
    schema: "local-harness-candidate-mcp-canary-v1",
    serverID: "candidate-inert-canary",
    executableSHA256: executable.contentSHA256,
    entrypointSHA256: entrypoint.contentSHA256,
    projectFingerprint: project.fingerprint,
    pluginID: "mcp-security_canary",
    packageName: "@deepseek-ai/dsh-mcp-client",
    transport: "stdio",
    serverName: "security_canary",
    command: executable.canonicalPath,
    arguments: [serverPath],
    environment: [],
    workingDirectory: projectPath,
    toolCallTimeoutMilliseconds: 5_000,
    startupTimeoutMilliseconds: 5_000,
    maximumDiscoveredTools: 1,
    maximumOutputBytes: MCP_MAX_OUTPUT_BYTES,
    inheritAmbientEnvironment: false,
    mcpBoundary: "onDevice",
    modelProvider: EXPECTED_PROVIDER,
    modelBoundary: "onDevice"
  })).digest("hex");
  const plan = core.validateActivationPlan({
    serverID: "candidate-inert-canary",
    reviewFingerprint,
    executable,
    reviewedArgumentFiles: [{ argumentIndex: 0, ...entrypoint }],
    project,
    dsh: {
      pluginID: "mcp-security_canary",
      packageName: "@deepseek-ai/dsh-mcp-client",
      transport: "stdio",
      serverName: "security_canary",
      command: executable.canonicalPath,
      arguments: [serverPath],
      environment: [],
      workingDirectory: projectPath,
      toolCallTimeoutMilliseconds: 5_000,
      failOnStartupError: true,
      reconnect: {
        enabled: false,
        initialDelayMilliseconds: 100,
        maximumDelayMilliseconds: 100,
        maximumAttempts: 1
      }
    },
    wrapper: {
      startupTimeoutMilliseconds: 5_000,
      maximumDiscoveredTools: 1,
      maximumOutputBytes: MCP_MAX_OUTPUT_BYTES,
      inheritAmbientEnvironment: false
    },
    disclosure: {
      mcpServer: { boundary: "onDevice", dataKinds: ["toolArguments", "toolResults"] },
      modelProvider: EXPECTED_PROVIDER,
      modelBoundary: "onDevice"
    }
  });
  core.validateCatalogValue({ schemaVersion: 1, plans: [plan] });
  const catalog = await open(state.mcpCatalog, "r+");
  try {
    await catalog.truncate(0);
    await catalog.writeFile(`${JSON.stringify({ schemaVersion: 1, plans: [plan] })}\n`, "utf8");
    await catalog.sync();
  } finally {
    await catalog.close();
  }
  await chmod(state.mcpCatalog, 0o600);
  return { plan, serverPath };
}

async function userDshSnapshot(sourceDshHome) {
  const info = await lstat(sourceDshHome).catch((error) => error?.code === "ENOENT" ? undefined : Promise.reject(error));
  if (info === undefined) return { exists: false, bytes: undefined };
  if (!info.isDirectory() || info.isSymbolicLink()) compatibilityFailure("the source ~/.dsh is not a regular directory tree");
  return { exists: true, bytes: await snapshotLocalTree(sourceDshHome) };
}

function assertSameUserDsh(before, after) {
  if (before.exists !== after.exists) compatibilityFailure("the source ~/.dsh existence changed during the isolated canary");
  if (before.exists && !before.bytes.equals(after.bytes)) compatibilityFailure("the source ~/.dsh changed during the isolated canary");
}

async function openLog(file) {
  return open(file, "wx", 0o600);
}

async function startProvider(layout, testRoot, environment) {
  const readyPath = path.join(testRoot, "provider-ready.json");
  const logPath = path.join(testRoot, "provider-log.jsonl");
  const stdout = await openLog(path.join(testRoot, "provider.stdout.log"));
  const stderr = await openLog(path.join(testRoot, "provider.stderr.log"));
  const providerEnvironment = {
    HOME: environment.HOME,
    USER: environment.USER,
    LOGNAME: environment.LOGNAME,
    PATH: environment.PATH,
    LANG: environment.LANG,
    TMPDIR: environment.TMPDIR
  };
  const child = trackExactChild(spawn(layout.node, [
    path.join(PROJECT_DIR, "scripts", "simulated-openai-provider.mjs"),
    readyPath,
    logPath,
    "local-ollama",
    EXPECTED_MODEL
  ], {
    cwd: environment.HOME,
    env: providerEnvironment,
    stdio: ["ignore", stdout.fd, stderr.fd]
  }));
  child.once("error", (error) => { child.canarySpawnError = error; });
  await stdout.close();
  await stderr.close();
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) compatibilityFailure("the local provider fixture did not receive an exact PID");
  let ready;
  try {
    ready = await waitFor(async () => {
      const info = await lstat(readyPath).catch(() => undefined);
      return info?.isFile() ? boundedJSON(readyPath) : undefined;
    }, { child, label: "local provider fixture", timeoutMs: 10_000 });
  } catch (error) {
    await stopExactChild(child, "local provider fixture").catch(() => {});
    throw error;
  }
  if (
    ready?.host !== "127.0.0.1"
    || !Number.isSafeInteger(ready.port)
    || ready.port < 1
    || ready.port > 65_535
    || ready.origin !== `http://127.0.0.1:${ready.port}`
  ) compatibilityFailure("the local provider fixture published an invalid endpoint");
  return { child, ready, logPath };
}

async function startHarness(layout, testRoot, environment, workspace, authentication) {
  const stdoutPath = path.join(testRoot, "runtime.stdout.log");
  const stderrPath = path.join(testRoot, "runtime.stderr.log");
  const stdoutLog = await openLog(stdoutPath);
  const stderrLog = await openLog(stderrPath);
  const authenticationInput = openRuntimeAuthenticationInput(authentication.token, authentication.nonce);
  let child;
  try {
    child = trackExactChild(spawn(layout.node, [
      "--import", layout.preload,
      layout.cli,
      "web",
      "--patch", layout.patch,
      "--no-open",
      "--host", "127.0.0.1",
      "--port", "0"
    ], {
      cwd: workspace,
      env: environment,
      stdio: [authenticationInput, "pipe", stderrLog.fd]
    }));
  } finally {
    closeSync(authenticationInput);
  }
  child.once("error", (error) => { child.canarySpawnError = error; });
  await stderrLog.close();
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) compatibilityFailure("the candidate DSH host did not receive an exact PID");
  let stdout = "";
  child.stdout.on("data", (chunk) => {
    if (Buffer.byteLength(stdout) < MAX_LOG_BYTES) stdout += chunk.toString("utf8");
    void stdoutLog.write(chunk).catch(() => {});
  });
  let port;
  try {
    port = await waitFor(() => {
      const matches = [...stdout.matchAll(/dsh web: http:\/\/127\.0\.0\.1:([0-9]+)/gu)];
      const candidate = Number(matches.at(-1)?.[1]);
      return Number.isSafeInteger(candidate) && candidate > 0 && candidate <= 65_535 ? candidate : undefined;
    }, { child, label: "candidate DSH web host", timeoutMs: 25_000 });
  } catch (error) {
    await stopExactChild(child, "candidate DSH web host").catch(() => {});
    await stdoutLog.close().catch(() => {});
    const stderr = await boundedText(stderrPath).catch(() => "");
    if (error && typeof error === "object") {
      error.canaryDiagnostics = [stdout, stderr].filter(Boolean).join("\n").slice(-16_384);
    }
    throw error;
  }
  await stdoutLog.sync();
  return { child, port, stdoutPath, stderrPath, stdoutLog };
}

async function createProfileShadow(state) {
  const shadowRoot = path.join(state.dshHome, "profiles", "web", "node_modules", "@local-harness");
  for (const packageName of LOCAL_PLUGIN_PACKAGES) {
    const packageRoot = path.join(shadowRoot, packageName);
    await mkdir(packageRoot, { recursive: true, mode: 0o700 });
    await chmod(packageRoot, 0o700);
    await writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: `@local-harness/${packageName}`,
      version: "999.0.0-shadow",
      type: "module",
      main: "./index.mjs",
      exports: {
        ".": "./index.mjs",
        "./client": "./client.js",
        "./package.json": "./package.json",
        "./typert": "./typert.mjs"
      },
      dsh: {
        client: {
          platform: "web",
          inject: ["@deepseek-ai/dsh-client-runtime"]
        }
      }
    }) + "\n", { mode: 0o600, flag: "wx" });
    await writeFile(
      path.join(packageRoot, "index.mjs"),
      `throw new Error(${JSON.stringify(`PROFILE_SHADOW_LOADED:root:${packageName}`)});\n`,
      { mode: 0o600, flag: "wx" }
    );
    await writeFile(
      path.join(packageRoot, "client.js"),
      `throw new Error(${JSON.stringify(`PROFILE_SHADOW_LOADED:client:${packageName}`)});\n`,
      { mode: 0o600, flag: "wx" }
    );
    await writeFile(
      path.join(packageRoot, "typert.mjs"),
      `throw new Error(${JSON.stringify(`PROFILE_SHADOW_LOADED:typert:${packageName}`)});\n`,
      { mode: 0o600, flag: "wx" }
    );
  }
}

async function assertProfileShadowCannotLoad(layout) {
  const state = await prepareState();
  let primaryError;
  let refused = false;
  try {
    await createProfileShadow(state);
    const environment = childEnvironment(state, layout);
    try {
      state.runtime = await startHarness(layout, state.root, environment, state.workspace, state);
    } catch (error) {
      const diagnostics = typeof error?.canaryDiagnostics === "string" ? error.canaryDiagnostics : "";
      if (/Profile-local module overrides are disabled by Fulmar/u.test(diagnostics)) {
        refused = true;
      } else {
        throw error;
      }
    }
    if (!refused) compatibilityFailure("a profile-local @local-harness package was not rejected before web readiness");
  } catch (error) {
    primaryError = error;
  }
  try { await stopExactChild(state.runtime?.child, "profile-shadow candidate DSH host"); } catch (error) { primaryError ??= error; }
  try { await closeHarnessLog(state.runtime); } catch (error) { primaryError ??= error; }
  const stderr = state.runtime?.stderrPath
    ? await boundedText(state.runtime.stderrPath).catch(() => "")
    : "";
  if (stderr.includes("PROFILE_SHADOW_LOADED:")) {
    primaryError ??= new DSHCompatibilityError("a profile-local package shadowed a reviewed in-bundle plugin");
  }
  try { await removeStateRoot(state); } catch (error) { primaryError ??= error; }
  if (primaryError) {
    if (typeof primaryError.canaryDiagnostics === "string" && primaryError.canaryDiagnostics.length > 0) {
      process.stderr.write(primaryError.canaryDiagnostics);
      if (!primaryError.canaryDiagnostics.endsWith("\n")) process.stderr.write("\n");
    }
    throw primaryError;
  }
}

function captureBounded(chunks, chunk, maximum = 128 * 1024) {
  const current = chunks.reduce((total, entry) => total + entry.length, 0);
  if (current >= maximum) return;
  const bytes = Buffer.from(chunk);
  chunks.push(bytes.subarray(0, maximum - current));
}

async function expectPreloadTargetRefusal(layout, state, runtimeRoot, label, expectedDiagnostic) {
  const environment = {
    ...childEnvironment(state, layout),
    LOCAL_HARNESS_RUNTIME_ROOT: runtimeRoot
  };
  const authenticationInput = openRuntimeAuthenticationInput(state.token, state.nonce);
  let child;
  try {
    child = trackExactChild(spawn(layout.node, [
      "--import", layout.preload,
      "--eval", "process.stdout.write('UNREACHABLE_PRELOAD_PROBE')"
    ], {
      cwd: state.workspace,
      env: environment,
      stdio: [authenticationInput, "pipe", "pipe"]
    }));
  } finally {
    closeSync(authenticationInput);
  }
  child.once("error", (error) => { child.canarySpawnError = error; });
  if (!Number.isSafeInteger(child.pid) || child.pid <= 1) compatibilityFailure(`${label} did not receive an exact PID`);
  const stdoutChunks = [];
  const stderrChunks = [];
  child.stdout.on("data", (chunk) => captureBounded(stdoutChunks, chunk));
  child.stderr.on("data", (chunk) => captureBounded(stderrChunks, chunk));
  const exit = await Promise.race([processExit(child), delay(10_000).then(() => undefined)]);
  if (exit === undefined) {
    await stopExactChild(child, label);
    compatibilityFailure(`${label} did not fail before its bounded startup deadline`);
  }
  if (child.canarySpawnError) compatibilityFailure(`${label} failed to spawn: ${child.canarySpawnError.message}`);
  const stdout = Buffer.concat(stdoutChunks).toString("utf8");
  const stderr = Buffer.concat(stderrChunks).toString("utf8");
  if (exit.code === 0 || stdout.includes("UNREACHABLE_PRELOAD_PROBE")) {
    compatibilityFailure(`${label} reached application code instead of failing in the security preload`);
  }
  if (!expectedDiagnostic.test(stderr)) {
    compatibilityFailure(`${label} returned the wrong preload diagnostic: ${stderr.slice(-2_048)}`);
  }
}

async function copyReviewedPluginEntrypoints(layout, runtimeRoot) {
  const localRoot = path.join(runtimeRoot, "node_modules", "@local-harness");
  await mkdir(localRoot, { recursive: true, mode: 0o700 });
  await chmod(runtimeRoot, 0o700);
  for (const packageName of LOCAL_PLUGIN_PACKAGES) {
    const packageRoot = path.join(localRoot, packageName);
    await mkdir(packageRoot, { recursive: true, mode: 0o700 });
    await chmod(packageRoot, 0o700);
    const source = path.join(layout.dsh, "node_modules", "@local-harness", packageName, "index.mjs");
    const destination = path.join(packageRoot, "index.mjs");
    await copyFile(source, destination);
    await chmod(destination, 0o600);
  }
}

async function assertMalformedBundleTargetsFailClosed(layout) {
  const state = await prepareState();
  let primaryError;
  try {
    const probes = [
      {
        name: "missing bundled-plugin target",
        packageName: "dsh-credentials-keychain",
        mutate: (target) => rm(target),
        diagnostic: /Bundled plugin @local-harness\/dsh-credentials-keychain does not exist/u
      },
      {
        name: "linked bundled-plugin target",
        packageName: "dsh-mcp-guarded",
        mutate: async (target) => {
          await rm(target);
          await symlink(layout.mcpPlugin, target);
        },
        diagnostic: /Bundled plugin @local-harness\/dsh-mcp-guarded cannot traverse a symbolic link/u
      },
      {
        name: "unsafe-mode bundled-plugin target",
        packageName: "dsh-performance-profile",
        mutate: (target) => chmod(target, 0o666),
        diagnostic: /Bundled plugin @local-harness\/dsh-performance-profile has unsafe ownership, type, or permissions/u
      }
    ];
    for (const [index, probe] of probes.entries()) {
      const runtimeRoot = path.join(state.root, `adversarial-runtime-${index}`);
      await copyReviewedPluginEntrypoints(layout, runtimeRoot);
      const target = path.join(runtimeRoot, "node_modules", "@local-harness", probe.packageName, "index.mjs");
      await probe.mutate(target);
      await expectPreloadTargetRefusal(layout, state, runtimeRoot, probe.name, probe.diagnostic);
    }
  } catch (error) {
    primaryError = error;
  }
  try { await removeStateRoot(state); } catch (error) { primaryError ??= error; }
  if (primaryError) throw primaryError;
}

async function runResolverAdversarialProbes(layout) {
  await assertProfileShadowCannotLoad(layout);
  await assertMalformedBundleTargetsFailClosed(layout);
  return 4;
}

async function closeHarnessLog(runtime) {
  await runtime?.stdoutLog?.close().catch(() => {});
}

async function authenticatedCandidateBytes(state, pathname, maximumBytes = 2 * 1024 * 1024) {
  const origin = `http://127.0.0.1:${state.runtime.port}`;
  const response = await fetch(`${origin}${pathname}`, {
    headers: { [AUTH_HEADER]: state.token, Origin: origin },
    redirect: "error",
    signal: AbortSignal.timeout(10_000)
  }).catch((error) => compatibilityFailure(`authenticated ${pathname} fetch failed: ${error.message}`));
  if (response.status !== 200) compatibilityFailure(`authenticated ${pathname} fetch returned HTTP ${response.status}`);
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    compatibilityFailure(`authenticated ${pathname} response exceeded its declared byte bound`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > maximumBytes) {
    compatibilityFailure(`authenticated ${pathname} response was empty or exceeded its byte bound`);
  }
  return bytes;
}

async function assertServedSecurityBridge(layout, state) {
  const served = await authenticatedCandidateBytes(
    state,
    "/plugins/@local-harness/dsh-client-security-bridge/client.js",
    512 * 1024
  );
  const reviewed = await readFile(layout.clientSecurityClient);
  if (!served.equals(reviewed)) compatibilityFailure("the web host did not serve the exact reviewed client security bridge bytes");

  let registration;
  const events = [];
  const createCalls = [];
  const workspaceCreateCalls = [];
  const performanceCalls = [];
  const allocatedSessionId = "local-harness-performance-v1-balanced-00000000-0000-4000-8000-000000000001";
  const approvedWorkspacePath = "/isolated-native-approved-workspace";
  let snapshot = {
    current: "existing-session",
    ids: ["existing-session"],
    byId: { "existing-session": { id: "existing-session", blank: false } }
  };
  const listeners = new Set();
  const browserWindow = {
    __ModuleLoader__: { load(value) { registration = value; } },
    crypto: Object.freeze({ randomUUID }),
    webkit: { messageHandlers: {
      localHarnessPerformance: {
        async postMessage(message) {
          performanceCalls.push(message);
          return { ok: true, sessionID: allocatedSessionId, workspacePath: approvedWorkspacePath };
        }
      },
      localHarnessRecovery: {
        async postMessage(message) {
          if (message.action === "cancel") {
            events.push(["cancel", message.operationID]);
            return { ok: true };
          }
          events.push(["checkpoint", message.sessionID]);
          return { ok: true, mode: "protected" };
        }
      }
    } }
  };
  browserWindow.window = browserWindow;
  // A WKWebView exposes Web Crypto on the page global. Node's vm contexts do
  // not inherit the host global. Use one self-referential browser global so
  // window, globalThis, and crypto have the same identity as the real page.
  const browserRealmIsFaithful = runInNewContext(
    "window === globalThis && window.crypto === globalThis.crypto && typeof crypto.randomUUID === 'function'",
    browserWindow,
    { filename: "candidate-browser-realm-preflight.js", timeout: 2_000 }
  );
  if (browserRealmIsFaithful !== true) {
    compatibilityFailure("the packaged bridge proof did not create a faithful browser Web Crypto realm");
  }
  runInNewContext(served.toString("utf8"), browserWindow, {
    filename: "candidate-reviewed-client-security-bridge.js",
    timeout: 2_000
  });
  if (registration?.id !== "@local-harness/dsh-client-security-bridge" || typeof registration.factory !== "function") {
    compatibilityFailure("the served client security bridge did not register its exact package identity");
  }
  const plugin = registration.factory();
  if (typeof plugin?.apply !== "function") compatibilityFailure("the served client security bridge exposed no apply function");

  const sessions = {
    list: {
      getSnapshot: () => snapshot,
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }
    },
    async create(options) {
      createCalls.push(options);
      const id = options.sessionId ?? "unbound-session";
      snapshot = {
        current: snapshot.current,
        ids: [...snapshot.ids, id],
        byId: { ...snapshot.byId, [id]: { id, blank: true } }
      };
      return id;
    },
    open(id) {
      snapshot = { ...snapshot, current: id };
      for (const listener of listeners) listener();
    }
  };
  const conversation = {
    scopedSession() { return { sessionId: snapshot.current }; },
    async send() { compatibilityFailure("the scoped send path was not used by this proof"); },
    async sendSession(session, text, imageIds, mode) {
      events.push(["sendSession", session.sessionId, text, imageIds, mode]);
      return { kind: "success" };
    }
  };
  const workspaces = {
    list: { getSnapshot: () => ({
      baselinesReady: true,
      recentWorkspaceId: "stale-workspace",
      items: [{ workspaceId: "stale-workspace", path: "/stale-workspace", sessionIds: ["existing-session"] }]
    }) },
    async create(options) {
      workspaceCreateCalls.push(options);
      return { workspaceId: "approved-workspace", path: options.path, sessionIds: [] };
    }
  };
  let dispose;
  plugin.apply({
    sessions,
    workspaces,
    conversation,
    effect(factory) { dispose = factory(); }
  });
  const bridge = browserWindow.__localHarnessSecurityBridge;
  if (bridge?.version !== 2 || typeof bridge.startFreshSession !== "function") {
    compatibilityFailure("the served client security bridge did not install its exact native bridge surface");
  }
  const fresh = await bridge.startFreshSession();
  if (
    fresh.before !== "existing-session"
    || fresh.created !== allocatedSessionId
    || fresh.current !== allocatedSessionId
    || createCalls.length !== 1
    || createCalls[0]?.workspaceId !== "approved-workspace"
    || createCalls[0]?.sessionId !== allocatedSessionId
    || workspaceCreateCalls.length !== 1
    || workspaceCreateCalls[0]?.path !== approvedWorkspacePath
    || performanceCalls.length !== 1
    || performanceCalls[0]?.version !== 1
  ) compatibilityFailure("the served client bridge failed its native performance-bound fresh-session proof");
  await conversation.sendSession(
    { sessionId: allocatedSessionId },
    "candidate checkpoint proof",
    [],
    "queue"
  );
  if (
    events.length !== 2
    || events[0]?.[0] !== "checkpoint"
    || events[0]?.[1] !== allocatedSessionId
    || events[1]?.[0] !== "sendSession"
    || events[1]?.[1] !== allocatedSessionId
  ) compatibilityFailure("the served client bridge did not checkpoint before forwarding a prompt");
  dispose?.();
  if (browserWindow.__localHarnessSecurityBridge !== undefined) {
    compatibilityFailure("the served client bridge did not remove its native bridge surface on disposal");
  }
  return 2;
}

class SocketCapture {
  constructor(name, socket, serverRequestSchema, frameSchema) {
    this.name = name;
    this.socket = socket;
    this.serverRequestSchema = serverRequestSchema;
    this.frameSchema = frameSchema;
    this.frames = [];
    this.requests = [];
    this.error = undefined;
    socket.on("message", (data) => {
      try {
        const envelope = serverRequestSchema.parse(JSON.parse(data.toString("utf8")));
        const frame = frameSchema.parse(envelope.payload);
        this.frames.push(frame);
        this.requests.push({ rpcId: envelope.rpcId, method: envelope.method, payload: frame });
      } catch (error) {
        this.error = error;
        socket.close(1008, "invalid typed frame");
      }
    });
    socket.on("error", (error) => { this.error ??= error; });
  }

  assertHealthy() {
    if (this.error) compatibilityFailure(`${this.name} WebSocket delivered an invalid frame: ${this.error.message}`);
    if (this.socket.readyState !== 1) compatibilityFailure(`${this.name} WebSocket closed during the RPC canary`);
  }
}

async function expectUnauthenticatedWebSocketRejected(WebSocket, url, origin) {
  const status = await new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers: { Origin: origin }, handshakeTimeout: 5_000 });
    const timeout = setTimeout(() => { socket.terminate(); reject(new Error("unauthenticated WebSocket timed out")); }, 5_000);
    socket.once("open", () => { clearTimeout(timeout); socket.terminate(); reject(new Error("unauthenticated WebSocket opened")); });
    socket.once("unexpected-response", (_request, response) => {
      clearTimeout(timeout);
      const code = response.statusCode;
      response.resume();
      resolve(code);
    });
    socket.once("error", () => {});
  });
  if (status !== 401) compatibilityFailure(`unauthenticated WebSocket returned HTTP ${String(status)} instead of 401`);
}

async function openAuthenticatedWebSocket(WebSocket, url, origin, token, name, serverRequestSchema, frameSchema) {
  const socket = new WebSocket(url, {
    headers: { [AUTH_HEADER]: token, Origin: origin },
    handshakeTimeout: 5_000,
    maxPayload: 8 * 1024 * 1024
  });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { socket.terminate(); reject(new Error(`${name} WebSocket timed out`)); }, 5_000);
    socket.once("open", () => { clearTimeout(timeout); resolve(); });
    socket.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  return new SocketCapture(name, socket, serverRequestSchema, frameSchema);
}

async function closeSocket(capture) {
  if (!capture) return;
  const socket = capture.socket;
  if (socket.readyState === 3) return;
  if (socket.readyState === 0) { socket.terminate(); return; }
  const closed = new Promise((resolve) => socket.once("close", resolve));
  socket.close(1000, "canary complete");
  const graceful = await Promise.race([closed.then(() => true), delay(2_000).then(() => false)]);
  if (!graceful) socket.terminate();
}

function responseValue(response, method, methodTrace) {
  methodTrace.push(method);
  if (response?.result?.ok !== true) {
    const code = response?.result?.error?.code ?? "unknown-error";
    const message = response?.result?.error?.message ?? "no error message";
    compatibilityFailure(`${method} returned ${String(code)}: ${String(message)}`);
  }
  return response.result.value;
}

async function call(clientCall, method, payload, methodTrace) {
  let response;
  try {
    response = await clientCall(payload);
  } catch (error) {
    compatibilityFailure(`${method} transport/schema validation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  return responseValue(response, method, methodTrace);
}

async function assertReviewedPluginsActive(state) {
  const method = "pluginInventory/list";
  const rpcId = randomUUID();
  const origin = `http://127.0.0.1:${state.runtime.port}`;
  const response = await fetch(`${origin}/api/${method}`, {
    method: "POST",
    headers: {
      [AUTH_HEADER]: state.token,
      Origin: origin,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      type: "client-request",
      rpcId,
      method,
      payload: { args: {} }
    }),
    redirect: "error",
    signal: AbortSignal.timeout(10_000)
  }).catch((error) => compatibilityFailure(`plugin inventory transport failed: ${error.message}`));
  if (response.status !== 200) compatibilityFailure(`plugin inventory returned HTTP ${response.status}`);
  const envelope = await response.json().catch(() => undefined);
  if (envelope?.type !== "server-response" || envelope.rpcId !== rpcId || envelope.result?.ok !== true) {
    compatibilityFailure("plugin inventory returned an invalid strict Remote envelope");
  }
  const entries = envelope.result.value?.entries;
  if (!Array.isArray(entries)) compatibilityFailure("plugin inventory omitted its typed entries");
  for (const packageName of LOCAL_PLUGIN_PACKAGES) {
    const moduleName = `@local-harness/${packageName}`;
    const matches = entries.filter((entry) => entry?.moduleName === moduleName);
    if (matches.length !== 1 || matches[0].enabled !== true || matches[0].fiberPhase !== "active") {
      const phase = matches.length === 1 ? String(matches[0].fiberPhase) : `count-${matches.length}`;
      compatibilityFailure(`the reviewed plugin ${moduleName} is not active (${phase})`);
    }
  }
  const upstreamFileSystems = entries.filter((entry) => entry?.moduleName === "@deepseek-ai/dsh-fs-sandbox");
  if (upstreamFileSystems.some((entry) => entry.enabled === true || entry.fiberPhase === "active")) {
    compatibilityFailure("the superseded upstream filesystem sandbox is still active");
  }
}

export function turnEndCount(history) {
  return Array.isArray(history?.events)
    ? history.events.filter((entry) => entry?.event?.type === "turn/end").length
    : 0;
}

export function hasCompletedFixtureTurn(history, baselineTurnEnds, responseMarker) {
  return Number.isSafeInteger(baselineTurnEnds)
    && baselineTurnEnds >= 0
    && typeof responseMarker === "string"
    && responseMarker.length > 0
    && turnEndCount(history) > baselineTurnEnds
    && JSON.stringify(history).includes(responseMarker);
}

async function waitForTurnEnd(
  client,
  sessionId,
  methodTrace,
  baselineTurnEnds,
  responseMarker,
  label = "bounded local turn"
) {
  return waitFor(async () => {
    const history = await call(client.sessions.history, "session.history", { sessionId, maxMessages: 100 }, methodTrace);
    return hasCompletedFixtureTurn(history, baselineTurnEnds, responseMarker) ? history : undefined;
  }, { label, timeoutMs: 45_000, intervalMs: 100 });
}

async function readProviderRows(logPath) {
  const text = await boundedText(logPath);
  if (text.length === 0) return [];
  try {
    return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  } catch {
    compatibilityFailure("the local provider fixture log is malformed");
  }
}

async function connectCandidateAPI(layout, state) {
  const baseURL = `http://127.0.0.1:${state.runtime.port}`;
  const wsBaseURL = `ws://127.0.0.1:${state.runtime.port}`;
  const [{ AbstractApiClient }, { serverRequestSchema }, { muxFrameSchema, hostFrameSchema }] = await Promise.all([
    import(pathToFileURL(layout.apiClient).href),
    import(pathToFileURL(layout.apiSchemas).href),
    import(pathToFileURL(layout.eventSchemas).href)
  ]);
  const requireFromCandidate = createRequire(path.join(layout.dsh, "package.json"));
  const WebSocket = requireFromCandidate("ws");

  class AuthenticatedCandidateClient extends AbstractApiClient {
    constructor() { super(10_000); }
    resolveBase() { return baseURL; }
    doFetch(input, init = {}) {
      const headers = new Headers(init.headers);
      headers.set(AUTH_HEADER, state.token);
      headers.set("Origin", baseURL);
      return fetch(input, { ...init, headers });
    }
  }

  await expectUnauthenticatedWebSocketRejected(WebSocket, `${wsBaseURL}/api/events.mux`, baseURL);
  state.mux = await openAuthenticatedWebSocket(
    WebSocket, `${wsBaseURL}/api/events.mux`, baseURL, state.token, "mux", serverRequestSchema, muxFrameSchema
  );
  state.host = await openAuthenticatedWebSocket(
    WebSocket, `${wsBaseURL}/api/events.host`, baseURL, state.token, "host", serverRequestSchema, hostFrameSchema
  );
  return new AuthenticatedCandidateClient();
}

async function restartCandidateHarness(layout, state, label) {
  await closeSocket(state.mux);
  await closeSocket(state.host);
  state.mux = undefined;
  state.host = undefined;
  await stopExactChild(state.runtime?.child, `${label} predecessor DSH host`);
  await closeHarnessLog(state.runtime);
  state.runtime = undefined;

  const logRoot = path.join(state.root, label);
  await mkdir(logRoot, { mode: 0o700 });
  await chmod(logRoot, 0o700);
  state.runtime = await startHarness(
    layout,
    logRoot,
    childEnvironment(state, layout),
    state.workspace,
    state
  );
  return connectCandidateAPI(layout, state);
}

async function runTypedCompatibility(layout, state) {
  let client = await connectCandidateAPI(layout, state);
  const trace = state.methodTrace;
  const hostDescription = await call(client.host.describe, "host.describe", {}, trace);
  if (!isPlainRecord(hostDescription)) compatibilityFailure("host.describe returned a non-object value");
  await assertReviewedPluginsActive(state);

  const initialSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  const initialSessions = await call(client.sessions.list, "session.list", {}, trace);
  const initialDefault = assertFreshRuntimeState(initialSettings, initialSessions, state.settingsExistedBeforeLaunch);
  const piNamespace = namespace(initialSettings, "llm-pi-ai");

  // Exercise the DSH settings dialect with a deterministic fixture endpoint.
  // The shipped native app replaces this conventional test-only port with its
  // own reserved random port after proving the exact Ollama child listener.
  const providerProfile = localProviderProfile();
  const updatedPi = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{ op: "set", path: ["providers", EXPECTED_PROVIDER], value: providerProfile }],
    expectedRevision: piNamespace.revision
  }, trace);
  if (updatedPi?.value?.providers?.[EXPECTED_PROVIDER]?.apiKeyEnv !== "OLLAMA_API_KEY") {
    compatibilityFailure("settings.mutate did not retain the isolated Ollama credential reference");
  }

  const updatedDefault = await call(client.settings.mutate, "settings.mutate", {
    ns: "agent-default-model",
    ops: [
      { op: "set", path: ["provider"], value: EXPECTED_PROVIDER },
      { op: "set", path: ["model"], value: EXPECTED_MODEL },
      { op: "unset", path: ["reasoningEffort"] }
    ],
    expectedRevision: initialDefault.revision
  }, trace);
  assertExactLocalDefault(updatedDefault);

  const finalSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  assertExactLocalDefault(namespace(finalSettings, "agent-default-model"));
  const storedProfile = namespace(finalSettings, "llm-pi-ai")?.value?.providers?.[EXPECTED_PROVIDER];
  if (!isPlainRecord(storedProfile) || storedProfile.baseURL !== providerProfile.baseURL) {
    compatibilityFailure("the live settings view lost the exact loopback Ollama profile");
  }

  // Provider adapters are host-scoped. Persist the deterministic fixture,
  // then cross the same controlled restart boundary used by the native app
  // before creating the first session.
  const preSessionPi = namespace(finalSettings, "llm-pi-ai");
  const fixtureBaseURL = providerFixtureBaseURL(state.provider.ready.origin);
  const fixtureSettings = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{ op: "set", path: ["providers", EXPECTED_PROVIDER, "baseURL"], value: fixtureBaseURL }],
    expectedRevision: preSessionPi.revision
  }, trace);
  if (fixtureSettings?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== fixtureBaseURL) {
    compatibilityFailure("the deterministic local provider fixture was not applied before session creation");
  }
  client = await restartCandidateHarness(layout, state, "post-provider-settings-runtime");
  await assertReviewedPluginsActive(state);
  const restartedSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  assertExactLocalDefault(namespace(restartedSettings, "agent-default-model"));
  if (namespace(restartedSettings, "llm-pi-ai")?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== fixtureBaseURL) {
    compatibilityFailure("the deterministic local provider fixture did not survive the required host restart");
  }
  const restartedSessions = await call(client.sessions.list, "session.list", {}, trace);
  if (!Array.isArray(restartedSessions?.items) || restartedSessions.items.length !== 0) {
    compatibilityFailure("the provider restart introduced a session before the canary's first session");
  }
  const providerDirectory = await call(client.llm.providers, "llm.providers", {}, trace);
  const modelCatalog = await call(client.llm.models, "llm.models", {}, trace);
  assertLocalCatalog(providerDirectory, modelCatalog);

  const workspaceCreated = await call(client.workspace.create, "workspace.create", { path: state.workspace }, trace);
  if (workspaceCreated?.workspace?.path !== state.workspace) compatibilityFailure("workspace.create returned the wrong isolated path");
  const workspaceId = workspaceCreated.workspace.workspaceId;
  const workspaces = await call(client.workspace.list, "workspace.list", {}, trace);
  if (!workspaces.items.some((entry) => entry.workspaceId === workspaceId)) compatibilityFailure("workspace.list omitted the created workspace");

  // This is intentionally the first session.create in the entire clean home.
  // Both settings namespaces were committed and re-read before this boundary.
  const created = await call(client.sessions.create, "session.create", { workspaceId }, trace);
  const sessionId = created.sessionId;
  const models = await call(client.sessions.models, "session.models", { sessionId }, trace);
  const blankList = await call(client.sessions.list, "session.list", {}, trace);
  const blankSummary = blankList.items.find((entry) => entry.sessionId === sessionId);
  assertBlankLocalSession(models, blankSummary);

  const selected = await call(client.sessions.selectModel, "session.selectModel", {
    sessionId,
    provider: EXPECTED_PROVIDER,
    model: EXPECTED_MODEL
  }, trace);
  if (!sameRoute(selected.selected)) compatibilityFailure("session.selectModel did not retain the exact Qwen route");

  const initialHistory = await call(client.sessions.history, "session.history", { sessionId, maxMessages: 100 }, trace);
  if (!Array.isArray(initialHistory.events)) compatibilityFailure("session.history did not return a typed event list");
  const renamed = await call(client.sessions.rename, "session.rename", {
    sessionId,
    title: "Local Qwen compatibility canary"
  }, trace);
  if (renamed.title !== "Local Qwen compatibility canary") compatibilityFailure("session.rename did not retain the exact title");

  const prompt = await call(client.sessions.prompt, "session.prompt", {
    sessionId,
    mode: "queue",
    content: [{ type: "text", text: "Reply briefly. LOCAL_HARNESS_WEB_RPC_SIMPLE" }],
    clientTimeZone: "UTC"
  }, trace);
  if (prompt.accepted !== true) compatibilityFailure("session.prompt did not accept the bounded local turn");
  const completedHistory = await waitForTurnEnd(
    client,
    sessionId,
    trace,
    turnEndCount(initialHistory),
    "SIMULATED_SIMPLE_OK",
    "bounded simple local turn"
  );
  if (!JSON.stringify(completedHistory).includes("SIMULATED_SIMPLE_OK")) {
    compatibilityFailure("the bounded local turn completed without the fixture's exact response marker");
  }
  const simpleProviderRows = await readProviderRows(state.provider.logPath);
  const simpleCalls = simpleProviderRows.filter((row) =>
    row.kind === "chat" && row.text?.includes("LOCAL_HARNESS_WEB_RPC_SIMPLE")
  );
  if (simpleCalls.length !== 1
      || simpleCalls[0].maxTokens !== 4_096
      || simpleCalls[0].maxTokensField !== "max_tokens"
      || simpleCalls[0].reasoningEffort !== "none") {
    compatibilityFailure("the local route did not apply the exact fast output cap and explicit reasoning-off default");
  }
  if (!Array.isArray(simpleCalls[0].tools)
      || !simpleCalls[0].tools.includes("web_fetch")
      || simpleCalls[0].tools.includes("web_search")) {
    compatibilityFailure("the ordinary local agent turn did not receive the exact approved-fetch-only web capability");
  }

  const liveWebFetch = process.env.LOCAL_HARNESS_LIVE_WEB_FETCH === "1";
  const webRequestStart = state.mux.requests.length;
  const webHistoryBeforePrompt = await call(client.sessions.history, "session.history", {
    sessionId,
    maxMessages: 100
  }, trace);
  const webPrompt = await call(client.sessions.prompt, "session.prompt", {
    sessionId,
    mode: "queue",
    content: [{ type: "text", text: `Retrieve ${WEB_FETCH_CANARY_URL} once. CONTRACT_WEB_FETCH` }],
    clientTimeZone: "UTC"
  }, trace);
  if (webPrompt.accepted !== true) compatibilityFailure("the approved-page canary turn was not accepted");
  const webRequest = await waitForWebFetchApproval(state, sessionId, webRequestStart);
  await answerApproval(client, state, webRequest, liveWebFetch ? "allowed-once" : "rejected", trace, "web fetch");
  const webHistory = await waitForTurnEnd(
    client,
    sessionId,
    trace,
    turnEndCount(webHistoryBeforePrompt),
    "SIMULATED_WEB_FETCH_OK",
    liveWebFetch ? "live approved-page retrieval" : "approved-page denial"
  );
  const webHistoryText = JSON.stringify(webHistory);
  if (!webHistoryText.includes("SIMULATED_WEB_FETCH_OK")) {
    compatibilityFailure("the approved-page canary did not complete through the local model fixture");
  }
  const webProviderRows = (await readProviderRows(state.provider.logPath)).filter((row) =>
    row.kind === "chat" && row.text?.includes("CONTRACT_WEB_FETCH")
  );
  const webToolRows = webProviderRows.filter((row) => Array.isArray(row.toolMessages) && row.toolMessages.length > 0);
  if (webToolRows.length !== 1) compatibilityFailure("the approved-page canary did not produce one model-visible tool result");
  const webToolResult = JSON.stringify(webToolRows[0].toolMessages);
  if (liveWebFetch) {
    if (!hasSuccessfulWebFetchToolResult(webToolRows[0].toolMessages)) {
      compatibilityFailure("the live approved-page retrieval did not return one successful result for the exact URL");
    }
  } else if (!/APPROVAL_DENIED|not approved|user rejected tool/iu.test(webToolResult)) {
    compatibilityFailure("the rejected approved-page retrieval did not record a bounded denial result");
  }

  const automaticBaselineTurnEnds = turnEndCount(webHistory);
  const automaticPrompt = await call(client.sessions.prompt, "session.prompt", {
    sessionId,
    mode: "queue",
    content: [{ type: "text", text: "Finish without asking me to continue. CONTRACT_AUTO_CONTINUE" }],
    clientTimeZone: "UTC"
  }, trace);
  if (automaticPrompt.accepted !== true) compatibilityFailure("session.prompt did not accept the automatic-continuation turn");
  const automaticHistory = await waitForTurnEnd(
    client,
    sessionId,
    trace,
    automaticBaselineTurnEnds,
    "SIMULATED_AUTOCONTINUE_OK",
    "automatic max-token continuation"
  );
  const automaticTurnEnds = automaticHistory.events
    .filter((entry) => entry?.event?.type === "turn/end")
    .slice(automaticBaselineTurnEnds);
  if (automaticTurnEnds.length !== 2
      || automaticTurnEnds[0]?.event?.data?.reason?.kind !== "max-tokens"
      || automaticTurnEnds[1]?.event?.data?.reason?.kind !== "completed") {
    compatibilityFailure("the max-token turn was not followed by exactly one automatically completed turn");
  }
  const automaticNotice = automaticHistory.events.find((entry) =>
    entry?.event?.type === "user/message"
      && entry.event.data?.source?.kind === "plugin"
      && entry.event.data?.source?.plugin === "fulmar-automatic-continuation"
  );
  if (automaticNotice?.event?.data?.source?.summary !== "Fulmar continued automatically · 1/12") {
    compatibilityFailure("the durable automatic-continuation turn omitted its bounded Fulmar provenance");
  }
  const automaticProviderRows = (await readProviderRows(state.provider.logPath)).filter((row) =>
    row.kind === "chat" && row.text?.includes("CONTRACT_AUTO_CONTINUE")
  );
  if (automaticProviderRows.length !== 2
      || automaticProviderRows.some((row) => row.maxTokens !== 4_096)
      || !automaticProviderRows[1].text.includes("Continue the unfinished user task from exactly where the previous response stopped.")) {
    compatibilityFailure("the provider did not observe one exact bounded automatic continuation");
  }

  const forked = await call(client.sessions.fork, "session.fork", { sessionId }, trace);
  if (forked.sessionId === sessionId) compatibilityFailure("session.fork reused the parent identity");
  const forkModels = await call(client.sessions.models, "session.models", { sessionId: forked.sessionId }, trace);
  if (!sameRoute(forkModels.current)) compatibilityFailure("the fork lost the exact local route");
  const forkHistory = await call(client.sessions.history, "session.history", {
    sessionId: forked.sessionId,
    maxMessages: 100
  }, trace);
  if (!forkHistory.events.some((entry) => entry?.event?.type === "turn/end")) compatibilityFailure("the fork omitted its completed source turn");

  const cancelCreated = await call(client.sessions.create, "session.create", { workspaceId }, trace);
  const cancelModels = await call(client.sessions.models, "session.models", { sessionId: cancelCreated.sessionId }, trace);
  if (!sameRoute(cancelModels.current)) compatibilityFailure("the cancellation session lost the exact local default");
  await call(client.sessions.prompt, "session.prompt", {
    sessionId: cancelCreated.sessionId,
    mode: "queue",
    content: [{ type: "text", text: "Hold the local stream. CONTRACT_CANCEL" }],
    clientTimeZone: "UTC"
  }, trace);
  await waitFor(async () => {
    const rows = await readProviderRows(state.provider.logPath);
    return rows.some((row) => row.kind === "chat" && row.text?.includes("CONTRACT_CANCEL"));
  }, { child: state.provider.child, label: "local cancellation stream", timeoutMs: 20_000 });
  const cancelled = await call(client.sessions.cancel, "session.cancel", { sessionId: cancelCreated.sessionId }, trace);
  if (cancelled.accepted !== true) compatibilityFailure("session.cancel did not accept cancellation");
  await waitFor(async () => {
    const rows = await readProviderRows(state.provider.logPath);
    return rows.some((row) => row.kind === "cancelled" && row.model === EXPECTED_MODEL);
  }, { child: state.provider.child, label: "provider cancellation propagation", timeoutMs: 10_000 });

  const archived = await call(client.workspace.archiveSession, "workspace.archiveSession", {
    sessionId: forked.sessionId
  }, trace);
  if (!archived.archivedSessionIds.includes(forked.sessionId)) compatibilityFailure("workspace.archiveSession omitted the archived fork");
  const finalWorkspaces = await call(client.workspace.list, "workspace.list", {}, trace);
  if (!finalWorkspaces.archivedSessionIds.includes(forked.sessionId)) compatibilityFailure("workspace.list lost the archived fork");
  const finalSessions = await call(client.sessions.list, "session.list", {}, trace);
  const parent = finalSessions.items.find((entry) => entry.sessionId === forked.sessionId)?.parentSessionId;
  if (parent !== sessionId) compatibilityFailure("session.list did not retain the fork parent relationship");

  // Restore and re-read the exact production bootstrap value so the durable
  // isolated document ends in precisely the same shape the native app writes.
  const restoreDescription = await call(client.settings.describe, "settings.describe", {}, trace);
  const restorePi = namespace(restoreDescription, "llm-pi-ai");
  const restoredPi = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{
      op: "set",
      path: ["providers", EXPECTED_PROVIDER, "baseURL"],
      value: providerProfile.baseURL
    }],
    expectedRevision: restorePi.revision
  }, trace);
  if (restoredPi?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== providerProfile.baseURL) {
    compatibilityFailure("the exact production Ollama endpoint was not restored");
  }

  await waitFor(() => state.mux.frames.length > 0 && state.host.frames.length > 0, {
    label: "authenticated typed WebSocket frames",
    timeoutMs: 10_000
  });
  state.mux.assertHealthy();
  state.host.assertHealthy();
  const bridgeBehaviorChecks = await assertServedSecurityBridge(layout, state);

  const methods = [...new Set(trace)].sort();
  for (const required of REQUIRED_TYPED_METHODS) {
    if (!methods.includes(required)) compatibilityFailure(`the canary did not execute required typed method ${required}`);
  }
  return {
    methods,
    muxFrames: state.mux.frames.length,
    hostFrames: state.host.frames.length,
    bridgeBehaviorChecks,
    automaticContinuationTurns: automaticTurnEnds.length,
    approvedPageOutcome: liveWebFetch ? "live-allowed" : "rejected"
  };
}

async function waitForMCPApproval(state, sessionId, callId, startIndex) {
  const request = await waitFor(() => state.mux.requests.slice(startIndex).find((entry) =>
    entry.payload?.type === "approval/requested"
    && entry.payload.sessionId === sessionId
    && entry.payload.toolName === MCP_TOOL_NAME
    && entry.payload.callId === callId
  ), { child: state.runtime.child, label: `MCP approval request ${callId}`, timeoutMs: 30_000 });
  const reason = request.payload.reason ?? "";
  if (
    !reason.includes(`Run approved local MCP tool “${MCP_TOOL_NAME}”?`)
    || !reason.includes(`Project: ${state.workspace}`)
    || !reason.includes(`Model provider: ${EXPECTED_PROVIDER} (onDevice)`)
    || !reason.includes("Arguments (exact JSON): {}")
  ) compatibilityFailure("the candidate MCP approval omitted its exact tool, project, route, or arguments disclosure");
  return request;
}

async function waitForWebFetchApproval(state, sessionId, startIndex) {
  const request = await waitFor(() => state.mux.requests.slice(startIndex).find((entry) =>
    entry.payload?.type === "approval/requested"
    && entry.payload.sessionId === sessionId
    && entry.payload.toolName === WEB_FETCH_TOOL_NAME
    && entry.payload.callId === "call_web_fetch_1"
  ), { child: state.runtime.child, label: "approved-page permission request", timeoutMs: 30_000 });
  assertExactWebFetchApprovalReason(request.payload.reason);
  return request;
}

async function answerApproval(client, state, request, outcome, trace, label) {
  const frameStart = state.mux.frames.length;
  let receipt;
  try {
    receipt = await client.respond({
      type: "client-response",
      rpcId: request.rpcId,
      result: {
        ok: true,
        value: {
          sessionId: request.payload.sessionId,
          approvalId: request.payload.approvalId,
          outcome
        }
      }
    });
  } catch (error) {
    compatibilityFailure(`approval.respond transport/schema validation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  trace.push("approval.respond");
  if (receipt?.accepted !== true) compatibilityFailure(`approval.respond was not accepted (${String(receipt?.reason ?? "unknown")})`);
  await waitFor(() => state.mux.frames.slice(frameStart).find((frame) =>
    frame?.type === "approval/resolved"
    && frame.sessionId === request.payload.sessionId
    && frame.approvalId === request.payload.approvalId
    && frame.outcome === outcome
  ), { child: state.runtime.child, label: `${label} approval resolution ${outcome}`, timeoutMs: 10_000 });
}

function extractAllowedMCPOutput(rows, subprocesses) {
  const toolRows = rows.filter((row) => Array.isArray(row.toolMessages) && row.toolMessages.length > 0);
  if (toolRows.length !== 1) compatibilityFailure("the allow-once MCP turn did not produce exactly one model-visible tool result");
  const serialized = JSON.stringify(toolRows[0].toolMessages);
  const pattern = /MCP_ALLOWED_ONCE_OK\|call_count=1\|server_pid=(\d+)\|guard_pid=(\d+)\|padding=x+/gu;
  const output = [...serialized.matchAll(pattern)].find((match) =>
    match[1] === String(subprocesses.serverPID) && match[2] === String(subprocesses.guardPID)
  )?.[0];
  if (output === undefined) compatibilityFailure("the allow-once MCP result was absent from the next local-model request");
  return output;
}

function pidIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

async function assertMCPProcessesStopped(subprocesses) {
  for (const [label, pid] of [["reviewed MCP server", subprocesses.serverPID], ["MCP guard", subprocesses.guardPID]]) {
    await waitFor(() => !pidIsAlive(pid), { label: `${label} PID ${pid} shutdown`, timeoutMs: 10_000 });
  }
}

export function assertExactMCPProviderCallTopology(deniedCalls, allowedCalls) {
  if (!Array.isArray(deniedCalls) || !Array.isArray(allowedCalls)) {
    compatibilityFailure("MCP provider call topology was unavailable");
  }
  const agentCalls = (rows) => rows.filter((row) =>
    row?.tools?.filter((name) => name === MCP_TOOL_NAME).length === 1
  );
  const titleCalls = (rows) => rows.filter((row) =>
    Array.isArray(row?.tools) && row.tools.length === 0 && row.toolMessages === undefined
  );
  const deniedRows = agentCalls(deniedCalls);
  const allowedRows = agentCalls(allowedCalls);
  if (
    deniedCalls.length !== 3 || allowedCalls.length !== 3
    || deniedRows.length !== 2 || allowedRows.length !== 2
    || titleCalls(deniedCalls).length !== 1 || titleCalls(allowedCalls).length !== 1
  ) {
    const shape = (rows) => rows.map((row) => [
      Array.isArray(row?.tools) ? row.tools.length : -1,
      Array.isArray(row?.tools) ? row.tools.filter((name) => name === MCP_TOOL_NAME).length : -1,
      Array.isArray(row?.toolMessages) ? row.toolMessages.length : -1
    ].join("/")).join(",");
    compatibilityFailure(
      "each MCP approval path did not make exactly one title call plus one tool-request and one tool-result call "
      + `(denied ${deniedCalls.length} [${shape(deniedCalls)}]; allowed ${allowedCalls.length} [${shape(allowedCalls)}])`
    );
  }
  return Object.freeze({ deniedRows: Object.freeze(deniedRows), allowedRows: Object.freeze(allowedRows) });
}

async function runMCPCompatibility(layout, state) {
  let client = await connectCandidateAPI(layout, state);
  const trace = state.methodTrace;
  const hostDescription = await call(client.host.describe, "host.describe", {}, trace);
  if (!isPlainRecord(hostDescription)) compatibilityFailure("the MCP candidate host returned an invalid description");
  await assertReviewedPluginsActive(state);

  const initialSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  const initialSessions = await call(client.sessions.list, "session.list", {}, trace);
  const initialDefault = assertFreshRuntimeState(initialSettings, initialSessions, state.settingsExistedBeforeLaunch);
  const piNamespace = namespace(initialSettings, "llm-pi-ai");
  const providerProfile = localProviderProfile();
  const updatedPi = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{ op: "set", path: ["providers", EXPECTED_PROVIDER], value: providerProfile }],
    expectedRevision: piNamespace.revision
  }, trace);
  if (updatedPi?.value?.providers?.[EXPECTED_PROVIDER]?.apiKeyEnv !== "OLLAMA_API_KEY") {
    compatibilityFailure("the MCP canary lost the exact isolated Ollama credential reference");
  }
  const updatedDefault = await call(client.settings.mutate, "settings.mutate", {
    ns: "agent-default-model",
    ops: [
      { op: "set", path: ["provider"], value: EXPECTED_PROVIDER },
      { op: "set", path: ["model"], value: EXPECTED_MODEL },
      { op: "unset", path: ["reasoningEffort"] }
    ],
    expectedRevision: initialDefault.revision
  }, trace);
  assertExactLocalDefault(updatedDefault);
  const finalSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  assertExactLocalDefault(namespace(finalSettings, "agent-default-model"));
  if (namespace(finalSettings, "llm-pi-ai")?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== providerProfile.baseURL) {
    compatibilityFailure("the MCP canary lost the reviewed production Ollama endpoint before restart");
  }

  // MCP provider adapters cross the same host restart boundary as ordinary
  // sessions; no session or tool process may be reused across the transition.
  const preSessionPi = namespace(finalSettings, "llm-pi-ai");
  const fixtureBaseURL = providerFixtureBaseURL(state.provider.ready.origin);
  const fixtureSettings = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{ op: "set", path: ["providers", EXPECTED_PROVIDER, "baseURL"], value: fixtureBaseURL }],
    expectedRevision: preSessionPi.revision
  }, trace);
  if (fixtureSettings?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== fixtureBaseURL) {
    compatibilityFailure("the MCP canary could not bind its deterministic fixture before session creation");
  }
  client = await restartCandidateHarness(layout, state, "post-mcp-provider-settings-runtime");
  await assertReviewedPluginsActive(state);
  const restartedSettings = await call(client.settings.describe, "settings.describe", {}, trace);
  assertExactLocalDefault(namespace(restartedSettings, "agent-default-model"));
  if (namespace(restartedSettings, "llm-pi-ai")?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== fixtureBaseURL) {
    compatibilityFailure("the MCP deterministic provider fixture did not survive the required host restart");
  }
  const restartedSessions = await call(client.sessions.list, "session.list", {}, trace);
  if (!Array.isArray(restartedSessions?.items) || restartedSessions.items.length !== 0) {
    compatibilityFailure("the MCP provider restart introduced a session before its first reviewed session");
  }
  const providers = await call(client.llm.providers, "llm.providers", {}, trace);
  const models = await call(client.llm.models, "llm.models", {}, trace);
  assertLocalCatalog(providers, models);

  const workspaceCreated = await call(client.workspace.create, "workspace.create", { path: state.workspace }, trace);
  if (workspaceCreated?.workspace?.path !== state.workspace) compatibilityFailure("the MCP workspace did not retain its reviewed project path");
  const workspaceId = workspaceCreated.workspace.workspaceId;
  const deniedSession = await call(client.sessions.create, "session.create", { workspaceId }, trace);
  const deniedModels = await call(client.sessions.models, "session.models", { sessionId: deniedSession.sessionId }, trace);
  const blankSessions = await call(client.sessions.list, "session.list", {}, trace);
  assertBlankLocalSession(deniedModels, blankSessions.items.find((entry) => entry.sessionId === deniedSession.sessionId));

  let requestStart = state.mux.requests.length;
  const deniedHistoryBeforePrompt = await call(client.sessions.history, "session.history", {
    sessionId: deniedSession.sessionId,
    maxMessages: 100
  }, trace);
  const deniedPrompt = await call(client.sessions.prompt, "session.prompt", {
    sessionId: deniedSession.sessionId,
    mode: "queue",
    content: [{ type: "text", text: "Call the reviewed tool once. CONTRACT_MCP_DENY" }],
    clientTimeZone: "UTC"
  }, trace);
  if (deniedPrompt.accepted !== true) compatibilityFailure("the MCP denial turn was not accepted");
  const deniedRequest = await waitForMCPApproval(state, deniedSession.sessionId, "call_mcp_deny_1", requestStart);
  await answerApproval(client, state, deniedRequest, "rejected", trace, "MCP");
  const deniedHistory = await waitForTurnEnd(
    client,
    deniedSession.sessionId,
    trace,
    turnEndCount(deniedHistoryBeforePrompt),
    "SIMULATED_MCP_DENY_OK"
  );
  const deniedHistoryText = JSON.stringify(deniedHistory);
  if (!deniedHistoryText.includes("SIMULATED_MCP_DENY_OK")) {
    compatibilityFailure("the MCP denial turn did not complete through the local model fixture");
  }
  if (!/MCP_APPROVAL_DENIED|not approved/iu.test(deniedHistoryText)) {
    compatibilityFailure("the MCP denial turn did not durably record the rejected tool result");
  }

  const allowedSession = await call(client.sessions.create, "session.create", { workspaceId }, trace);
  const allowedModels = await call(client.sessions.models, "session.models", { sessionId: allowedSession.sessionId }, trace);
  if (!sameRoute(allowedModels.current) || allowedModels.routable !== true) {
    compatibilityFailure("the MCP allow-once session lost the exact local route");
  }
  requestStart = state.mux.requests.length;
  const allowedHistoryBeforePrompt = await call(client.sessions.history, "session.history", {
    sessionId: allowedSession.sessionId,
    maxMessages: 100
  }, trace);
  const allowedPrompt = await call(client.sessions.prompt, "session.prompt", {
    sessionId: allowedSession.sessionId,
    mode: "queue",
    content: [{ type: "text", text: "Call the reviewed tool once. CONTRACT_MCP_ALLOW" }],
    clientTimeZone: "UTC"
  }, trace);
  if (allowedPrompt.accepted !== true) compatibilityFailure("the MCP allow-once turn was not accepted");
  const allowedRequest = await waitForMCPApproval(state, allowedSession.sessionId, "call_mcp_allow_1", requestStart);
  await answerApproval(client, state, allowedRequest, "allowed-once", trace, "MCP");
  const allowedHistory = await waitForTurnEnd(
    client,
    allowedSession.sessionId,
    trace,
    turnEndCount(allowedHistoryBeforePrompt),
    "SIMULATED_MCP_ALLOW_OK"
  );
  if (!JSON.stringify(allowedHistory).includes("SIMULATED_MCP_ALLOW_OK")) {
    compatibilityFailure("the MCP allow-once turn did not complete through the local model fixture");
  }

  const providerRows = await readProviderRows(state.provider.logPath);
  const deniedCalls = providerRows.filter((row) => row.kind === "chat" && row.text?.includes("CONTRACT_MCP_DENY"));
  const allowedCalls = providerRows.filter((row) => row.kind === "chat" && row.text?.includes("CONTRACT_MCP_ALLOW"));
  const { deniedRows, allowedRows } = assertExactMCPProviderCallTopology(deniedCalls, allowedCalls);
  for (const row of [...deniedRows, ...allowedRows]) {
    if (row.tools?.filter((name) => name === MCP_TOOL_NAME).length !== 1) {
      compatibilityFailure("the exact MCP namespace was not visible exactly once to the local model");
    }
  }
  const subprocesses = assertMCPToolAdvertisement(deniedRows[0].mcpTool);
  const allowedSubprocesses = assertMCPToolAdvertisement(allowedRows[0].mcpTool);
  if (
    allowedSubprocesses.serverPID !== subprocesses.serverPID
    || allowedSubprocesses.guardPID !== subprocesses.guardPID
  ) compatibilityFailure("the deny and allow-once turns did not use the same reviewed MCP process pair");
  const deniedToolRows = deniedRows.filter((row) => Array.isArray(row.toolMessages) && row.toolMessages.length > 0);
  if (deniedToolRows.length !== 1 || JSON.stringify(deniedToolRows[0].toolMessages).includes("MCP_ALLOWED_ONCE_OK")) {
    compatibilityFailure("the rejected MCP call executed or failed to produce one bounded denial result");
  }
  const outputBytes = assertMCPAllowedOutput(extractAllowedMCPOutput(allowedRows, subprocesses), subprocesses);
  if (!pidIsAlive(subprocesses.serverPID) || !pidIsAlive(subprocesses.guardPID)) {
    compatibilityFailure("the reviewed MCP process pair stopped before candidate host disposal");
  }

  const restoreDescription = await call(client.settings.describe, "settings.describe", {}, trace);
  const restorePi = namespace(restoreDescription, "llm-pi-ai");
  const restoredPi = await call(client.settings.mutate, "settings.mutate", {
    ns: "llm-pi-ai",
    ops: [{ op: "set", path: ["providers", EXPECTED_PROVIDER, "baseURL"], value: providerProfile.baseURL }],
    expectedRevision: restorePi.revision
  }, trace);
  if (restoredPi?.value?.providers?.[EXPECTED_PROVIDER]?.baseURL !== providerProfile.baseURL) {
    compatibilityFailure("the MCP canary did not restore the exact production Ollama endpoint");
  }
  state.mux.assertHealthy();
  state.host.assertHealthy();
  return {
    checks: 5,
    outputBytes,
    subprocesses,
    muxFrames: state.mux.frames.length,
    hostFrames: state.host.frames.length
  };
}

async function assertEphemeralArtifacts(state) {
  await waitFor(async () => {
    const candidate = await boundedJSON(state.telemetryFile, TELEMETRY_MAXIMUM_FILE_BYTES);
    try {
      assertPerformanceTelemetryDocument(candidate);
      return candidate;
    } catch (error) {
      if (error instanceof DSHCompatibilityError) return undefined;
      throw error;
    }
  }, { child: state.runtime?.child, label: "candidate performance telemetry", timeoutMs: 10_000 });
  const [
    supportInfo,
    telemetryDirectoryInfo,
    telemetryLockInfo,
    supportEntries,
    telemetryEntries,
    telemetrySnapshot,
    thermalPolicySnapshot
  ] = await Promise.all([
    lstat(state.applicationSupport),
    lstat(state.telemetryDirectory),
    lstat(state.telemetryLock),
    readdir(state.applicationSupport),
    readdir(state.telemetryDirectory),
    boundedJSONSnapshot(state.telemetryFile, TELEMETRY_MAXIMUM_FILE_BYTES, {
      label: "candidate performance telemetry",
      minimumBytes: 2,
      requireCurrentUser: true,
      requirePrivateMode: true
    }),
    boundedJSONSnapshot(state.thermalPolicyFile, THERMAL_POLICY_MAXIMUM_FILE_BYTES, {
      label: "candidate adaptive thermal policy",
      minimumBytes: 2,
      requireCurrentUser: true,
      requirePrivateMode: true
    })
  ]);
  const telemetryFileInfo = telemetrySnapshot.metadata;
  const thermalPolicyInfo = thermalPolicySnapshot.metadata;
  const telemetryBytes = telemetrySnapshot.bytes;
  const thermalPolicyBytes = thermalPolicySnapshot.bytes;
  const telemetry = telemetrySnapshot.value;
  const thermalPolicy = thermalPolicySnapshot.value;
  const currentUID = typeof process.getuid === "function" ? process.getuid() : Number(telemetryFileInfo.uid);
  if (
    !supportInfo.isDirectory()
    || supportInfo.isSymbolicLink()
    || supportInfo.uid !== currentUID
    || (supportInfo.mode & 0o777) !== 0o700
    || !telemetryDirectoryInfo.isDirectory()
    || telemetryDirectoryInfo.isSymbolicLink()
    || telemetryDirectoryInfo.uid !== currentUID
    || (telemetryDirectoryInfo.mode & 0o777) !== 0o700
    || !telemetryFileInfo.isFile()
    || telemetryFileInfo.uid !== BigInt(currentUID)
    || telemetryFileInfo.nlink !== 1n
    || (telemetryFileInfo.mode & 0o777n) !== 0o600n
    || telemetryFileInfo.size < 2n
    || telemetryFileInfo.size > BigInt(TELEMETRY_MAXIMUM_FILE_BYTES)
    || !telemetryLockInfo.isFile()
    || telemetryLockInfo.isSymbolicLink()
    || telemetryLockInfo.uid !== currentUID
    || telemetryLockInfo.nlink !== 1
    || (telemetryLockInfo.mode & 0o777) !== 0o600
    || telemetryLockInfo.size !== 0
    || !thermalPolicyInfo.isFile()
    || thermalPolicyInfo.uid !== BigInt(currentUID)
    || thermalPolicyInfo.nlink !== 1n
    || (thermalPolicyInfo.mode & 0o777n) !== 0o600n
    || thermalPolicyInfo.size < 2n
    || thermalPolicyInfo.size > BigInt(THERMAL_POLICY_MAXIMUM_FILE_BYTES)
    || supportEntries.length !== 1
    || supportEntries[0] !== "PerformanceTelemetry"
    || JSON.stringify(telemetryEntries.sort()) !== JSON.stringify([
      ".performance-telemetry.lock",
      "performance-telemetry.json",
      "thermal-workload-policy.json"
    ])
  ) compatibilityFailure("performance telemetry or thermal policy escaped its exact owner-only directory/file topology or byte bound");
  if (JSON.stringify(Object.keys(thermalPolicy).sort()) !== JSON.stringify([
    "ecoMaxOutputTokens", "minimumDelayMilliseconds", "mode", "schemaVersion"
  ]) || thermalPolicy.schemaVersion !== 1 || thermalPolicy.mode !== "normal"
      || thermalPolicy.ecoMaxOutputTokens !== 2_048
      || thermalPolicy.minimumDelayMilliseconds !== 5_000) {
    compatibilityFailure("the adaptive thermal policy changed outside its fixed native schema");
  }
  assertPerformanceTelemetryContentAbsent(telemetryBytes);
  assertPerformanceTelemetryContentAbsent(thermalPolicyBytes);
  if (telemetryBytes.includes(Buffer.from(state.token)) || telemetryBytes.includes(Buffer.from(state.nonce))
      || thermalPolicyBytes.includes(Buffer.from(state.token)) || thermalPolicyBytes.includes(Buffer.from(state.nonce))) {
    compatibilityFailure("performance telemetry or thermal policy retained the candidate authentication identity");
  }
  state.telemetryRecordCount = assertPerformanceTelemetryDocument(telemetry);

  const settingsPath = path.join(state.dshHome, "settings.yaml");
  const info = await lstat(settingsPath).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o600) {
    compatibilityFailure("the isolated settings document is missing, linked, or not owner-only");
  }
  const settings = await boundedText(settingsPath);
  if (!settings.includes(EXPECTED_MODEL) || !settings.includes("OLLAMA_API_KEY")) {
    compatibilityFailure("the isolated settings document omitted the exact local route");
  }
  if (/DEEPSEEK_API_KEY|api\.deepseek\.com|onboarding/iu.test(settings)) {
    compatibilityFailure("the isolated settings document introduced a DeepSeek key or onboarding dependency");
  }

  const helperLogPath = path.join(state.home, "canary-credential-helper.log");
  const helperLogInfo = await lstat(helperLogPath).catch(() => undefined);
  const helperLog = helperLogInfo === undefined ? "" : await boundedText(helperLogPath, 64 * 1024);
  const helperRows = helperLog.trim().split("\n").filter(Boolean).map((row) => row.split("\t"));
  const allowedHelperCall = ([command, subject]) =>
    command === "list-records" && subject === ""
    || command === "get-record" && subject === "llm-pi-ai/ollama";
  if (
    helperRows.some(([, subject]) => subject === "OLLAMA_API_KEY")
    || helperRows.some((row) => !allowedHelperCall(row))
  ) {
    compatibilityFailure("the isolated local route touched Keychain or escaped the reviewed authorization-record read set");
  }

  const providerRows = await readProviderRows(state.provider.logPath);
  const chats = providerRows.filter((row) => row.kind === "chat");
  if (chats.length < 2) compatibilityFailure("the local provider fixture observed too few typed turns");
  if (chats.some((row) => row.authorized !== true || row.model !== EXPECTED_MODEL || row.stream !== true)) {
    compatibilityFailure("the local provider fixture observed a wrong route, unauthenticated request, or non-streaming call");
  }
  if (chats.some((row) => row.tools?.some((name) => name === "workflow" || name === "ralph"))) {
    compatibilityFailure("the model received a workflow capability removed by the sanitized Fulmar preset");
  }
  if (chats.some((row) => row.tools?.includes("web_search"))) {
    compatibilityFailure("a model call received the disabled credential-dependent web_search capability");
  }
  if (providerRows.some((row) => row.kind === "unauthorized")) {
    compatibilityFailure("the candidate sent an unauthorized local-provider request");
  }
}

function childEnvironment(state, layout) {
  const username = os.userInfo().username;
  const providerSecurity = providerFixtureSecurityEnvironment(state.provider?.ready);
  return Object.freeze({
    HOME: state.home,
    USER: username,
    LOGNAME: username,
    PATH: "/usr/bin:/bin",
    LANG: "en_US.UTF-8",
    TMPDIR: state.temp,
    DSH_HOME: state.dshHome,
    DSH_AGENTS_HOME: path.join(state.dshHome, "Agents"),
    DSH_TELEMETRY_MODE: "DISABLED",
    OLLAMA_HOST: providerSecurity.ollamaHost,
    OLLAMA_API_KEY: "local-ollama",
    NARB_DISABLE_NATIVE_CACHE: "1",
    LOCAL_HARNESS_CREDENTIAL_PLUGIN: layout.credentialPlugin,
    LOCAL_HARNESS_MCP_PLUGIN: layout.mcpPlugin,
    LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN: layout.clientSecurityPlugin,
    LOCAL_HARNESS_PERFORMANCE_PLUGIN: layout.performancePlugin,
    LOCAL_HARNESS_AUTOMATIC_CONTINUATION_DIAGNOSTICS: "1",
    LOCAL_HARNESS_CREDENTIAL_HELPER: path.join(PROJECT_DIR, "Tests", "Fixtures", "CanaryCredentialHelper.sh"),
    LOCAL_HARNESS_CREDENTIAL_HOME: state.home,
    LOCAL_HARNESS_SANDBOX_HELPER: layout.sandboxHelper,
    LOCAL_HARNESS_WORKSPACE_ROOTS: JSON.stringify([state.workspace]),
    LOCAL_HARNESS_READONLY_ROOTS: JSON.stringify([state.skillRoot]),
    LOCAL_HARNESS_SANDBOX_TEMP: state.temp,
    LOCAL_HARNESS_FS_PLUGIN: layout.fsPlugin,
    LOCAL_HARNESS_MCP_CATALOG: state.mcpCatalog,
    LOCAL_HARNESS_PERFORMANCE_PROFILE: "fast",
    LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT: state.applicationSupport,
    LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE: state.telemetryFile,
    LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER: layout.credentialHelper,
    LOCAL_HARNESS_THERMAL_POLICY_FILE: state.thermalPolicyFile,
    LOCAL_HARNESS_PERFORMANCE_PROFILES: JSON.stringify({
      fast: { maxOutputTokens: 4_096 },
      balanced: { maxOutputTokens: EXPECTED_MAX_TOKENS },
      deep: { maxOutputTokens: 16_384 }
    }),
    LOCAL_HARNESS_ACTIVE_PROVIDER: EXPECTED_PROVIDER,
    LOCAL_HARNESS_CONTEXT_ENFORCEMENT: JSON.stringify({
      provider: EXPECTED_PROVIDER,
      model: EXPECTED_MODEL,
      contextWindowTokens: EXPECTED_CONTEXT_WINDOW
    }),
    LOCAL_HARNESS_STRICT_LOCAL: "1",
    LOCAL_HARNESS_PROVIDER_ORIGINS: JSON.stringify(providerSecurity.providerOrigins),
    LOCAL_HARNESS_RUNTIME_ROOT: layout.dsh
  });
}

function isExactCanaryRoot(root) {
  return typeof root === "string"
    && path.dirname(root) === path.dirname(TEMP_PREFIX)
    && path.basename(root).startsWith(path.basename(TEMP_PREFIX));
}

async function prepareState() {
  const root = await mkdtemp(TEMP_PREFIX);
  if (!isExactCanaryRoot(root)) {
    await rm(root, { recursive: true, force: true }).catch(() => {});
    compatibilityFailure("the private canary root escaped /private/tmp");
  }
  ACTIVE_ROOTS.add(root);
  try {
    const home = path.join(root, "home");
    const dshHome = path.join(home, ".dsh");
    const workspace = path.join(root, "workspace");
    const temp = path.join(root, "temp");
    const applicationSupportParent = path.join(root, "application-support");
    const applicationSupport = path.join(applicationSupportParent, "Local Harness");
    const telemetryDirectory = path.join(applicationSupport, "PerformanceTelemetry");
    const telemetryFile = path.join(telemetryDirectory, "performance-telemetry.json");
    const telemetryLock = path.join(telemetryDirectory, ".performance-telemetry.lock");
    const thermalPolicyFile = path.join(telemetryDirectory, "thermal-workload-policy.json");
    const workspacePolicyFile = path.join(dshHome, ".fulmar-workspace-mutation-policy.json");
    const skillRoot = path.join(dshHome, "skills", "Active");
    const mcpCatalog = path.join(root, "mcp-activation-catalog.json");
    await Promise.all([
      mkdir(path.join(dshHome, "Agents"), { recursive: true, mode: 0o700 }),
      mkdir(skillRoot, { recursive: true, mode: 0o700 }),
      mkdir(workspace, { recursive: true, mode: 0o700 }),
      mkdir(temp, { recursive: true, mode: 0o700 }),
      mkdir(telemetryDirectory, { recursive: true, mode: 0o700 })
    ]);
    for (const directory of [
      root, home, dshHome, path.join(dshHome, "Agents"), path.join(dshHome, "skills"), skillRoot,
      workspace, temp, applicationSupportParent, applicationSupport, telemetryDirectory
    ]) {
      await chmod(directory, 0o700);
    }
    const telemetry = await open(telemetryFile, "wx", 0o600);
    try {
      await telemetry.writeFile('{"schemaVersion":1,"records":[]}\n');
      await telemetry.sync();
    } finally {
      await telemetry.close();
    }
    const telemetryLockHandle = await open(telemetryLock, "wx", 0o600);
    try {
      await telemetryLockHandle.sync();
    } finally {
      await telemetryLockHandle.close();
    }
    const thermalPolicy = await open(thermalPolicyFile, "wx", 0o600);
    try {
      await thermalPolicy.writeFile('{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"normal","schemaVersion":1}\n');
      await thermalPolicy.sync();
    } finally {
      await thermalPolicy.close();
    }
    const workspacePolicy = await open(workspacePolicyFile, "wx", 0o600);
    try {
      await workspacePolicy.writeFile('{"mode":"readWrite","reason":"protectedCheckpoint","schemaVersion":1}\n');
      await workspacePolicy.sync();
    } finally {
      await workspacePolicy.close();
    }
    const catalog = await open(mcpCatalog, "wx", 0o600);
    try {
      await catalog.writeFile('{"schemaVersion":1,"plans":[]}\n');
      await catalog.sync();
    } finally {
      await catalog.close();
    }
    return {
      root, home, dshHome, workspace, temp, skillRoot, mcpCatalog,
      applicationSupport, telemetryDirectory, telemetryFile, telemetryLock, thermalPolicyFile,
      token: `canary-${randomBytes(32).toString("hex")}`,
      nonce: `canary-${randomBytes(24).toString("hex")}`,
      settingsExistedBeforeLaunch: false,
      methodTrace: [],
      provider: undefined,
      runtime: undefined,
      mux: undefined,
      host: undefined
    };
  } catch (error) {
    await rm(root, { recursive: true, force: true }).catch(() => {});
    ACTIVE_ROOTS.delete(root);
    throw error;
  }
}

async function removeStateRoot(state) {
  if (!isExactCanaryRoot(state?.root)) compatibilityFailure("refusing to remove an unvalidated canary root");
  await rm(state.root, { recursive: true, force: true });
  ACTIVE_ROOTS.delete(state.root);
}

function installSignalCleanup() {
  const onSignal = async (signal) => {
    const exitCode = signal === "SIGINT" ? 130 : 143;
    if (signalCleanupStarted) {
      for (const child of ACTIVE_CHILDREN) {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      }
      process.exit(exitCode);
    }
    signalCleanupStarted = true;
    const children = [...ACTIVE_CHILDREN];
    await Promise.all(children.map((child) => stopExactChild(child, `canary child PID ${child.pid}`).catch(() => {})));
    for (const root of [...ACTIVE_ROOTS]) {
      if (isExactCanaryRoot(root)) await rm(root, { recursive: true, force: true }).catch(() => {});
      ACTIVE_ROOTS.delete(root);
    }
    process.exit(exitCode);
  };
  process.once("SIGINT", () => { void onSignal("SIGINT"); });
  process.once("SIGTERM", () => { void onSignal("SIGTERM"); });
}

async function runCandidateMCPCanary(layout) {
  const state = await prepareState();
  let primaryError;
  let result;
  try {
    state.activation = await prepareReviewedMCPActivation(layout, state);
    state.settingsExistedBeforeLaunch = (await lstat(path.join(state.dshHome, "settings.yaml")).catch(() => undefined)) !== undefined;
    const providerEnvironment = childEnvironment(state, layout);
    state.provider = await startProvider(layout, state.root, providerEnvironment);
    const environment = childEnvironment(state, layout);
    state.runtime = await startHarness(layout, state.root, environment, state.workspace, state);
    result = await runMCPCompatibility(layout, state);
    await assertEphemeralArtifacts(state);
    result.telemetryRecords = state.telemetryRecordCount;
    const [catalogSnapshot, serverInfo] = await Promise.all([
      boundedJSONSnapshot(state.mcpCatalog, 2 * 1024 * 1024, {
        label: "reviewed MCP activation catalog",
        minimumBytes: 2,
        requireCurrentUser: true,
        requirePrivateMode: true
      }),
      lstat(state.activation.serverPath)
    ]);
    const catalogInfo = catalogSnapshot.metadata;
    const catalogValue = catalogSnapshot.value;
    const catalogBytes = catalogSnapshot.bytes;
    if (
      !catalogInfo.isFile()
      || catalogInfo.nlink !== 1n
      || (catalogInfo.mode & 0o777n) !== 0o600n
      || !serverInfo.isFile()
      || serverInfo.isSymbolicLink()
      || serverInfo.nlink !== 1
      || (serverInfo.mode & 0o777) !== 0o600
      || catalogValue?.schemaVersion !== 1
      || catalogValue?.plans?.length !== 1
      || catalogValue.plans[0]?.reviewFingerprint !== state.activation.plan.reviewFingerprint
      || catalogValue.plans[0]?.wrapper?.maximumOutputBytes !== MCP_MAX_OUTPUT_BYTES
    ) compatibilityFailure("the live candidate changed its reviewed owner-only MCP activation inputs or output bound");
    result.catalogByteCount = catalogBytes.length;
    result.catalogSHA256 = createHash("sha256").update(catalogBytes).digest("hex");
    result.reviewFingerprint = state.activation.plan.reviewFingerprint;
  } catch (error) {
    primaryError = error;
  }

  try { await closeSocket(state.mux); } catch (error) { primaryError ??= error; }
  try { await closeSocket(state.host); } catch (error) { primaryError ??= error; }
  try { await stopExactChild(state.runtime?.child, "candidate DSH MCP host"); } catch (error) { primaryError ??= error; }
  if (result?.subprocesses) {
    try { await assertMCPProcessesStopped(result.subprocesses); } catch (error) { primaryError ??= error; }
  }
  try { await closeHarnessLog(state.runtime); } catch (error) { primaryError ??= error; }
  try { await stopExactChild(state.provider?.child, "MCP local provider fixture"); } catch (error) { primaryError ??= error; }

  if (primaryError) {
    const continuationDiagnostics = state.host?.frames?.filter((frame) =>
      JSON.stringify(frame).includes("Fulmar automatic-continuation diagnostic:")
    ) ?? [];
    if (continuationDiagnostics.length > 0) {
      process.stderr.write(`${JSON.stringify(continuationDiagnostics.slice(-32))}\n`);
    }
    if (typeof primaryError.canaryDiagnostics === "string" && primaryError.canaryDiagnostics.length > 0) {
      process.stderr.write(primaryError.canaryDiagnostics);
      if (!primaryError.canaryDiagnostics.endsWith("\n")) process.stderr.write("\n");
    }
    const stderr = state.runtime?.stderrPath
      ? await boundedText(state.runtime.stderrPath).catch(() => "")
      : "";
    if (stderr) process.stderr.write(stderr.slice(-16_384));
  }
  try { await removeStateRoot(state); } catch (error) { primaryError ??= error; }
  if (primaryError) throw primaryError;
  return result;
}

export async function runCandidateCanary(appDir) {
  const layout = canonicalCandidateLayout(appDir);
  await validateCandidate(layout);
  const sourceHome = process.env.HOME;
  if (typeof sourceHome !== "string" || !path.isAbsolute(sourceHome)) compatibilityFailure("the invoking HOME is unavailable for the source-state guard");
  const sourceDshHome = path.join(sourceHome, ".dsh");
  const beforeSource = await userDshSnapshot(sourceDshHome);
  const state = await prepareState();
  let primaryError;
  let summary;
  try {
    state.settingsExistedBeforeLaunch = (await lstat(path.join(state.dshHome, "settings.yaml")).catch(() => undefined)) !== undefined;
    const providerEnvironment = childEnvironment(state, layout);
    state.provider = await startProvider(layout, state.root, providerEnvironment);
    const environment = childEnvironment(state, layout);
    state.runtime = await startHarness(layout, state.root, environment, state.workspace, state);
    summary = await runTypedCompatibility(layout, state);
    await assertEphemeralArtifacts(state);
    summary.telemetryRecords = state.telemetryRecordCount;
  } catch (error) {
    primaryError = error;
  }

  try { await closeSocket(state.mux); } catch (error) { primaryError ??= error; }
  try { await closeSocket(state.host); } catch (error) { primaryError ??= error; }
  try { await stopExactChild(state.runtime?.child, "candidate DSH host"); } catch (error) { primaryError ??= error; }
  try { await closeHarnessLog(state.runtime); } catch (error) { primaryError ??= error; }
  try { await stopExactChild(state.provider?.child, "local provider fixture"); } catch (error) { primaryError ??= error; }

  if (!primaryError) {
    try {
      summary.resolverProbes = await runResolverAdversarialProbes(layout);
    } catch (error) {
      primaryError = error;
    }
  }

  if (!primaryError) {
    try {
      summary.mcp = await runCandidateMCPCanary(layout);
    } catch (error) {
      primaryError = error;
    }
  }

  if (primaryError) {
    const continuationDiagnostics = state.host?.frames?.filter((frame) =>
      JSON.stringify(frame).includes("Fulmar automatic-continuation diagnostic:")
    ) ?? [];
    if (continuationDiagnostics.length > 0) {
      process.stderr.write(`${JSON.stringify(continuationDiagnostics.slice(-32))}\n`);
    }
    if (typeof primaryError.canaryDiagnostics === "string" && primaryError.canaryDiagnostics.length > 0) {
      process.stderr.write(primaryError.canaryDiagnostics);
      if (!primaryError.canaryDiagnostics.endsWith("\n")) process.stderr.write("\n");
    }
    const stderr = state.runtime?.stderrPath
      ? await boundedText(state.runtime.stderrPath).catch(() => "")
      : "";
    if (stderr) process.stderr.write(stderr.slice(-16_384));
  }

  try {
    const afterSource = await userDshSnapshot(sourceDshHome);
    assertSameUserDsh(beforeSource, afterSource);
  } catch (error) {
    primaryError ??= error;
  }
  try { await removeStateRoot(state); } catch (error) { primaryError ??= error; }
  if (primaryError) throw primaryError;
  return summary;
}

async function main() {
  const [appDir] = process.argv.slice(2);
  if (!appDir || process.argv.length !== 3) {
    process.stderr.write("Usage: verify-dsh-web-rpc-canary.mjs <candidate.app>\n");
    process.exitCode = 64;
    return;
  }
  installSignalCleanup();
  const summary = await runCandidateCanary(path.resolve(appDir));
  process.stdout.write(
    `Candidate DSH web/RPC canary passed: ${summary.methods.length} typed methods, `
    + `${summary.muxFrames} mux frames, ${summary.hostFrames} host frames; `
    + `${summary.resolverProbes} adversarial plugin-resolution probes; `
    + `${summary.bridgeBehaviorChecks} signed client-bridge behavior proofs; `
    + `approved-page ${summary.approvedPageOutcome} path with exact URL disclosure and no web_search; `
    + `${summary.automaticContinuationTurns} automatic max-token continuation turns; `
    + `${summary.mcp.checks} candidate-host MCP proofs with ${summary.mcp.outputBytes}/${MCP_MAX_OUTPUT_BYTES} bounded result bytes `
    + `and exact shutdown of PIDs ${summary.mcp.subprocesses.guardPID}/${summary.mcp.subprocesses.serverPID}; `
    + `reviewed MCP catalog ${summary.mcp.catalogByteCount} bytes/SHA-256 ${summary.mcp.catalogSHA256}; `
    + `${summary.telemetryRecords + summary.mcp.telemetryRecords} exact content-free telemetry records across both private hosts; `
    + `clean upstream ${UPSTREAM_PROVIDER}/${UPSTREAM_MODEL} changed to exact `
    + `${EXPECTED_PROVIDER}/${EXPECTED_MODEL} before the first blank session; `
    + "bounded turn/cancel/fork/archive succeeded with no DeepSeek key, onboarding, cloud egress, or source ~/.dsh change.\n"
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
