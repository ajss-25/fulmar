import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, normalize, sep } from "node:path";
import {
  MAX_APPROVAL_ARGUMENT_BYTES,
  MAX_INVENTORY_BYTES,
  encodeGuardRunnerPlan,
  under
} from "./catalog-core.mjs";

const BASE_CHILD_ENVIRONMENT = Object.freeze(["HOME", "USER", "LOGNAME", "PATH", "LANG", "TMPDIR"]);
const MARKER_ENVIRONMENT = Object.freeze([
  "LOCAL_HARNESS_MCP_GUARD_CHILD",
  "LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS",
  "LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP",
  "LOCAL_HARNESS_MCP_GUARD_PLAN"
]);

class MCPToolApprovalError extends Error {
  constructor(message, code = "MCP_APPROVAL_REQUIRED") {
    super(message);
    this.name = "MCPToolApprovalError";
    this.code = code;
  }
}

function cleanEnvironmentValue(value, name, maximumBytes = 65_536) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || Buffer.byteLength(value, "utf8") > maximumBytes) {
    throw new Error(`mcp-guarded: environment value for ${name} is missing or unsafe`);
  }
  return value;
}

function canonicalPrivateDirectory(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value || value.includes("\0")) {
    throw new Error(`mcp-guarded: ${label} is not a normalized absolute path`);
  }
  const canonical = realpathSync(value);
  if (canonical !== value) throw new Error(`mcp-guarded: ${label} cannot contain symbolic links`);
  const metadata = lstatSync(canonical);
  const currentUID = process.getuid?.() ?? metadata.uid;
  if (!metadata.isDirectory() || metadata.uid !== currentUID || (metadata.mode & 0o077) !== 0) {
    throw new Error(`mcp-guarded: ${label} must be an owner-only directory`);
  }
  return canonical;
}

async function resolveCredentialEnvironment(ctx, plan, credentialRef) {
  if (!ctx?.credentials || typeof ctx.credentials.resolve !== "function") {
    throw new Error("mcp-guarded: the credential service is unavailable");
  }
  const environment = Object.create(null);
  for (const binding of plan.dsh.environment) {
    let resolved;
    try {
      resolved = await ctx.credentials.resolve(credentialRef(binding.credential));
    } catch {
      throw new Error(`mcp-guarded: credential reference ${binding.credential} could not be resolved`);
    }
    if (!resolved || typeof resolved.value !== "string") {
      throw new Error(`mcp-guarded: credential reference ${binding.credential} is not configured`);
    }
    environment[binding.variableName] = cleanEnvironmentValue(resolved.value, binding.variableName);
  }
  return Object.freeze(environment);
}

function strictBaseEnvironment(ambient) {
  const result = Object.create(null);
  for (const name of BASE_CHILD_ENVIRONMENT) {
    result[name] = cleanEnvironmentValue(ambient?.[name], name, 16_384);
  }
  if (!isAbsolute(result.HOME) || !isAbsolute(result.TMPDIR)) {
    throw new Error("mcp-guarded: HOME and TMPDIR must be absolute paths");
  }
  return result;
}

function buildGuardChildEnvironment({ plan, credentials, sandboxTemp, ambient = process.env }) {
  const environment = strictBaseEnvironment(ambient);
  const privateTemp = canonicalPrivateDirectory(sandboxTemp, "sandbox temp root");
  environment.LOCAL_HARNESS_MCP_GUARD_CHILD = "1";
  environment.LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS = JSON.stringify([plan.project.canonicalPath]);
  environment.LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP = privateTemp;
  environment.LOCAL_HARNESS_MCP_GUARD_PLAN = encodeGuardRunnerPlan(plan);
  for (const binding of plan.dsh.environment) {
    if (!Object.hasOwn(credentials, binding.variableName)) {
      throw new Error(`mcp-guarded: resolved credential ${binding.variableName} is missing`);
    }
    environment[binding.variableName] = cleanEnvironmentValue(credentials[binding.variableName], binding.variableName);
  }
  return environment;
}

function buildStrictServerEnvironment(ambient, credentialVariables) {
  const environment = strictBaseEnvironment(ambient);
  for (const variableName of credentialVariables) {
    if (BASE_CHILD_ENVIRONMENT.includes(variableName) || MARKER_ENVIRONMENT.includes(variableName) || variableName.startsWith("LOCAL_HARNESS_")) {
      throw new Error(`mcp-guarded: credential variable ${variableName} collides with guard metadata`);
    }
    environment[variableName] = cleanEnvironmentValue(ambient?.[variableName], variableName);
  }
  return environment;
}

function approvalArguments(argumentsValue) {
  let serialized;
  try {
    serialized = JSON.stringify(argumentsValue);
  } catch {
    throw new MCPToolApprovalError("The MCP call arguments could not be rendered safely for approval.", "MCP_ARGUMENTS_INVALID");
  }
  if (serialized === undefined) serialized = "null";
  if (Buffer.byteLength(serialized, "utf8") > MAX_APPROVAL_ARGUMENT_BYTES) {
    throw new MCPToolApprovalError(
      "The MCP call arguments exceed the size that Fulmar can show in full for approval.",
      "MCP_ARGUMENTS_TOO_LARGE"
    );
  }
  return serialized;
}

function activeProvider(agent) {
  let requestProvider;
  try {
    requestProvider = agent?.session?.requestHeader?.()?.config?.provider;
  } catch {
    return undefined;
  }
  return requestProvider ?? agent?.options?.provider;
}

function canonicalExecutionDirectory(agent) {
  const cwd = agent?.session?.header?.cwd;
  if (typeof cwd !== "string" || !isAbsolute(cwd) || cwd.includes("\0")) return undefined;
  try {
    return realpathSync(cwd);
  } catch {
    return undefined;
  }
}

function assertExecutionBinding(plan, exec) {
  if (!exec?.agent) throw new MCPToolApprovalError("Local MCP tools require an active conversation.");
  if (typeof exec.callId !== "string" || exec.callId.length === 0 || Buffer.byteLength(exec.callId, "utf8") > 256) {
    throw new MCPToolApprovalError("Local MCP tools require a valid, visible tool-call identity.");
  }
  const provider = activeProvider(exec.agent);
  if (provider !== plan.disclosure.modelProvider) {
    throw new MCPToolApprovalError("This MCP server was not approved for the model provider used by this turn.", "MCP_PROVIDER_NOT_APPROVED");
  }
  const cwd = canonicalExecutionDirectory(exec.agent);
  if (cwd === undefined || !under(cwd, plan.project.canonicalPath)) {
    throw new MCPToolApprovalError("This MCP server was not approved for the project used by this conversation.", "MCP_PROJECT_NOT_APPROVED");
  }
  const projectMetadata = lstatSync(plan.project.canonicalPath);
  const currentUID = process.getuid?.() ?? projectMetadata.uid;
  if (!projectMetadata.isDirectory()
    || projectMetadata.uid !== currentUID
    || projectMetadata.dev !== plan.project.deviceID
    || projectMetadata.ino !== plan.project.inode
    || (projectMetadata.mode & 0o022) !== 0) {
    throw new MCPToolApprovalError("The approved project identity changed; MCP trust must be reviewed again.", "MCP_TRUST_REVOKED");
  }
  if (exec.signal?.aborted) throw new MCPToolApprovalError("The MCP tool call was cancelled.", "MCP_APPROVAL_CANCELLED");
}

function definitionInventoryBytes(definition) {
  let serialized;
  try {
    serialized = JSON.stringify({
      name: definition.name,
      description: definition.description,
      parameters: definition.parameters,
      output: definition.output?.schema
    });
  } catch {
    throw new Error("mcp-guarded: an MCP tool advertised an unserializable schema");
  }
  const bytes = Buffer.byteLength(serialized ?? "", "utf8");
  if (bytes === 0 || bytes > MAX_INVENTORY_BYTES) {
    throw new Error("mcp-guarded: an MCP tool advertised an oversized schema");
  }
  return bytes;
}

function wrapDefinition(ctx, plan, definition) {
  if (!definition || typeof definition !== "object" || typeof definition.execute !== "function") {
    throw new Error("mcp-guarded: the bundled MCP bridge registered an invalid tool definition");
  }
  const expectedPrefix = `mcp__${plan.dsh.serverName}__`;
  if (typeof definition.name !== "string" || !definition.name.startsWith(expectedPrefix)) {
    throw new Error("mcp-guarded: the bundled MCP bridge attempted to escape its reviewed tool namespace");
  }
  const execute = definition.execute;
  return {
    ...definition,
    timeoutMs: Math.min(
      Number.isFinite(definition.timeoutMs) && definition.timeoutMs > 0
        ? definition.timeoutMs
        : plan.dsh.toolCallTimeoutMilliseconds,
      plan.dsh.toolCallTimeoutMilliseconds
    ),
    async execute(argumentsValue, exec) {
      assertExecutionBinding(plan, exec);
      const visibleArguments = approvalArguments(argumentsValue);
      if (!ctx?.approval || typeof ctx.approval.request !== "function") {
        throw new MCPToolApprovalError("The native approval service is unavailable.");
      }
      let outcome;
      try {
        outcome = await ctx.approval.request({
          agent: exec.agent,
          toolName: definition.name,
          callId: exec.callId,
          reason: [
            `Run approved local MCP tool “${definition.name}”?`,
            `Project: ${plan.project.canonicalPath}`,
            `Model provider: ${plan.disclosure.modelProvider} (${plan.disclosure.modelBoundary})`,
            `Arguments (exact JSON): ${visibleArguments}`
          ].join("\n"),
          signal: exec.signal
        });
      } catch {
        throw new MCPToolApprovalError("The MCP tool call could not obtain a recorded native approval.");
      }
      if (outcome !== "allowed-once") {
        throw new MCPToolApprovalError("The MCP tool call was not approved.", outcome === "cancelled" ? "MCP_APPROVAL_CANCELLED" : "MCP_APPROVAL_DENIED");
      }
      if (exec.signal?.aborted) throw new MCPToolApprovalError("The MCP tool call was cancelled.", "MCP_APPROVAL_CANCELLED");
      return Reflect.apply(execute, definition, [argumentsValue, exec]);
    }
  };
}

function boundProperty(target, property) {
  const value = Reflect.get(target, property, target);
  return typeof value === "function" ? value.bind(target) : value;
}

function createGuardedContext(ctx, plan) {
  if (!ctx?.tools || typeof ctx.tools.register !== "function") {
    throw new Error("mcp-guarded: the tool runtime is unavailable");
  }
  let liveToolCount = 0;
  let liveInventoryBytes = 0;
  const tools = new Proxy(ctx.tools, {
    get(target, property) {
      if (property !== "register") return boundProperty(target, property);
      return (definition) => {
        if (liveToolCount >= plan.wrapper.maximumDiscoveredTools) {
          throw new Error(`mcp-guarded: ${plan.dsh.serverName} exceeded its approved tool-count limit`);
        }
        const bytes = definitionInventoryBytes(definition);
        if (liveInventoryBytes + bytes > MAX_INVENTORY_BYTES) {
          throw new Error(`mcp-guarded: ${plan.dsh.serverName} exceeded its tool-schema size limit`);
        }
        const guarded = wrapDefinition(ctx, plan, definition);
        const disposeOriginal = target.register(guarded);
        liveToolCount += 1;
        liveInventoryBytes += bytes;
        let disposed = false;
        return () => {
          if (disposed) return;
          disposed = true;
          try {
            disposeOriginal();
          } finally {
            liveToolCount -= 1;
            liveInventoryBytes -= bytes;
          }
        };
      };
    }
  });
  return new Proxy(ctx, {
    get(target, property) {
      if (property === "tools") return tools;
      return boundProperty(target, property);
    }
  });
}

export {
  BASE_CHILD_ENVIRONMENT,
  MARKER_ENVIRONMENT,
  MCPToolApprovalError,
  approvalArguments,
  assertExecutionBinding,
  buildGuardChildEnvironment,
  buildStrictServerEnvironment,
  createGuardedContext,
  resolveCredentialEnvironment,
  wrapDefinition
};
