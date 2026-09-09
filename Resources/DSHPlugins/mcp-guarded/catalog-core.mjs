import {
  accessSync,
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync
} from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, normalize, resolve, sep } from "node:path";

const CATALOG_SCHEMA_VERSION = 1;
const GUARD_PLAN_SCHEMA_VERSION = 1;
const MAX_CATALOG_BYTES = 2 * 1024 * 1024;
const MAX_PLANS = 16;
const MAX_TOTAL_DISCOVERED_TOOLS = 256;
const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const MAX_REVIEWED_FILE_BYTES = 256 * 1024 * 1024;
const MAX_INVENTORY_BYTES = 1024 * 1024;
const MAX_APPROVAL_ARGUMENT_BYTES = 64 * 1024;
const PINNED_MCP_PACKAGE = "@deepseek-ai/dsh-mcp-client";
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const SERVER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SERVER_NAME_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const ENVIRONMENT_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const CREDENTIAL_PATTERN = /^[A-Z][A-Z0-9_]{0,95}$/;
const PROVIDER_PATTERN = /^[^\0\r\n]{1,128}$/;
const DATA_BOUNDARIES = new Set(["onDevice", "localNetwork", "cloud"]);
const DISCLOSURE_DATA_KINDS = new Set([
  "accountData",
  "authenticationMetadata",
  "fileContents",
  "fileNames",
  "projectMetadata",
  "toolArguments",
  "toolResults"
]);
const FORBIDDEN_ENVIRONMENT = new Set([
  "BASH_ENV",
  "ENV",
  "HOME",
  "IFS",
  "LANG",
  "LOGNAME",
  "NODE_OPTIONS",
  "PATH",
  "PERL5OPT",
  "PYTHONHOME",
  "PYTHONPATH",
  "RUBYOPT",
  "SHELL",
  "TMPDIR",
  "USER",
  "ZDOTDIR"
]);
const FORBIDDEN_EXECUTABLES = new Set([
  "ash", "bash", "csh", "cmd", "cmd.exe", "dash", "env", "fish", "ksh",
  "powershell", "powershell.exe", "pwsh", "sh", "tcsh", "zsh"
]);
const RUNTIME_EXECUTABLES = new Set([
  "node", "nodejs", "deno", "bun", "java", "ruby", "perl"
]);
const REVIEWED_CODE_EXTENSIONS = new Set(["js", "mjs", "cjs", "ts", "py", "rb", "pl", "jar"]);
const SENSITIVE_ARGUMENT = /^--?(?:api[-_]?key|password|secret|token|access[-_]?token)(?:=|$)/i;

class MCPGuardConfigurationError extends Error {
  constructor(message) {
    super(`mcp-guarded: ${message}`);
    this.name = "MCPGuardConfigurationError";
    this.code = "MCP_GUARD_CONFIGURATION";
  }
}

function fail(message) {
  throw new MCPGuardConfigurationError(message);
}

function isRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function record(value, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  return value;
}

function exactKeys(value, required, optional, label) {
  const object = record(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) fail(`${label}.${key} is not an approved field`);
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) fail(`${label}.${key} is required`);
  }
  return object;
}

function stringValue(value, label, { min = 0, max = Number.MAX_SAFE_INTEGER, pattern } = {}) {
  if (typeof value !== "string") fail(`${label} must be a string`);
  const length = Buffer.byteLength(value, "utf8");
  if (length < min || length > max || value.includes("\0")) fail(`${label} has an invalid length or contains NUL`);
  if (pattern && !pattern.test(value)) fail(`${label} has an invalid value`);
  return value;
}

function integerValue(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} is outside the approved range`);
  }
  return value;
}

function booleanValue(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be a boolean`);
  return value;
}

function absolutePath(value, label) {
  const path = stringValue(value, label, { min: 1, max: 4096 });
  if (!isAbsolute(path) || normalize(path) !== path || path.includes("\n") || path.includes("\r")) {
    fail(`${label} must be a normalized absolute path`);
  }
  return path;
}

function sha256(value, label) {
  return stringValue(value, label, { min: 64, max: 64, pattern: SHA256_PATTERN });
}

function arrayValue(value, label, maximum) {
  if (!Array.isArray(value) || value.length > maximum) fail(`${label} must be a bounded array`);
  return value;
}

function uniqueStrings(values, label) {
  if (new Set(values).size !== values.length) fail(`${label} contains duplicates`);
}

function under(path, root) {
  return path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

function permissionValue(value, label) {
  return integerValue(value, label, 0, 0o7777);
}

function ownerValue(value, label, currentUID, rootAllowed = true) {
  const owner = integerValue(value, label, 0, 0xffffffff);
  if (owner !== currentUID && !(rootAllowed && owner === 0)) fail(`${label} is not owned by the current user or root`);
  return owner;
}

function validateExecutableAudit(value, currentUID) {
  const object = exactKeys(value, [
    "declaredPath", "canonicalPath", "contentSHA256", "byteCount", "ownerUID", "permissions", "fingerprint"
  ], ["interpreterCanonicalPath", "interpreterContentSHA256"], "plan.executable");
  const declaredPath = absolutePath(object.declaredPath, "plan.executable.declaredPath");
  const canonicalPath = absolutePath(object.canonicalPath, "plan.executable.canonicalPath");
  const contentSHA256 = sha256(object.contentSHA256, "plan.executable.contentSHA256");
  const byteCount = integerValue(object.byteCount, "plan.executable.byteCount", 0, MAX_EXECUTABLE_BYTES);
  const ownerUID = ownerValue(object.ownerUID, "plan.executable.ownerUID", currentUID);
  const permissions = permissionValue(object.permissions, "plan.executable.permissions");
  const fingerprint = sha256(object.fingerprint, "plan.executable.fingerprint");
  const interpreterCanonicalPath = object.interpreterCanonicalPath === undefined
    ? undefined
    : absolutePath(object.interpreterCanonicalPath, "plan.executable.interpreterCanonicalPath");
  const interpreterContentSHA256 = object.interpreterContentSHA256 === undefined
    ? undefined
    : sha256(object.interpreterContentSHA256, "plan.executable.interpreterContentSHA256");
  if ((interpreterCanonicalPath === undefined) !== (interpreterContentSHA256 === undefined)) {
    fail("plan.executable interpreter path and digest must either both be present or both be absent");
  }
  if (FORBIDDEN_EXECUTABLES.has(basename(canonicalPath).toLowerCase())) {
    fail("plan.executable cannot be a shell or environment launcher");
  }
  if ((permissions & 0o6022) !== 0) fail("plan.executable permissions are unsafe");
  if ((permissions & 0o111) === 0) fail("plan.executable is not executable");
  return {
    declaredPath,
    canonicalPath,
    contentSHA256,
    byteCount,
    ownerUID,
    permissions,
    ...(interpreterCanonicalPath === undefined ? {} : { interpreterCanonicalPath, interpreterContentSHA256 }),
    fingerprint
  };
}

function validateReviewedArgumentFile(value, currentUID, label) {
  const object = exactKeys(value, [
    "argumentIndex", "declaredPath", "canonicalPath", "contentSHA256", "byteCount", "ownerUID", "permissions"
  ], [], label);
  const permissions = permissionValue(object.permissions, `${label}.permissions`);
  if ((permissions & 0o6022) !== 0) fail(`${label}.permissions are unsafe`);
  return {
    argumentIndex: integerValue(object.argumentIndex, `${label}.argumentIndex`, 0, 63),
    declaredPath: absolutePath(object.declaredPath, `${label}.declaredPath`),
    canonicalPath: absolutePath(object.canonicalPath, `${label}.canonicalPath`),
    contentSHA256: sha256(object.contentSHA256, `${label}.contentSHA256`),
    byteCount: integerValue(object.byteCount, `${label}.byteCount`, 0, MAX_REVIEWED_FILE_BYTES),
    ownerUID: ownerValue(object.ownerUID, `${label}.ownerUID`, currentUID),
    permissions
  };
}

function validateProject(value, currentUID) {
  const object = exactKeys(value, ["canonicalPath", "ownerUID", "deviceID", "inode", "fingerprint"], [], "plan.project");
  return {
    canonicalPath: absolutePath(object.canonicalPath, "plan.project.canonicalPath"),
    ownerUID: ownerValue(object.ownerUID, "plan.project.ownerUID", currentUID, false),
    deviceID: integerValue(object.deviceID, "plan.project.deviceID", 0, Number.MAX_SAFE_INTEGER),
    inode: integerValue(object.inode, "plan.project.inode", 1, Number.MAX_SAFE_INTEGER),
    fingerprint: sha256(object.fingerprint, "plan.project.fingerprint")
  };
}

function validateEnvironment(value) {
  const entries = arrayValue(value, "plan.dsh.environment", 12).map((entry, index) => {
    const label = `plan.dsh.environment[${index}]`;
    const object = exactKeys(entry, ["variableName", "credential"], [], label);
    const variableName = stringValue(object.variableName, `${label}.variableName`, { min: 1, max: 64, pattern: ENVIRONMENT_PATTERN });
    const credential = stringValue(object.credential, `${label}.credential`, { min: 1, max: 96, pattern: CREDENTIAL_PATTERN });
    if (FORBIDDEN_ENVIRONMENT.has(variableName)
      || variableName.startsWith("DSH_")
      || variableName.startsWith("DYLD_")
      || variableName.startsWith("LD_")
      || variableName.startsWith("LOCAL_HARNESS_")) {
      fail(`${label}.variableName is not allowed`);
    }
    return { variableName, credential };
  });
  uniqueStrings(entries.map((entry) => entry.variableName), "plan.dsh.environment variable names");
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1].variableName >= entries[index].variableName) {
      fail("plan.dsh.environment must use the native canonical ordering");
    }
  }
  return entries;
}

function validateReconnect(value) {
  const object = exactKeys(value, [
    "enabled", "initialDelayMilliseconds", "maximumDelayMilliseconds", "maximumAttempts"
  ], [], "plan.dsh.reconnect");
  const initialDelayMilliseconds = integerValue(
    object.initialDelayMilliseconds,
    "plan.dsh.reconnect.initialDelayMilliseconds",
    100,
    60_000
  );
  const maximumDelayMilliseconds = integerValue(
    object.maximumDelayMilliseconds,
    "plan.dsh.reconnect.maximumDelayMilliseconds",
    initialDelayMilliseconds,
    120_000
  );
  return {
    enabled: booleanValue(object.enabled, "plan.dsh.reconnect.enabled"),
    initialDelayMilliseconds,
    maximumDelayMilliseconds,
    maximumAttempts: integerValue(object.maximumAttempts, "plan.dsh.reconnect.maximumAttempts", 1, 20)
  };
}

function validateDSHPlan(value, executable, project) {
  const object = exactKeys(value, [
    "pluginID",
    "packageName",
    "transport",
    "serverName",
    "command",
    "arguments",
    "environment",
    "workingDirectory",
    "toolCallTimeoutMilliseconds",
    "failOnStartupError",
    "reconnect"
  ], [], "plan.dsh");
  const serverName = stringValue(object.serverName, "plan.dsh.serverName", { min: 1, max: 32, pattern: SERVER_NAME_PATTERN });
  const pluginID = stringValue(object.pluginID, "plan.dsh.pluginID", { min: 1, max: 68 });
  if (pluginID !== `mcp-${serverName}`) fail("plan.dsh.pluginID does not match its reviewed server namespace");
  if (object.packageName !== PINNED_MCP_PACKAGE) fail("plan.dsh.packageName is not the pinned bundled MCP bridge");
  if (object.transport !== "stdio") fail("plan.dsh.transport must be stdio");
  const command = absolutePath(object.command, "plan.dsh.command");
  if (command !== executable.canonicalPath) fail("plan.dsh.command does not match the reviewed executable");
  const argumentsValue = arrayValue(object.arguments, "plan.dsh.arguments", 64);
  let argumentBytes = 0;
  const argumentsList = argumentsValue.map((argument, index) => {
    const item = stringValue(argument, `plan.dsh.arguments[${index}]`, { max: 4096 });
    if (item.includes("\n") || item.includes("\r") || SENSITIVE_ARGUMENT.test(item)) {
      fail(`plan.dsh.arguments[${index}] is unsafe or credential-shaped`);
    }
    argumentBytes += Buffer.byteLength(item, "utf8");
    return item;
  });
  if (argumentBytes > 16_384) fail("plan.dsh.arguments exceeds the approved aggregate size");
  const workingDirectory = absolutePath(object.workingDirectory, "plan.dsh.workingDirectory");
  if (!under(workingDirectory, project.canonicalPath)) fail("plan.dsh.workingDirectory escapes the approved project");
  if (object.failOnStartupError !== true) fail("plan.dsh.failOnStartupError must remain enabled");
  return {
    pluginID,
    packageName: PINNED_MCP_PACKAGE,
    transport: "stdio",
    serverName,
    command,
    arguments: argumentsList,
    environment: validateEnvironment(object.environment),
    workingDirectory,
    toolCallTimeoutMilliseconds: integerValue(
      object.toolCallTimeoutMilliseconds,
      "plan.dsh.toolCallTimeoutMilliseconds",
      1_000,
      120_000
    ),
    failOnStartupError: true,
    reconnect: validateReconnect(object.reconnect)
  };
}

function validateWrapper(value) {
  const object = exactKeys(value, [
    "startupTimeoutMilliseconds", "maximumDiscoveredTools", "maximumOutputBytes", "inheritAmbientEnvironment"
  ], [], "plan.wrapper");
  if (object.inheritAmbientEnvironment !== false) fail("plan.wrapper.inheritAmbientEnvironment must remain false");
  return {
    startupTimeoutMilliseconds: integerValue(
      object.startupTimeoutMilliseconds,
      "plan.wrapper.startupTimeoutMilliseconds",
      1_000,
      60_000
    ),
    maximumDiscoveredTools: integerValue(object.maximumDiscoveredTools, "plan.wrapper.maximumDiscoveredTools", 1, 128),
    maximumOutputBytes: integerValue(object.maximumOutputBytes, "plan.wrapper.maximumOutputBytes", 1_024, 4 * 1024 * 1024),
    inheritAmbientEnvironment: false
  };
}

function validateMCPDisclosure(value) {
  const object = exactKeys(value, ["boundary", "dataKinds"], ["destinationName"], "plan.disclosure.mcpServer");
  if (object.boundary !== "onDevice") {
    fail("network or cloud MCP servers are not supported by the local stdio guard");
  }
  if (object.destinationName !== undefined && object.destinationName !== null && object.destinationName !== "") {
    fail("an on-device MCP server cannot declare an external destination");
  }
  const dataKinds = arrayValue(object.dataKinds, "plan.disclosure.mcpServer.dataKinds", DISCLOSURE_DATA_KINDS.size)
    .map((kind, index) => {
      const result = stringValue(kind, `plan.disclosure.mcpServer.dataKinds[${index}]`, { min: 1, max: 64 });
      if (!DISCLOSURE_DATA_KINDS.has(result)) fail(`plan.disclosure.mcpServer.dataKinds[${index}] is unknown`);
      return result;
    });
  if (dataKinds.length === 0) fail("plan.disclosure.mcpServer.dataKinds cannot be empty");
  uniqueStrings(dataKinds, "plan.disclosure.mcpServer.dataKinds");
  return { boundary: "onDevice", dataKinds };
}

function validateDisclosure(value) {
  const object = exactKeys(value, ["mcpServer", "modelProvider", "modelBoundary"], [], "plan.disclosure");
  const modelProvider = stringValue(object.modelProvider, "plan.disclosure.modelProvider", {
    min: 1,
    max: 128,
    pattern: PROVIDER_PATTERN
  });
  if (!DATA_BOUNDARIES.has(object.modelBoundary)) fail("plan.disclosure.modelBoundary is unknown");
  return {
    mcpServer: validateMCPDisclosure(object.mcpServer),
    modelProvider,
    modelBoundary: object.modelBoundary
  };
}

function validateRuntimeShape(dsh, reviewedFiles) {
  const reviewedIndexes = new Set(reviewedFiles.map((file) => file.argumentIndex));
  const executableName = basename(dsh.command).toLowerCase();
  const runtime = RUNTIME_EXECUTABLES.has(executableName) || executableName.startsWith("python");
  if (runtime && reviewedFiles.length === 0) fail("runtime-based MCP servers require a fingerprinted entry point");
  const forbiddenInline = executableName === "node" || executableName === "nodejs"
    ? new Set(["-e", "--eval", "-p", "--print"])
    : executableName.startsWith("python")
      ? new Set(["-c"])
      : executableName === "ruby" || executableName === "perl"
        ? new Set(["-e"])
        : new Set();
  if (dsh.arguments.some((argument) => forbiddenInline.has(argument))) fail("inline runtime source is not allowed");
  for (const [index, argument] of dsh.arguments.entries()) {
    const extension = basename(argument).toLowerCase().split(".").at(-1);
    if (REVIEWED_CODE_EXTENSIONS.has(extension)) {
      if (!isAbsolute(argument)) fail(`plan.dsh.arguments[${index}] is relative executable content`);
      if (!reviewedIndexes.has(index)) {
        fail(`plan.dsh.arguments[${index}] is executable content but has no reviewed fingerprint`);
      }
    }
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validateActivationPlan(value, { currentUID = process.getuid?.() ?? 0 } = {}) {
  const object = exactKeys(value, [
    "serverID",
    "reviewFingerprint",
    "executable",
    "reviewedArgumentFiles",
    "project",
    "dsh",
    "wrapper",
    "disclosure"
  ], [], "plan");
  const serverID = stringValue(object.serverID, "plan.serverID", { min: 1, max: 64, pattern: SERVER_ID_PATTERN });
  const reviewFingerprint = sha256(object.reviewFingerprint, "plan.reviewFingerprint");
  const executable = validateExecutableAudit(object.executable, currentUID);
  const project = validateProject(object.project, currentUID);
  const reviewedArgumentFiles = arrayValue(object.reviewedArgumentFiles, "plan.reviewedArgumentFiles", 16)
    .map((file, index) => validateReviewedArgumentFile(file, currentUID, `plan.reviewedArgumentFiles[${index}]`));
  uniqueStrings(reviewedArgumentFiles.map((file) => String(file.argumentIndex)), "plan.reviewedArgumentFiles argument indexes");
  const dsh = validateDSHPlan(object.dsh, executable, project);
  for (const file of reviewedArgumentFiles) {
    if (file.argumentIndex >= dsh.arguments.length || dsh.arguments[file.argumentIndex] !== file.declaredPath) {
      fail(`plan.reviewedArgumentFiles index ${file.argumentIndex} does not bind the reviewed argv entry`);
    }
  }
  validateRuntimeShape(dsh, reviewedArgumentFiles);
  const wrapper = validateWrapper(object.wrapper);
  if (wrapper.maximumOutputBytes + 65_536 > 10 * 1024 * 1024) {
    fail("plan.wrapper.maximumOutputBytes exceeds the bundled MCP framing safety budget");
  }
  const disclosure = validateDisclosure(object.disclosure);
  if (dsh.environment.length > 0 && !disclosure.mcpServer.dataKinds.includes("authenticationMetadata")) {
    fail("credential-bearing MCP servers must disclose authentication metadata");
  }
  return deepFreeze({
    serverID,
    reviewFingerprint,
    executable,
    reviewedArgumentFiles,
    project,
    dsh,
    wrapper,
    disclosure
  });
}

function validateCatalogValue(value, options = {}) {
  const object = exactKeys(value, ["schemaVersion", "plans"], [], "catalog");
  if (object.schemaVersion !== CATALOG_SCHEMA_VERSION) fail("catalog.schemaVersion is unsupported");
  const plans = arrayValue(object.plans, "catalog.plans", MAX_PLANS)
    .map((plan) => validateActivationPlan(plan, options));
  if (plans.reduce((total, plan) => total + plan.wrapper.maximumDiscoveredTools, 0) > MAX_TOTAL_DISCOVERED_TOOLS) {
    fail("catalog aggregate tool-count budget is too large");
  }
  for (const [field, values] of [
    ["server IDs", plans.map((plan) => plan.serverID)],
    ["server names", plans.map((plan) => plan.dsh.serverName)],
    ["plugin IDs", plans.map((plan) => plan.dsh.pluginID)]
  ]) uniqueStrings(values, `catalog ${field}`);
  return deepFreeze({ schemaVersion: CATALOG_SCHEMA_VERSION, plans });
}

function bigintStat(path, follow = false) {
  return (follow ? statSync : lstatSync)(path, { bigint: true });
}

function isDirectory(stat) {
  return (stat.mode & 0o170000n) === 0o040000n;
}

function isRegularFile(stat) {
  return (stat.mode & 0o170000n) === 0o100000n;
}

function isSymbolicLink(stat) {
  return (stat.mode & 0o170000n) === 0o120000n;
}

function safeOwner(stat, currentUID, rootAllowed = true) {
  return stat.uid === BigInt(currentUID) || (rootAllowed && stat.uid === 0n);
}

function safeDirectoryMode(stat) {
  const writableByOthers = (stat.mode & 0o022n) !== 0n;
  const rootOwnedSticky = stat.uid === 0n && (stat.mode & 0o1000n) !== 0n;
  return !writableByOthers || rootOwnedSticky;
}

function pathComponents(path) {
  const normalized = normalize(path);
  const components = normalized.split(sep).filter(Boolean);
  const result = [];
  let current = sep;
  for (const component of components) {
    current = current === sep ? `${sep}${component}` : `${current}${sep}${component}`;
    result.push(current);
  }
  return result;
}

function validateDeclaredChain(path, currentUID, { finalMayBeSymlink = true } = {}) {
  const components = pathComponents(path);
  for (const [index, component] of components.entries()) {
    const metadata = bigintStat(component);
    if (!safeOwner(metadata, currentUID)) fail(`unsafe owner in reviewed path ${component}`);
    const final = index === components.length - 1;
    if (isDirectory(metadata)) {
      if (!safeDirectoryMode(metadata)) fail(`unsafe writable directory in reviewed path ${component}`);
    } else if (isSymbolicLink(metadata)) {
      if (final && !finalMayBeSymlink) fail(`symbolic link is not allowed at ${component}`);
    } else if (!final) {
      fail(`non-directory component in reviewed path ${component}`);
    }
  }
}

function validateCanonicalParents(path, currentUID) {
  const parent = dirname(path);
  for (const component of pathComponents(parent)) {
    const metadata = bigintStat(component);
    if (!isDirectory(metadata) || !safeOwner(metadata, currentUID) || !safeDirectoryMode(metadata)) {
      fail(`unsafe canonical parent ${component}`);
    }
  }
}

function sameSnapshot(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function snapshotFile(path, {
  currentUID,
  maximumBytes,
  executable = false,
  expectedOwner,
  expectedPermissions
}) {
  validateCanonicalParents(path, currentUID);
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!isRegularFile(before) || !safeOwner(before, currentUID)) fail(`reviewed file is unsafe: ${path}`);
    if ((before.mode & 0o6022n) !== 0n || before.size < 0n || before.size > BigInt(maximumBytes)) {
      fail(`reviewed file has unsafe permissions or size: ${path}`);
    }
    if (executable && (before.mode & 0o111n) === 0n) fail(`reviewed executable is not executable: ${path}`);
    if (expectedOwner !== undefined && before.uid !== BigInt(expectedOwner)) fail(`reviewed file owner changed: ${path}`);
    const permissions = Number(before.mode & 0o7777n);
    if (expectedPermissions !== undefined && permissions !== expectedPermissions) fail(`reviewed file permissions changed: ${path}`);
    const hasher = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    while (true) {
      const count = readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      total += count;
      if (total > maximumBytes) fail(`reviewed file grew beyond its size limit: ${path}`);
      hasher.update(buffer.subarray(0, count));
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameSnapshot(before, after) || BigInt(total) !== before.size) fail(`reviewed file changed while it was verified: ${path}`);
    return {
      digest: hasher.digest("hex"),
      byteCount: total,
      ownerUID: Number(before.uid),
      permissions
    };
  } finally {
    closeSync(descriptor);
  }
}

function appendFingerprintField(hasher, value) {
  const bytes = Buffer.from(String(value), "utf8");
  const length = Buffer.allocUnsafe(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hasher.update(length);
  hasher.update(bytes);
}

function executableFingerprint(audit) {
  const hasher = createHash("sha256");
  for (const value of [
    "local-harness-mcp-executable-v1",
    audit.canonicalPath,
    audit.contentSHA256,
    audit.byteCount,
    audit.ownerUID,
    audit.permissions,
    audit.interpreterCanonicalPath ?? "",
    audit.interpreterContentSHA256 ?? ""
  ]) appendFingerprintField(hasher, value);
  return hasher.digest("hex");
}

function unsignedDecimal(value) {
  return BigInt.asUintN(64, value).toString(10);
}

function projectFingerprint(project) {
  const hasher = createHash("sha256");
  for (const value of [
    "local-harness-mcp-project-v1",
    project.canonicalPath,
    project.deviceID,
    project.inode,
    project.ownerUID
  ]) appendFingerprintField(hasher, value);
  return hasher.digest("hex");
}

function revalidateProject(project, currentUID) {
  validateDeclaredChain(project.canonicalPath, currentUID, { finalMayBeSymlink: false });
  const canonical = realpathSync(project.canonicalPath);
  if (canonical !== project.canonicalPath) fail("the approved project path now resolves somewhere else");
  const metadata = bigintStat(canonical);
  if (!isDirectory(metadata)
    || metadata.uid !== BigInt(currentUID)
    || (metadata.mode & 0o022n) !== 0n
    || Number(metadata.dev) !== project.deviceID
    || Number(metadata.ino) !== project.inode) {
    fail("the approved project identity or permissions changed");
  }
  const current = {
    canonicalPath: canonical,
    ownerUID: Number(metadata.uid),
    deviceID: unsignedDecimal(metadata.dev),
    inode: unsignedDecimal(metadata.ino)
  };
  const expected = {
    ...current,
    deviceID: String(project.deviceID),
    inode: String(project.inode)
  };
  if (projectFingerprint(expected) !== project.fingerprint) fail("the approved project fingerprint changed");
}

function revalidateWorkingDirectory(plan, currentUID) {
  const path = plan.dsh.workingDirectory;
  validateDeclaredChain(path, currentUID, { finalMayBeSymlink: false });
  const canonical = realpathSync(path);
  if (canonical !== path || !under(canonical, plan.project.canonicalPath)) {
    fail("the MCP working directory no longer belongs to its approved project");
  }
  const metadata = bigintStat(canonical);
  if (!isDirectory(metadata) || !safeOwner(metadata, currentUID) || (metadata.mode & 0o022n) !== 0n) {
    fail("the MCP working directory permissions are unsafe");
  }
}

function revalidateExecutable(executable, currentUID) {
  validateDeclaredChain(executable.declaredPath, currentUID);
  const canonical = realpathSync(executable.declaredPath);
  if (canonical !== executable.canonicalPath) fail("the reviewed MCP executable target changed");
  const snapshot = snapshotFile(canonical, {
    currentUID,
    maximumBytes: MAX_EXECUTABLE_BYTES,
    executable: true,
    expectedOwner: executable.ownerUID,
    expectedPermissions: executable.permissions
  });
  accessSync(canonical, fsConstants.X_OK);
  if (snapshot.digest !== executable.contentSHA256 || snapshot.byteCount !== executable.byteCount) {
    fail("the reviewed MCP executable bytes changed");
  }
  let interpreterContentSHA256;
  if (executable.interpreterCanonicalPath !== undefined) {
    validateDeclaredChain(executable.interpreterCanonicalPath, currentUID);
    const interpreterCanonical = realpathSync(executable.interpreterCanonicalPath);
    if (interpreterCanonical !== executable.interpreterCanonicalPath) fail("the reviewed interpreter target changed");
    const interpreter = snapshotFile(interpreterCanonical, {
      currentUID,
      maximumBytes: MAX_EXECUTABLE_BYTES,
      executable: true
    });
    accessSync(interpreterCanonical, fsConstants.X_OK);
    interpreterContentSHA256 = interpreter.digest;
    if (interpreterContentSHA256 !== executable.interpreterContentSHA256) fail("the reviewed interpreter bytes changed");
  }
  const current = {
    ...executable,
    contentSHA256: snapshot.digest,
    byteCount: snapshot.byteCount,
    ownerUID: snapshot.ownerUID,
    permissions: snapshot.permissions,
    ...(interpreterContentSHA256 === undefined ? {} : { interpreterContentSHA256 })
  };
  if (executableFingerprint(current) !== executable.fingerprint) fail("the reviewed executable fingerprint changed");
}

function revalidateArgumentFile(file, currentUID) {
  validateDeclaredChain(file.declaredPath, currentUID);
  const canonical = realpathSync(file.declaredPath);
  if (canonical !== file.canonicalPath) fail(`reviewed argv file target changed at index ${file.argumentIndex}`);
  const snapshot = snapshotFile(canonical, {
    currentUID,
    maximumBytes: MAX_REVIEWED_FILE_BYTES,
    expectedOwner: file.ownerUID,
    expectedPermissions: file.permissions
  });
  if (snapshot.digest !== file.contentSHA256 || snapshot.byteCount !== file.byteCount) {
    fail(`reviewed argv file bytes changed at index ${file.argumentIndex}`);
  }
}

function revalidateActivationPlan(plan, { currentUID = process.getuid?.() ?? 0 } = {}) {
  revalidateProject(plan.project, currentUID);
  revalidateWorkingDirectory(plan, currentUID);
  revalidateExecutable(plan.executable, currentUID);
  for (const file of plan.reviewedArgumentFiles) revalidateArgumentFile(file, currentUID);
  return plan;
}

function revalidateGuardRunnerPlan(plan, { currentUID = process.getuid?.() ?? 0 } = {}) {
  revalidateProject(plan.project, currentUID);
  const activationShape = {
    project: plan.project,
    dsh: { workingDirectory: plan.workingDirectory }
  };
  revalidateWorkingDirectory(activationShape, currentUID);
  revalidateExecutable(plan.executable, currentUID);
  for (const file of plan.reviewedArgumentFiles) revalidateArgumentFile(file, currentUID);
  return plan;
}

function validateCatalogPath(path, currentUID) {
  const declared = absolutePath(path, "catalogPath");
  if (resolve(declared) !== declared) fail("catalogPath is not normalized");
  const parent = dirname(declared);
  validateDeclaredChain(parent, currentUID, { finalMayBeSymlink: false });
  const canonicalParent = realpathSync(parent);
  if (canonicalParent !== parent) fail("catalogPath parent cannot contain symbolic links");
  const parentMetadata = bigintStat(parent);
  if (!isDirectory(parentMetadata)
    || parentMetadata.uid !== BigInt(currentUID)
    || (parentMetadata.mode & 0o077n) !== 0n) {
    fail("catalogPath parent must be an owner-only directory");
  }
  return declared;
}

function loadApprovedCatalog(path, { currentUID = process.getuid?.() ?? 0 } = {}) {
  const declared = validateCatalogPath(path, currentUID);
  const metadata = bigintStat(declared);
  if (!isRegularFile(metadata)
    || metadata.uid !== BigInt(currentUID)
    || metadata.nlink !== 1n
    || (metadata.mode & 0o077n) !== 0n
    || metadata.size < 2n
    || metadata.size > BigInt(MAX_CATALOG_BYTES)) {
    fail("activation catalog must be an owner-only regular file within its size limit");
  }
  if (realpathSync(declared) !== declared) fail("activation catalog cannot be a symbolic link");
  const descriptor = openSync(declared, fsConstants.O_RDONLY | fsConstants.O_CLOEXEC | fsConstants.O_NOFOLLOW);
  let bytes;
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!isRegularFile(before) || before.uid !== BigInt(currentUID) || before.nlink !== 1n || (before.mode & 0o077n) !== 0n) {
      fail("activation catalog changed before it could be read safely");
    }
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameSnapshot(before, after) || BigInt(bytes.length) !== before.size) {
      fail("activation catalog changed while it was being read");
    }
  } finally {
    closeSync(descriptor);
  }
  let decoded;
  try {
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("activation catalog is not valid JSON");
  }
  const catalog = validateCatalogValue(decoded, { currentUID });
  for (const plan of catalog.plans) revalidateActivationPlan(plan, { currentUID });
  return catalog;
}

function buildGuardRunnerPlan(plan) {
  return deepFreeze({
    schemaVersion: GUARD_PLAN_SCHEMA_VERSION,
    serverID: plan.serverID,
    reviewFingerprint: plan.reviewFingerprint,
    serverName: plan.dsh.serverName,
    executable: plan.executable,
    reviewedArgumentFiles: plan.reviewedArgumentFiles,
    project: plan.project,
    command: plan.dsh.command,
    arguments: plan.dsh.arguments,
    workingDirectory: plan.dsh.workingDirectory,
    credentialVariables: plan.dsh.environment.map((entry) => entry.variableName),
    limits: {
      startupTimeoutMilliseconds: plan.wrapper.startupTimeoutMilliseconds,
      toolCallTimeoutMilliseconds: plan.dsh.toolCallTimeoutMilliseconds,
      maximumDiscoveredTools: plan.wrapper.maximumDiscoveredTools,
      maximumOutputBytes: plan.wrapper.maximumOutputBytes,
      maximumInventoryBytes: MAX_INVENTORY_BYTES
    }
  });
}

function validateGuardRunnerPlan(value, options = {}) {
  const object = exactKeys(value, [
    "schemaVersion",
    "serverID",
    "reviewFingerprint",
    "serverName",
    "executable",
    "reviewedArgumentFiles",
    "project",
    "command",
    "arguments",
    "workingDirectory",
    "credentialVariables",
    "limits"
  ], [], "guardPlan");
  if (object.schemaVersion !== GUARD_PLAN_SCHEMA_VERSION) fail("guardPlan.schemaVersion is unsupported");
  const activationLike = validateActivationPlan({
    serverID: object.serverID,
    reviewFingerprint: object.reviewFingerprint,
    executable: object.executable,
    reviewedArgumentFiles: object.reviewedArgumentFiles,
    project: object.project,
    dsh: {
      pluginID: `mcp-${object.serverName}`,
      packageName: PINNED_MCP_PACKAGE,
      transport: "stdio",
      serverName: object.serverName,
      command: object.command,
      arguments: object.arguments,
      environment: arrayValue(object.credentialVariables, "guardPlan.credentialVariables", 12)
        .map((variableName) => ({ variableName, credential: variableName })),
      workingDirectory: object.workingDirectory,
      toolCallTimeoutMilliseconds: record(object.limits, "guardPlan.limits").toolCallTimeoutMilliseconds,
      failOnStartupError: true,
      reconnect: {
        enabled: false,
        initialDelayMilliseconds: 100,
        maximumDelayMilliseconds: 100,
        maximumAttempts: 1
      }
    },
    wrapper: {
      startupTimeoutMilliseconds: object.limits.startupTimeoutMilliseconds,
      maximumDiscoveredTools: object.limits.maximumDiscoveredTools,
      maximumOutputBytes: object.limits.maximumOutputBytes,
      inheritAmbientEnvironment: false
    },
    disclosure: {
      mcpServer: {
        boundary: "onDevice",
        dataKinds: object.credentialVariables.length > 0
          ? ["authenticationMetadata", "toolArguments", "toolResults"]
          : ["toolArguments", "toolResults"]
      },
      modelProvider: "guarded-runtime",
      modelBoundary: "onDevice"
    }
  }, options);
  const limitsObject = exactKeys(object.limits, [
    "startupTimeoutMilliseconds",
    "toolCallTimeoutMilliseconds",
    "maximumDiscoveredTools",
    "maximumOutputBytes",
    "maximumInventoryBytes"
  ], [], "guardPlan.limits");
  if (limitsObject.maximumInventoryBytes !== MAX_INVENTORY_BYTES) fail("guardPlan.maximumInventoryBytes changed");
  const credentialVariables = arrayValue(object.credentialVariables, "guardPlan.credentialVariables", 12)
    .map((entry, index) => stringValue(entry, `guardPlan.credentialVariables[${index}]`, {
      min: 1,
      max: 64,
      pattern: ENVIRONMENT_PATTERN
    }));
  uniqueStrings(credentialVariables, "guardPlan.credentialVariables");
  return deepFreeze({
    schemaVersion: GUARD_PLAN_SCHEMA_VERSION,
    serverID: activationLike.serverID,
    reviewFingerprint: activationLike.reviewFingerprint,
    serverName: activationLike.dsh.serverName,
    executable: activationLike.executable,
    reviewedArgumentFiles: activationLike.reviewedArgumentFiles,
    project: activationLike.project,
    command: activationLike.dsh.command,
    arguments: activationLike.dsh.arguments,
    workingDirectory: activationLike.dsh.workingDirectory,
    credentialVariables,
    limits: {
      startupTimeoutMilliseconds: activationLike.wrapper.startupTimeoutMilliseconds,
      toolCallTimeoutMilliseconds: activationLike.dsh.toolCallTimeoutMilliseconds,
      maximumDiscoveredTools: activationLike.wrapper.maximumDiscoveredTools,
      maximumOutputBytes: activationLike.wrapper.maximumOutputBytes,
      maximumInventoryBytes: MAX_INVENTORY_BYTES
    }
  });
}

function encodeGuardRunnerPlan(plan) {
  const encoded = Buffer.from(JSON.stringify(buildGuardRunnerPlan(plan)), "utf8").toString("base64url");
  if (encoded.length > MAX_CATALOG_BYTES * 2) fail("guard plan is too large");
  return encoded;
}

function decodeGuardRunnerPlan(value, options = {}) {
  const encoded = stringValue(value, "LOCAL_HARNESS_MCP_GUARD_PLAN", { min: 1, max: MAX_CATALOG_BYTES * 2 });
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) fail("LOCAL_HARNESS_MCP_GUARD_PLAN is not canonical base64url");
  let bytes;
  try {
    bytes = Buffer.from(encoded, "base64url");
  } catch {
    fail("LOCAL_HARNESS_MCP_GUARD_PLAN could not be decoded");
  }
  if (bytes.toString("base64url") !== encoded) fail("LOCAL_HARNESS_MCP_GUARD_PLAN is not canonical base64url");
  let decoded;
  try {
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("LOCAL_HARNESS_MCP_GUARD_PLAN is not valid JSON");
  }
  return validateGuardRunnerPlan(decoded, options);
}

export {
  CATALOG_SCHEMA_VERSION,
  GUARD_PLAN_SCHEMA_VERSION,
  MAX_APPROVAL_ARGUMENT_BYTES,
  MAX_CATALOG_BYTES,
  MAX_INVENTORY_BYTES,
  MCPGuardConfigurationError,
  PINNED_MCP_PACKAGE,
  buildGuardRunnerPlan,
  decodeGuardRunnerPlan,
  encodeGuardRunnerPlan,
  executableFingerprint,
  loadApprovedCatalog,
  projectFingerprint,
  revalidateActivationPlan,
  revalidateGuardRunnerPlan,
  under,
  validateActivationPlan,
  validateCatalogValue,
  validateGuardRunnerPlan
};
