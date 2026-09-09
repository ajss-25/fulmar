#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  chmod,
  lstat,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  unlink,
  writeFile
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const MAX_ENTRIES = 250_000;
const MAX_FILE_BYTES = 2n * 1024n * 1024n * 1024n;
const MAX_TOTAL_FILE_BYTES = 8n * 1024n * 1024n * 1024n;
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;
const MAX_PATH_BYTES = 4096;
const MAX_SEGMENT_BYTES = 255;
const MAX_LINK_BYTES = 4096;
const IO_CHUNK_BYTES = 1024 * 1024;
const CONTROL_OR_DELETE = /[\u0000-\u001f\u007f]/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MODE = /^[0-7]{4}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const ROOT_LABEL = /^[A-Za-z][A-Za-z0-9._ -]{0,63}$/u;
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const releaseIdentity = JSON.parse(await readFile(
  new URL("../Config/ReleaseIdentity.json", import.meta.url), "utf8"
));
const expectedDSHVersion = releaseIdentity.runtime.deepseekHarnessVersion;

const pluginFiles = new Map([
  ["dsh-credentials-keychain", ["package.json", "index.mjs"]],
  ["dsh-fs-confined", ["package.json", "index.mjs"]],
  ["dsh-mcp-guarded", ["package.json", "index.mjs", "catalog-core.mjs", "guarded-runtime.mjs", "wire-guard.mjs", "stdio-guard-runner.mjs"]],
  ["dsh-client-security-bridge", ["package.json", "index.mjs", "client.js"]],
  ["dsh-performance-profile", ["package.json", "index.mjs"]],
  ["dsh-web-fetch-safe", ["package.json", "index.mjs"]]
]);
const pluginSourceDirectories = new Map([
  ["dsh-credentials-keychain", "credentials-keychain"],
  ["dsh-fs-confined", "fs-confined"],
  ["dsh-mcp-guarded", "mcp-guarded"],
  ["dsh-client-security-bridge", "client-security-bridge"],
  ["dsh-performance-profile", "performance-profile"],
  ["dsh-web-fetch-safe", "web-fetch-safe"]
]);
const localPluginDependencies = Object.freeze({
  "@local-harness/dsh-client-security-bridge": "1.2.1",
  "@local-harness/dsh-credentials-keychain": "1.0.8",
  "@local-harness/dsh-fs-confined": "1.0.0",
  "@local-harness/dsh-mcp-guarded": "1.0.0",
  "@local-harness/dsh-performance-profile": "1.2.0",
  "@local-harness/dsh-web-fetch-safe": "1.0.0"
});

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, expected, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${context} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${context} has an invalid schema (keys: ${actual.join(", ")})`);
  }
}

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function normalizeSegment(segment, context) {
  const normalized = segment.normalize("NFC");
  const bytes = Buffer.byteLength(normalized, "utf8");
  if (segment === "" || segment === "." || segment === ".." || segment.includes("/") || segment.includes("\\")
      || CONTROL_OR_DELETE.test(segment) || bytes === 0 || bytes > MAX_SEGMENT_BYTES) {
    fail(`${context} contains an unsafe path segment: ${JSON.stringify(segment)}`);
  }
  return normalized;
}

function normalizeRelativePath(path, context) {
  if (typeof path !== "string" || path === "" || isAbsolute(path) || path.includes("\\")
      || CONTROL_OR_DELETE.test(path) || Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) {
    fail(`${context} is not a safe bounded relative path: ${JSON.stringify(path)}`);
  }
  const normalized = path.split("/").map((segment) => normalizeSegment(segment, context)).join("/");
  if (normalized !== path.normalize("NFC")) fail(`${context} did not normalize deterministically`);
  return normalized;
}

function identityFor(path) {
  return path.normalize("NFC").toLowerCase();
}

function formatMode(info) {
  return Number(info.mode & 0o7777n).toString(8).padStart(4, "0");
}

function stableStatIdentity(info) {
  return [info.dev, info.ino, info.mode, info.nlink, info.uid, info.gid, info.rdev, info.size, info.mtimeNs, info.ctimeNs]
    .map(String).join(":");
}

function ensureContained(root, candidate, context) {
  const escape = relative(root, candidate);
  if (escape === ".." || escape.startsWith(`..${sep}`) || isAbsolute(escape)) fail(`${context} escapes its root`);
}

async function hashOpenRegularFile(path, before, { capture = false } = {}) {
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) fail(`unsupported or hard-linked regular file: ${path}`);
  if (before.size < 0n || before.size > MAX_FILE_BYTES) fail(`file exceeds the per-file safety bound: ${path}`);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino
        || stableStatIdentity(opened) !== stableStatIdentity(before)) {
      fail(`file changed while it was opened: ${path}`);
    }
    const hash = createHash("sha256");
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(IO_CHUNK_BYTES);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (chunks !== null) chunks.push(Buffer.from(chunk));
      position += bytesRead;
      if (BigInt(position) > before.size) fail(`file grew while hashing: ${path}`);
    }
    if (BigInt(position) !== before.size) fail(`file size changed while hashing: ${path}`);
    const after = await handle.stat({ bigint: true });
    if (stableStatIdentity(after) !== stableStatIdentity(opened)) fail(`file changed while hashing: ${path}`);
    return { sha256: hash.digest("hex"), bytes: chunks === null ? undefined : Buffer.concat(chunks) };
  } finally {
    await handle.close();
  }
}

async function decodeDirectoryNames(directory) {
  const encodedNames = await readdir(directory, { encoding: "buffer" });
  return encodedNames.map((encoded) => {
    try {
      return textDecoder.decode(encoded);
    } catch {
      fail(`directory contains a filename that is not valid UTF-8: ${directory}`);
    }
  }).sort(byteCompare);
}

async function scanInventory(rootArgument, rootLabel) {
  if (!ROOT_LABEL.test(rootLabel) || CONTROL_OR_DELETE.test(rootLabel)) fail(`invalid inventory root label: ${rootLabel}`);
  const rootInfo = await lstat(rootArgument, { bigint: true });
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail(`inventory root must be a real directory: ${rootArgument}`);
  const root = await realpath(rootArgument);
  const entries = [];
  const identities = new Set();
  let totalFileBytes = 0n;

  async function visit(directory, prefix = "") {
    const directoryBefore = await lstat(directory, { bigint: true });
    if (!directoryBefore.isDirectory() || directoryBefore.isSymbolicLink()) fail(`directory changed while scanning: ${directory}`);
    const names = await decodeDirectoryNames(directory);
    for (const rawName of names) {
      const name = normalizeSegment(rawName, `entry beneath ${prefix || rootLabel}`);
      const path = join(directory, rawName);
      const relativePath = normalizeRelativePath(prefix ? `${prefix}/${name}` : name, "inventory path");
      const identity = identityFor(relativePath);
      if (identities.has(identity)) fail(`duplicate case/canonical-normalized inventory path: ${relativePath}`);
      identities.add(identity);
      if (entries.length >= MAX_ENTRIES) fail(`inventory exceeds ${MAX_ENTRIES} entries`);
      const info = await lstat(path, { bigint: true });
      if (info.isDirectory() && !info.isSymbolicLink()) {
        entries.push({ path: relativePath, type: "directory", mode: formatMode(info) });
        await visit(path, relativePath);
      } else if (info.isFile() && !info.isSymbolicLink()) {
        const { sha256 } = await hashOpenRegularFile(path, info);
        totalFileBytes += info.size;
        if (totalFileBytes > MAX_TOTAL_FILE_BYTES) fail("inventory exceeds the total file-byte safety bound");
        entries.push({ path: relativePath, type: "file", mode: formatMode(info), size: Number(info.size), sha256 });
      } else if (info.isSymbolicLink()) {
        const encodedTarget = await readlink(path, { encoding: "buffer" });
        let target;
        try {
          target = textDecoder.decode(encodedTarget);
        } catch {
          fail(`symlink target is not valid UTF-8: ${relativePath}`);
        }
        if (target === "" || isAbsolute(target) || target.includes("\\") || CONTROL_OR_DELETE.test(target)
            || Buffer.byteLength(target, "utf8") > MAX_LINK_BYTES) {
          fail(`unsafe symlink target at ${relativePath}: ${JSON.stringify(target)}`);
        }
        const lexicalTarget = resolve(directory, target);
        ensureContained(root, lexicalTarget, `symlink ${relativePath}`);
        let resolvedTarget;
        try {
          resolvedTarget = await realpath(path);
        } catch {
          fail(`dangling or cyclic symlink at ${relativePath}`);
        }
        ensureContained(root, resolvedTarget, `symlink ${relativePath}`);
        entries.push({ path: relativePath, type: "symlink", target: target.normalize("NFC") });
      } else {
        fail(`unsupported filesystem object at ${relativePath}`);
      }
    }
    const namesAfter = await decodeDirectoryNames(directory);
    const directoryAfter = await lstat(directory, { bigint: true });
    if (JSON.stringify(namesAfter) !== JSON.stringify(names)
        || stableStatIdentity(directoryAfter) !== stableStatIdentity(directoryBefore)) {
      fail(`directory changed while scanning: ${directory}`);
    }
  }

  await visit(root);
  entries.sort((left, right) => byteCompare(left.path, right.path));
  return {
    schemaVersion: SCHEMA_VERSION,
    root: rootLabel,
    entryCount: entries.length,
    totalFileBytes: String(totalFileBytes),
    entries
  };
}

function canonicalManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

async function readBoundedRegular(path, maximumBytes) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) {
    fail(`expected a bounded, non-hard-linked regular file: ${path}`);
  }
  const { bytes } = await hashOpenRegularFile(path, before, { capture: true });
  return bytes;
}

function validateManifestObject(manifest, sourceBytes) {
  exactKeys(manifest, ["schemaVersion", "root", "entryCount", "totalFileBytes", "entries"], "inventory manifest");
  if (manifest.schemaVersion !== SCHEMA_VERSION) fail(`unsupported inventory schema: ${manifest.schemaVersion}`);
  if (typeof manifest.root !== "string" || !ROOT_LABEL.test(manifest.root) || CONTROL_OR_DELETE.test(manifest.root)) fail("invalid inventory root label");
  if (!Number.isSafeInteger(manifest.entryCount) || manifest.entryCount < 0 || manifest.entryCount > MAX_ENTRIES) fail("invalid inventory entry count");
  if (typeof manifest.totalFileBytes !== "string" || !DECIMAL.test(manifest.totalFileBytes)) fail("invalid inventory total byte count");
  if (!Array.isArray(manifest.entries) || manifest.entries.length !== manifest.entryCount) fail("inventory entry count does not match its entries");
  const totalClaim = BigInt(manifest.totalFileBytes);
  if (totalClaim > MAX_TOTAL_FILE_BYTES) fail("inventory total exceeds the safety bound");
  const identities = new Set();
  let previousPath;
  let total = 0n;
  for (let index = 0; index < manifest.entries.length; index += 1) {
    const entry = manifest.entries[index];
    const context = `inventory entry ${index}`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) fail(`${context} must be an object`);
    const path = normalizeRelativePath(entry.path, `${context} path`);
    if (path !== entry.path) fail(`${context} path is not NFC-normalized`);
    if (previousPath !== undefined && byteCompare(previousPath, path) >= 0) fail("inventory entries are not in strict UTF-8 byte order");
    previousPath = path;
    const identity = identityFor(path);
    if (identities.has(identity)) fail(`duplicate case/canonical-normalized manifest path: ${path}`);
    identities.add(identity);
    if (entry.type === "directory") {
      exactKeys(entry, ["path", "type", "mode"], context);
      if (typeof entry.mode !== "string" || !MODE.test(entry.mode)) fail(`${context} has an invalid mode`);
    } else if (entry.type === "file") {
      exactKeys(entry, ["path", "type", "mode", "size", "sha256"], context);
      if (typeof entry.mode !== "string" || !MODE.test(entry.mode)) fail(`${context} has an invalid mode`);
      if (!Number.isSafeInteger(entry.size) || entry.size < 0 || BigInt(entry.size) > MAX_FILE_BYTES) fail(`${context} has an invalid size`);
      if (typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)) fail(`${context} has an invalid SHA-256`);
      total += BigInt(entry.size);
      if (total > MAX_TOTAL_FILE_BYTES) fail("inventory total exceeds the safety bound");
    } else if (entry.type === "symlink") {
      exactKeys(entry, ["path", "type", "target"], context);
      if (typeof entry.target !== "string" || entry.target === "" || isAbsolute(entry.target) || entry.target.includes("\\")
          || CONTROL_OR_DELETE.test(entry.target) || Buffer.byteLength(entry.target, "utf8") > MAX_LINK_BYTES
          || entry.target !== entry.target.normalize("NFC")) {
        fail(`${context} has an unsafe symlink target`);
      }
    } else {
      fail(`${context} has an unsupported type`);
    }
  }
  if (total !== totalClaim) fail("inventory total byte count is inconsistent");
  if (sourceBytes !== undefined && !sourceBytes.equals(Buffer.from(canonicalManifest(manifest), "utf8"))) {
    fail("inventory manifest is not in deterministic canonical form");
  }
  return manifest;
}

async function loadManifest(path) {
  const bytes = await readBoundedRegular(path, MAX_MANIFEST_BYTES);
  let text;
  try {
    text = textDecoder.decode(bytes);
  } catch {
    fail(`inventory manifest is not valid UTF-8: ${path}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    fail(`inventory manifest is not valid JSON: ${path}`);
  }
  return validateManifestObject(manifest, bytes);
}

async function writeManifest(path, manifest) {
  validateManifestObject(manifest);
  const destination = resolve(path);
  const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, canonicalManifest(manifest), { mode: 0o600, flag: "wx" });
    await chmod(temporary, 0o644);
    await rename(temporary, destination);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

function compareInventories(expected, actual, context) {
  if (expected.root !== actual.root) fail(`${context} root label changed: expected ${expected.root}, found ${actual.root}`);
  const expectedByPath = new Map(expected.entries.map((entry) => [entry.path, entry]));
  const actualByPath = new Map(actual.entries.map((entry) => [entry.path, entry]));
  for (const path of expectedByPath.keys()) if (!actualByPath.has(path)) fail(`${context} is missing ${path}`);
  for (const path of actualByPath.keys()) if (!expectedByPath.has(path)) fail(`${context} has an extra entry ${path}`);
  for (const [path, expectedEntry] of expectedByPath) {
    if (JSON.stringify(expectedEntry) !== JSON.stringify(actualByPath.get(path))) fail(`${context} changed at ${path}`);
  }
  if (expected.entryCount !== actual.entryCount || expected.totalFileBytes !== actual.totalFileBytes) fail(`${context} aggregate counts changed`);
}

async function generate(root, destination, rootLabel) {
  const rootPath = await realpath(root);
  const destinationPath = resolve(destination);
  const inside = relative(rootPath, destinationPath);
  if (inside === "" || (!inside.startsWith(`..${sep}`) && inside !== ".." && !isAbsolute(inside))) {
    fail("inventory output must not be placed inside the inventoried tree");
  }
  const manifest = await scanInventory(rootPath, rootLabel);
  await writeManifest(destinationPath, manifest);
  process.stdout.write(`Generated ${rootLabel} inventory with ${manifest.entryCount} entries and ${manifest.totalFileBytes} file bytes.\n`);
}

async function verify(root, manifestPath, requiredLabel) {
  const expected = await loadManifest(manifestPath);
  if (requiredLabel !== undefined && expected.root !== requiredLabel) fail(`expected ${requiredLabel} inventory, found ${expected.root}`);
  const actual = await scanInventory(root, expected.root);
  compareInventories(expected, actual, expected.root);
  process.stdout.write(`Verified ${expected.root} inventory: ${expected.entryCount} entries and ${expected.totalFileBytes} file bytes.\n`);
}

async function verifyPrefix(root, manifestPath, prefixArgument, requiredLabel) {
  const expectedFull = await loadManifest(manifestPath);
  if (requiredLabel !== undefined && expectedFull.root !== requiredLabel) {
    fail(`expected ${requiredLabel} inventory, found ${expectedFull.root}`);
  }
  const prefix = normalizeRelativePath(prefixArgument, "inventory prefix");
  const rootEntry = expectedFull.entries.find((entry) => entry.path === prefix);
  if (rootEntry?.type !== "directory") fail(`inventory prefix is not one reviewed directory: ${prefix}`);
  const actualRoot = await lstat(root, { bigint: true });
  if (!actualRoot.isDirectory() || actualRoot.isSymbolicLink() || formatMode(actualRoot) !== rootEntry.mode) {
    fail(`inventory prefix root changed at ${prefix}`);
  }
  const marker = `${prefix}/`;
  const entries = expectedFull.entries
    .filter((entry) => entry.path.startsWith(marker))
    .map((entry) => ({ ...entry, path: entry.path.slice(marker.length) }));
  if (entries.length === 0) fail(`inventory prefix is empty: ${prefix}`);
  const total = entries.reduce(
    (sum, entry) => sum + (entry.type === "file" ? BigInt(entry.size) : 0n),
    0n
  );
  const expected = validateManifestObject({
    schemaVersion: SCHEMA_VERSION,
    root: "NodeRuntime",
    entryCount: entries.length,
    totalFileBytes: String(total),
    entries
  });
  const actual = await scanInventory(root, expected.root);
  compareInventories(expected, actual, `inventory prefix ${prefix}`);
  process.stdout.write(`Verified inventory prefix ${prefix}: ${expected.entryCount} entries and ${expected.totalFileBytes} file bytes.\n`);
}

function cloneEntry(entry, path, overrides = {}) {
  return { ...entry, ...overrides, path };
}

function fileEntry(path, bytes, mode = "0644") {
  return {
    path,
    type: "file",
    mode,
    size: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

function removePresetRows(source) {
  const removedRowIDs = new Set(["workflow-worker-thread", "tool-workflow", "tool-ralph"]);
  const lines = source.split("\n");
  const output = [];
  for (let index = 0; index < lines.length;) {
    const match = /^(\s*)- id:\s*['"]?([^'"\s#]+)['"]?\s*(?:#.*)?$/u.exec(lines[index]);
    if (!match || !removedRowIDs.has(match[2])) {
      output.push(lines[index]);
      index += 1;
      continue;
    }
    const indentation = match[1].length;
    index += 1;
    while (index < lines.length) {
      const line = lines[index];
      if (line.trim() === "" || line.trimStart().startsWith("#")) {
        index += 1;
        continue;
      }
      const leading = line.length - line.trimStart().length;
      if (leading <= indentation) break;
      index += 1;
    }
  }
  return output.join("\n").replace(/\n{3,}/gu, "\n\n");
}

function sanitizeComposition(source) {
  let composition = removePresetRows(source);
  function replaceSingleTopLevelRow(id, replacement) {
    const lines = composition.split("\n");
    const rowHeader = /^- id:[ \t]*([^ \t]+)[ \t]*$/u;
    const nextTopLevelRow = /^- id:/u;
    const rows = lines.flatMap((line, index) => rowHeader.exec(line)?.[1] === id ? [index] : []);
    if (rows.length !== 1) fail(`expected exactly one ${id} row, found ${rows.length}`);
    const start = rows[0];
    let end = start + 1;
    while (end < lines.length && !nextTopLevelRow.test(lines[end])) end += 1;
    lines.splice(start, end - start, ...replacement.split("\n"));
    composition = lines.join("\n");
  }
  const isolatedSkillRow = [
    "- id: skill-filesystem",
    "  name: '@deepseek-ai/dsh-skill-filesystem'",
    "  config:",
    "    includeDefaultRoots: false",
    "    bundledSkillDir: !!js \"process.getBuiltinModule('node:path').join(process.env.DSH_HOME, 'skills', 'Active')\"",
    "    watchFollowSymlinks: false",
    ""
  ].join("\n");
  replaceSingleTopLevelRow("skill-filesystem", isolatedSkillRow);
  const approvedWebToolRow = [
    "- id: tool-web",
    "  name: '@deepseek-ai/dsh-tool-web'",
    "  config:",
    "    search: false",
    "    fetch: true",
    "    fetchTimeoutMs: 30000",
    "    fetchMaxOutputChars: 200000",
    ""
  ].join("\n");
  replaceSingleTopLevelRow("tool-web", approvedWebToolRow);
  composition = composition.replace(
    "# The `web` service and its search provider stay in the host composition; only\n# the model-facing tool is per-session.",
    "# Fulmar exposes only its per-page-approved fetch tool to model-facing sessions;\n# credential-dependent general search remains absent until separately configured."
  );
  const forbidden = [
    "@deepseek-ai/dsh-fs-local", "@deepseek-ai/dsh-tool-cordis", "@deepseek-ai/dsh-tool-cordis-mount",
    "@deepseek-ai/dsh-cordis-mount", "@deepseek-ai/dsh-workflow-worker-thread", "@deepseek-ai/dsh-tool-workflow",
    "@deepseek-ai/dsh-tool-ralph", "@deepseek-ai/dsh-code-runtime-worker-thread", "@deepseek-ai/dsh-tool-code"
  ];
  for (const marker of forbidden) if (composition.includes(marker)) fail(`unsafe preset capability remained: ${marker}`);
  for (const required of ["@deepseek-ai/dsh-tool-bash", "@deepseek-ai/dsh-tool-fs", "@deepseek-ai/dsh-tool-subagent"])
    if (!composition.includes(required)) fail(`required sandboxed capability is missing: ${required}`);
  for (const required of ["search: false", "fetch: true", "fetchTimeoutMs: 30000", "fetchMaxOutputChars: 200000"])
    if (!composition.includes(required)) fail(`approved web capability is missing: ${required}`);
  return composition;
}

async function readVerifiedSourceFile(root, sourceEntry) {
  if (sourceEntry?.type !== "file") fail(`expected reviewed regular file in source inventory: ${sourceEntry?.path ?? "unknown"}`);
  const path = join(root, ...sourceEntry.path.split("/"));
  const info = await lstat(path, { bigint: true });
  const { sha256, bytes } = await hashOpenRegularFile(path, info, { capture: true });
  if (Number(info.size) !== sourceEntry.size || formatMode(info) !== sourceEntry.mode || sha256 !== sourceEntry.sha256) {
    fail(`reviewed source file changed while deriving assembly: ${sourceEntry.path}`);
  }
  return bytes;
}

async function materializedDSHManifest(vendorRoot, sourceEntry, projectRoot) {
  const bytes = await readVerifiedSourceFile(vendorRoot, sourceEntry);
  let manifest;
  try { manifest = JSON.parse(textDecoder.decode(bytes)); }
  catch { fail("reviewed DSH manifest is not valid JSON"); }
  if (manifest?.name !== "@deepseek-ai/dsh" || manifest.version !== expectedDSHVersion
      || manifest.dependencies === null || typeof manifest.dependencies !== "object"
      || Array.isArray(manifest.dependencies)) {
    fail("reviewed DSH manifest identity or dependency schema changed");
  }
  const existingLocal = Object.keys(manifest.dependencies).filter((name) => name.startsWith("@local-harness/"));
  if (existingLocal.some((name) => name !== "@local-harness/dsh-credentials-keychain")) {
    fail("reviewed DSH manifest introduced an unknown Fulmar local dependency");
  }
  for (const [name, version] of Object.entries(localPluginDependencies)) {
    const packageName = name.slice("@local-harness/".length);
    const sourceDirectory = pluginSourceDirectories.get(packageName);
    if (sourceDirectory === undefined) fail(`missing source mapping for ${name}`);
    const path = join(projectRoot, "Resources", "DSHPlugins", sourceDirectory, "package.json");
    const info = await lstat(path, { bigint: true });
    const { bytes: pluginBytes } = await hashOpenRegularFile(path, info, { capture: true });
    let localManifest;
    try { localManifest = JSON.parse(textDecoder.decode(pluginBytes)); }
    catch { fail(`local plugin manifest is invalid: ${name}`); }
    if (localManifest?.name !== name || localManifest.version !== version) {
      fail(`local plugin identity changed: ${name}`);
    }
    manifest.dependencies[name] = version;
  }
  manifest.dependencies = Object.fromEntries(
    Object.entries(manifest.dependencies).sort(([left], [right]) => byteCompare(left, right))
  );
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function expectedAssembly(vendorRoot, vendorManifest, projectRoot) {
  const source = new Map(vendorManifest.entries.map((entry) => [entry.path, entry]));
  const expected = new Map();
  function add(entry, provenance) {
    normalizeRelativePath(entry.path, "assembled runtime path");
    if (expected.has(entry.path)) fail(`assembled mapping collision at ${entry.path} (${provenance})`);
    expected.set(entry.path, entry);
  }
  function sourceEntry(path, type) {
    const entry = source.get(path);
    if (entry === undefined || entry.type !== type) fail(`source inventory lacks required ${type}: ${path}`);
    return entry;
  }

  add(cloneEntry(sourceEntry("node-v22.23.1-darwin-arm64/bin/node", "file"), "node", { mode: "0755" }), "pinned Node executable");
  add(cloneEntry(sourceEntry("node-v22.23.1-darwin-arm64/LICENSE", "file"), "NODE_LICENSE"), "Node license");
  add(cloneEntry(sourceEntry("package-lock.json", "file"), "package-lock.json"), "package lock");

  const dshPrefix = "node_modules/@deepseek-ai/dsh";
  const presetPrefix = `${dshPrefix}/config/agent-presets`;
  for (const entry of vendorManifest.entries) {
    if (entry.path !== dshPrefix && !entry.path.startsWith(`${dshPrefix}/`)) continue;
    if (entry.path === presetPrefix || entry.path.startsWith(`${presetPrefix}/`)) continue;
    const suffix = entry.path === dshPrefix ? "" : entry.path.slice(dshPrefix.length + 1);
    const destination = suffix === "" ? "dsh" : `dsh/${suffix}`;
    if (suffix === "package.json") {
      const materialized = await materializedDSHManifest(vendorRoot, entry, projectRoot);
      add(fileEntry(destination, materialized, entry.mode), "materialized top-level DSH manifest");
    } else {
      add(cloneEntry(entry, destination), "top-level DSH package");
    }
  }

  const modulesPrefix = "node_modules";
  const nestedDSHBinLink = "node_modules/.bin/dsh";
  for (const entry of vendorManifest.entries) {
    if (entry.path !== modulesPrefix && !entry.path.startsWith(`${modulesPrefix}/`)) continue;
    // The authoritative package is Runtime/dsh. Exclude the exact nested
    // @deepseek-ai/dsh self-package from the dependency tree so no alternate
    // CLI, composition, or preset discovery root is packaged.
    if (entry.path === dshPrefix || entry.path.startsWith(`${dshPrefix}/`)) continue;
    if (entry.path === nestedDSHBinLink) continue;
    const suffix = entry.path === modulesPrefix ? "" : entry.path.slice(modulesPrefix.length + 1);
    add(cloneEntry(entry, suffix === "" ? "dsh/node_modules" : `dsh/node_modules/${suffix}`), "complete npm dependency tree");
  }

  const compositionSourceEntry = sourceEntry(`${presetPrefix}/standard/agent.cordis.yml`, "file");
  const compositionSource = await readVerifiedSourceFile(vendorRoot, compositionSourceEntry);
  const composition = Buffer.from(sanitizeComposition(textDecoder.decode(compositionSource)), "utf8");
  const preset = Buffer.from([
    "name: Fulmar Standard",
    "description: Sandboxed coding agent with files, shell, approved page fetch, skills, goals, plans and subagents.",
    "order: 1",
    ""
  ].join("\n"), "utf8");
  const policy = Buffer.from(`${JSON.stringify({
    version: 1,
    allowedPresetIDs: ["standard"],
    removedRowIDs: ["tool-ralph", "tool-workflow", "workflow-worker-thread"],
    compositionSHA256: createHash("sha256").update(composition).digest("hex")
  }, null, 2)}\n`, "utf8");
  const presetRoots = ["dsh/config/agent-presets"];
  for (const presetRoot of presetRoots) {
    add(cloneEntry(sourceEntry(presetPrefix, "directory"), presetRoot), "sanitized preset root");
    add(cloneEntry(sourceEntry(`${presetPrefix}/standard`, "directory"), `${presetRoot}/standard`), "sanitized standard preset");
    add(fileEntry(`${presetRoot}/standard/agent.cordis.yml`, composition), "sanitized composition");
    add(fileEntry(`${presetRoot}/standard/preset.yml`, preset), "sanitized preset metadata");
    add(fileEntry(`${presetRoot}/local-harness-policy.json`, policy), "sanitized preset policy");
  }

  const localRoot = "dsh/node_modules/@local-harness";
  add({ path: localRoot, type: "directory", mode: "0755" }, "local plugin namespace");
  for (const [packageName, files] of pluginFiles) {
    add({ path: `${localRoot}/${packageName}`, type: "directory", mode: "0755" }, `${packageName} directory`);
    const sourceDirectory = pluginSourceDirectories.get(packageName);
    for (const filename of files) {
      const sourcePath = join(projectRoot, "Resources", "DSHPlugins", sourceDirectory, filename);
      const info = await lstat(sourcePath, { bigint: true });
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) fail(`local plugin source must be a non-hard-linked regular file: ${sourcePath}`);
      const { sha256 } = await hashOpenRegularFile(sourcePath, info);
      add({
        path: `${localRoot}/${packageName}/${filename}`,
        type: "file",
        mode: formatMode(info),
        size: Number(info.size),
        sha256
      }, `${packageName}/${filename}`);
    }
  }

  const entries = [...expected.values()].sort((left, right) => byteCompare(left.path, right.path));
  const total = entries.reduce((sum, entry) => sum + (entry.type === "file" ? BigInt(entry.size) : 0n), 0n);
  return validateManifestObject({
    schemaVersion: SCHEMA_VERSION,
    root: "Runtime",
    entryCount: entries.length,
    totalFileBytes: String(total),
    entries
  });
}

async function verifyAssembled(vendorRoot, vendorManifestPath, runtimeRoot, projectRoot, derivedManifestPath) {
  const vendorManifest = await loadManifest(vendorManifestPath);
  if (vendorManifest.root !== "VendorRuntime") fail("assembly requires the reviewed VendorRuntime inventory");
  const currentVendor = await scanInventory(vendorRoot, "VendorRuntime");
  compareInventories(vendorManifest, currentVendor, "VendorRuntime after copy");
  const expected = await expectedAssembly(await realpath(vendorRoot), vendorManifest, await realpath(projectRoot));
  const actual = await scanInventory(runtimeRoot, "Runtime");
  compareInventories(expected, actual, "assembled Runtime");
  if (derivedManifestPath !== undefined) await writeManifest(derivedManifestPath, expected);
  process.stdout.write(`Verified derived Runtime assembly: ${actual.entryCount} entries, one authoritative DSH package, six reviewed local plugins, and one exact sanitized preset root.\n`);
}

async function verifyDerivedManifest(vendorRoot, vendorManifestPath, projectRoot, unsignedManifestPath) {
  const vendorManifest = await loadManifest(vendorManifestPath);
  if (vendorManifest.root !== "VendorRuntime") fail("derivation requires the reviewed VendorRuntime inventory");
  const currentVendor = await scanInventory(vendorRoot, "VendorRuntime");
  compareInventories(vendorManifest, currentVendor, "VendorRuntime during release derivation");
  const expected = await expectedAssembly(await realpath(vendorRoot), vendorManifest, await realpath(projectRoot));
  const supplied = await loadManifest(unsignedManifestPath);
  compareInventories(expected, supplied, "derived unsigned Runtime manifest");
  process.stdout.write(`Verified independent unsigned Runtime derivation: ${expected.entryCount} exact entries.\n`);
}

function isMachOMagic(bytes) {
  if (bytes.length < 4) return false;
  const value = bytes.readUInt32BE(0);
  return new Set([0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]).has(value);
}

async function loadSignables(path) {
  const bytes = await readBoundedRegular(path, 8 * 1024 * 1024);
  let value;
  try {
    value = JSON.parse(textDecoder.decode(bytes));
  } catch {
    fail(`signable inventory is not valid canonical JSON: ${path}`);
  }
  exactKeys(value, ["schemaVersion", "root", "count", "paths"], "signable inventory");
  if (value.schemaVersion !== 1 || value.root !== "Runtime" || !Number.isSafeInteger(value.count)
      || value.count < 1 || value.count > MAX_ENTRIES || !Array.isArray(value.paths) || value.paths.length !== value.count) {
    fail("signable inventory header is invalid");
  }
  let previous;
  const identities = new Set();
  for (const path of value.paths) {
    normalizeRelativePath(path, "signable path");
    if (previous !== undefined && byteCompare(previous, path) >= 0) fail("signable paths are not in strict byte order");
    previous = path;
    const identity = identityFor(path);
    if (identities.has(identity)) fail(`duplicate signable path: ${path}`);
    identities.add(identity);
  }
  if (!bytes.equals(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"))) fail("signable inventory is not canonical");
  return value;
}

async function createSignables(runtimeRoot, unsignedManifestPath, outputPath) {
  const unsigned = await loadManifest(unsignedManifestPath);
  if (unsigned.root !== "Runtime") fail("Mach-O enumeration requires a Runtime inventory");
  const current = await scanInventory(runtimeRoot, "Runtime");
  compareInventories(unsigned, current, "unsigned Runtime before signing");
  const paths = [];
  for (const entry of unsigned.entries) {
    if (entry.type !== "file" || entry.size < 4) continue;
    const handle = await open(join(runtimeRoot, ...entry.path.split("/")), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const bytes = Buffer.alloc(4);
      const { bytesRead } = await handle.read(bytes, 0, 4, 0);
      if (bytesRead === 4 && isMachOMagic(bytes)) paths.push(entry.path);
    } finally {
      await handle.close();
    }
  }
  paths.sort(byteCompare);
  if (!paths.includes("node")) fail("assembled Runtime does not expose the pinned Node Mach-O as a signable file");
  await writeManifestLike(outputPath, { schemaVersion: 1, root: "Runtime", count: paths.length, paths });
  process.stdout.write(`Recorded ${paths.length} exact Runtime Mach-O signing targets.\n`);
}

async function writeManifestLike(path, value) {
  const destination = resolve(path);
  const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await chmod(temporary, 0o600);
    await rename(temporary, destination);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function emitSignables(path) {
  const signables = await loadSignables(path);
  for (const item of signables.paths) process.stdout.write(`${item}\n`);
}

async function validateSigningTransition(unsigned, after, signables, runtimeRoot) {
  const allowed = new Set(signables.paths);
  const before = new Map(unsigned.entries.map((entry) => [entry.path, entry]));
  for (const path of allowed) if (before.get(path)?.type !== "file") fail(`signable is not an unsigned Runtime file: ${path}`);
  const afterByPath = new Map(after.entries.map((entry) => [entry.path, entry]));
  for (const path of before.keys()) if (!afterByPath.has(path)) fail(`signed Runtime is missing ${path}`);
  for (const path of afterByPath.keys()) if (!before.has(path)) fail(`signed Runtime has an extra entry ${path}`);
  let changed = 0;
  for (const [path, expected] of before) {
    const actual = afterByPath.get(path);
    if (!allowed.has(path)) {
      if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`non-signable Runtime entry changed during signing: ${path}`);
      continue;
    }
    if (actual.type !== "file" || actual.mode !== expected.mode) fail(`signing changed type or mode at ${path}`);
    const handle = await open(join(runtimeRoot, ...path.split("/")), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const magic = Buffer.alloc(4);
      const { bytesRead } = await handle.read(magic, 0, 4, 0);
      if (bytesRead !== 4 || !isMachOMagic(magic)) fail(`signing target is no longer Mach-O: ${path}`);
    } finally {
      await handle.close();
    }
    if (actual.sha256 !== expected.sha256 || actual.size !== expected.size) changed += 1;
  }
  return { allowed: allowed.size, changed };
}

async function verifySigningTransition(unsignedManifestPath, runtimeRoot, signablesPath, finalManifestPath) {
  const unsigned = await loadManifest(unsignedManifestPath);
  if (unsigned.root !== "Runtime") fail("signing transition requires a Runtime inventory");
  const signables = await loadSignables(signablesPath);
  const after = await scanInventory(runtimeRoot, "Runtime");
  const result = await validateSigningTransition(unsigned, after, signables, runtimeRoot);
  await writeManifest(finalManifestPath, after);
  process.stdout.write(`Verified signing transition: ${result.allowed} exact Mach-O targets, ${result.changed} byte changes, and no other Runtime mutations.\n`);
}

async function verifySignedRuntime(unsignedManifestPath, runtimeRoot, signablesPath, finalManifestPath) {
  const unsigned = await loadManifest(unsignedManifestPath);
  const signables = await loadSignables(signablesPath);
  const expectedFinal = await loadManifest(finalManifestPath);
  if (unsigned.root !== "Runtime" || expectedFinal.root !== "Runtime") fail("signed release verification requires Runtime inventories");
  const actualFinal = await scanInventory(runtimeRoot, "Runtime");
  compareInventories(expectedFinal, actualFinal, "extracted signed Runtime");
  const result = await validateSigningTransition(unsigned, actualFinal, signables, runtimeRoot);
  process.stdout.write(`Verified extracted signed Runtime: ${actualFinal.entryCount} exact entries; only ${result.allowed} declared Mach-O paths could change during signing (${result.changed} changed).\n`);
}

async function fileSHA256(path) {
  const info = await lstat(path, { bigint: true });
  const hash = createHash("sha256");
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) fail(`cannot hash non-regular artifact: ${path}`);
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function main(argumentsList) {
  const [command, ...args] = argumentsList;
  if (command === "generate" && args.length === 3) return generate(args[0], args[1], args[2]);
  if (command === "verify" && (args.length === 2 || args.length === 3)) return verify(args[0], args[1], args[2]);
  if (command === "verify-prefix" && args.length === 4) return verifyPrefix(args[0], args[1], args[2], args[3]);
  if (command === "verify-assembled" && (args.length === 4 || args.length === 5)) return verifyAssembled(...args);
  if (command === "verify-derived" && args.length === 4) return verifyDerivedManifest(...args);
  if (command === "create-signables" && args.length === 3) return createSignables(...args);
  if (command === "emit-signables" && args.length === 1) return emitSignables(args[0]);
  if (command === "verify-signing-transition" && args.length === 4) return verifySigningTransition(...args);
  if (command === "verify-signed-runtime" && args.length === 4) return verifySignedRuntime(...args);
  if (command === "sha256" && args.length === 1) {
    process.stdout.write(`${await fileSHA256(args[0])}\n`);
    return;
  }
  fail([
    "usage:",
    "  runtime-inventory.mjs generate <root> <manifest> <root-label>",
    "  runtime-inventory.mjs verify <root> <manifest> [required-root-label]",
    "  runtime-inventory.mjs verify-prefix <root> <manifest> <prefix> <required-root-label>",
    "  runtime-inventory.mjs verify-assembled <vendor-root> <vendor-manifest> <runtime-root> <project-root> [derived-manifest]",
    "  runtime-inventory.mjs verify-derived <vendor-root> <vendor-manifest> <project-root> <unsigned-manifest>",
    "  runtime-inventory.mjs create-signables <runtime-root> <unsigned-manifest> <output>",
    "  runtime-inventory.mjs emit-signables <signables>",
    "  runtime-inventory.mjs verify-signing-transition <unsigned-manifest> <runtime-root> <signables> <final-manifest>",
    "  runtime-inventory.mjs verify-signed-runtime <unsigned-manifest> <runtime-root> <signables> <final-manifest>",
    "  runtime-inventory.mjs sha256 <regular-file>"
  ].join("\n"));
}

const invokedPath = process.argv[1] === undefined ? "" : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`Runtime inventory error: ${error?.message ?? String(error)}\n`);
    process.exitCode = 1;
  });
}

export { canonicalManifest, compareInventories, scanInventory, validateManifestObject };
