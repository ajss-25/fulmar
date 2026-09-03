import { constants as fsConstants, fstatSync, lstatSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join, posix as pathPosix, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const programMarkerName = "FULMAR_CREDENTIAL_MIGRATION_PROGRAM_V1";
const programMarkerValue = "descriptor-pinned-base64-v1";
const boundProgramInvocation = process.env[programMarkerName] === programMarkerValue;
const [sourcePath, helperPath, yamlModulePath] = process.argv.slice(
  boundProgramInvocation ? 1 : 2
);
if (!sourcePath || !helperPath || !yamlModulePath) throw new Error("migration arguments are incomplete");

const maximumSourceBytes = 4_194_304;
const maximumHelperOutputBytes = 1_048_576;
const refPattern = /^[A-Za-z_][A-Za-z0-9_]*$/;
const recordPattern = /^[A-Za-z0-9._~-]+\/[A-Za-z0-9._~-]+$/;
const leaseMarkerName = "FULMAR_CREDENTIAL_MIGRATION_LEASE_FD_V1";
const leaseDescriptor = 198;
const leaseFileName = ".fulmar-credential-migration.lock";
const yamlGraphMarkerName = "FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_V1";
const yamlGraphPayloadName = "FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_BASE64";
const yamlGraphMarkerValue = "descriptor-pinned-commonjs-v1";
const effectiveUserID = BigInt(process.geteuid());
const sourceDirectory = dirname(sourcePath);
const leasePath = join(sourceDirectory, leaseFileName);

function isRegularOwnerOnly(info) {
  const mode = typeof info.mode === "bigint" ? info.mode : BigInt(info.mode);
  const uid = typeof info.uid === "bigint" ? info.uid : BigInt(info.uid);
  const links = typeof info.nlink === "bigint" ? info.nlink : BigInt(info.nlink);
  return info.isFile()
    && !info.isSymbolicLink()
    && uid === effectiveUserID
    && links === 1n
    && (mode & 0o777n) === 0o600n;
}

function isPrivateOwnerDirectory(info) {
  const mode = typeof info.mode === "bigint" ? info.mode : BigInt(info.mode);
  const uid = typeof info.uid === "bigint" ? info.uid : BigInt(info.uid);
  return info.isDirectory()
    && !info.isSymbolicLink()
    && uid === effectiveUserID
    && (mode & 0o022n) === 0n;
}

async function assertPrivateSourceParent() {
  try {
    if (sourcePath !== resolve(sourcePath)
        || sourceDirectory !== resolve(sourceDirectory)
        || leasePath !== resolve(leasePath)
        || dirname(leasePath) !== sourceDirectory) {
      throw new Error("noncanonical migration path");
    }
    const [directoryInfo, canonicalDirectory] = await Promise.all([
      lstat(sourceDirectory, { bigint: true }),
      realpath(sourceDirectory)
    ]);
    if (canonicalDirectory !== sourceDirectory || !isPrivateOwnerDirectory(directoryInfo)) {
      throw new Error("unsafe migration directory");
    }
  } catch {
    throw new Error("credential migration source directory is not a canonical owner-controlled directory");
  }
}

async function assertMigrationLease() {
  try {
    if (process.env[leaseMarkerName] !== String(leaseDescriptor)) {
      throw new Error("missing migration lease marker");
    }
    const descriptorInfo = fstatSync(leaseDescriptor, { bigint: true });
    const pathInfo = await lstat(leasePath, { bigint: true });
    if (!isRegularOwnerOnly(descriptorInfo)
        || !isRegularOwnerOnly(pathInfo)
        || descriptorInfo.size !== 0n
        || pathInfo.size !== 0n
        || descriptorInfo.dev !== pathInfo.dev
        || descriptorInfo.ino !== pathInfo.ino) {
      throw new Error("migration lease identity mismatch");
    }
  } catch {
    throw new Error("credential migration lease boundary is invalid");
  }
}

function assertMigrationLeaseSynchronously() {
  try {
    if (process.env[leaseMarkerName] !== String(leaseDescriptor)) {
      throw new Error("missing migration lease marker");
    }
    const descriptorInfo = fstatSync(leaseDescriptor, { bigint: true });
    const pathInfo = lstatSync(leasePath, { bigint: true });
    if (!isRegularOwnerOnly(descriptorInfo)
        || !isRegularOwnerOnly(pathInfo)
        || descriptorInfo.size !== 0n
        || pathInfo.size !== 0n
        || descriptorInfo.dev !== pathInfo.dev
        || descriptorInfo.ino !== pathInfo.ino) {
      throw new Error("migration lease identity mismatch");
    }
  } catch {
    throw new Error("credential migration lease boundary is invalid");
  }
}

async function readBounded(handle, maximumBytes) {
  const chunks = [];
  let offset = 0;
  while (offset <= maximumBytes) {
    const requested = Math.min(64 * 1024, maximumBytes + 1 - offset);
    const buffer = Buffer.allocUnsafe(requested);
    const { bytesRead } = await handle.read(buffer, 0, requested, offset);
    if (bytesRead === 0) break;
    chunks.push(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  if (offset > maximumBytes) throw new Error("credential source exceeds the migration size limit");
  return Buffer.concat(chunks, offset);
}

function sameSourceIdentityAndVersion(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function loadDescriptorBoundYAMLGraph() {
  try {
    if (!boundProgramInvocation
        || process.env[yamlGraphMarkerName] !== yamlGraphMarkerValue
        || yamlModulePath !== "descriptor-bound-yaml-graph") {
      throw new Error("missing descriptor-bound YAML graph marker");
    }
    const payload = process.env[yamlGraphPayloadName];
    if (typeof payload !== "string" || payload.length === 0 || payload.length > 1_048_576) {
      throw new Error("invalid descriptor-bound YAML graph payload");
    }
    const decoded = Buffer.from(payload, "base64");
    if (decoded.length === 0 || decoded.length > 8_388_608) {
      throw new Error("invalid descriptor-bound YAML graph size");
    }
    const graph = JSON.parse(decoded.toString("utf8"));
    if (typeof graph !== "object" || graph === null || Array.isArray(graph)) {
      throw new Error("invalid descriptor-bound YAML graph");
    }
    const entries = Object.entries(graph);
    if (entries.length === 0 || entries.length > 128 || !("index.js" in graph)) {
      throw new Error("incomplete descriptor-bound YAML graph");
    }
    let totalBytes = 0;
    for (const [name, source] of entries) {
      if (!/^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.js$/u.test(name)
          || name.startsWith(".")
          || typeof source !== "string") {
        throw new Error("invalid descriptor-bound YAML module");
      }
      totalBytes += Buffer.byteLength(source);
      if (totalBytes > 8_388_608) throw new Error("descriptor-bound YAML graph is too large");
    }

    const nativeRequire = createRequire(pathToFileURL(sourcePath).href);
    const cache = new Map();
    const load = (name) => {
      if (!(name in graph)) throw new Error("descriptor-bound YAML module is missing");
      if (cache.has(name)) return cache.get(name).exports;
      const module = { exports: {} };
      cache.set(name, module);
      const localRequire = (request) => {
        if (request === "process" || request === "buffer") return nativeRequire(request);
        if (typeof request !== "string" || !request.startsWith(".")) {
          throw new Error("descriptor-bound YAML module requested an unapproved dependency");
        }
        let candidate = pathPosix.normalize(pathPosix.join(pathPosix.dirname(name), request));
        if (!candidate.endsWith(".js")) candidate += ".js";
        if (candidate.startsWith("../") || pathPosix.isAbsolute(candidate)) {
          throw new Error("descriptor-bound YAML module escaped its graph");
        }
        return load(candidate);
      };
      const evaluate = new Function(
        "require",
        "module",
        "exports",
        "__filename",
        "__dirname",
        `"use strict";\n${graph[name]}\n//# sourceURL=fulmar-yaml-graph/${name}`
      );
      evaluate(localRequire, module, module.exports, name, pathPosix.dirname(name));
      return module.exports;
    };
    return load("index.js");
  } catch {
    throw new Error("descriptor-bound YAML runtime could not be admitted");
  }
}

// The lease capability and its canonical owner-controlled directory are
// proven before importing any caller-selected module or reading plaintext
// credential data. The same identity is rechecked at every helper boundary.
await assertPrivateSourceParent();
await assertMigrationLease();
const sourceHandle = await open(
  sourcePath,
  fsConstants.O_RDWR | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW
);
let sourceInfo;
let sourceBytes;
sourceInfo = await sourceHandle.stat({ bigint: true });
if (!isRegularOwnerOnly(sourceInfo)) throw new Error("credential source must be an owner-only regular file with permissions 600");
if (sourceInfo.size > BigInt(maximumSourceBytes)) throw new Error("credential source exceeds the migration size limit");
const sourcePathInfo = await lstat(sourcePath, { bigint: true });
if (!isRegularOwnerOnly(sourcePathInfo)
    || sourcePathInfo.dev !== sourceInfo.dev
    || sourcePathInfo.ino !== sourceInfo.ino) {
  throw new Error("credential source path changed before migration");
}
sourceBytes = await readBounded(sourceHandle, maximumSourceBytes);
const sourceAfterRead = await sourceHandle.stat({ bigint: true });
if (!sameSourceIdentityAndVersion(sourceInfo, sourceAfterRead)
    || sourceBytes.length !== Number(sourceInfo.size)) {
  throw new Error("credential source changed while it was read");
}
await assertMigrationLease();
const { parseDocument } = boundProgramInvocation
  ? loadDescriptorBoundYAMLGraph()
  : await import(pathToFileURL(yamlModulePath).href);

const document = parseDocument(sourceBytes.toString("utf8"), { prettyErrors: false, uniqueKeys: true });
if (document.errors.length) throw new Error("credential source is not valid YAML");
const root = document.toJS() ?? {};
if (typeof root !== "object" || root === null || Array.isArray(root)) throw new Error("credential source must be a mapping");

let refs;
let records;
if (Object.keys(root).length === 0) {
  refs = {};
  records = {};
} else if ("version" in root) {
  if (root.version !== 1) throw new Error("credential source version is unsupported");
  for (const key of Object.keys(root)) if (!["version", "refs", "records"].includes(key)) throw new Error("credential source contains an unknown section");
  refs = root.refs ?? {};
  records = root.records ?? {};
} else {
  refs = root;
  records = {};
}
if (typeof refs !== "object" || refs === null || Array.isArray(refs)) throw new Error("credential references section is invalid");
if (typeof records !== "object" || records === null || Array.isArray(records)) throw new Error("credential records section is invalid");

const entries = [];
for (const [key, value] of Object.entries(refs).sort(([left], [right]) => left.localeCompare(right))) {
  if (!refPattern.test(key) || typeof value !== "string" || value.length === 0) throw new Error("credential source contains an invalid reference");
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > maximumHelperOutputBytes) throw new Error("credential source contains an unstorable reference");
  entries.push({ subject: key, bytes, get: "get", set: "set", unset: "unset" });
}
for (const [key, value] of Object.entries(records).sort(([left], [right]) => left.localeCompare(right))) {
  if (!recordPattern.test(key) || typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("credential source contains an invalid record");
  if (value.kind !== "api-key" && value.kind !== "grant") throw new Error("credential source contains an unknown record kind");
  const encoded = JSON.stringify(value);
  if (!encoded || Buffer.byteLength(encoded) > maximumHelperOutputBytes) throw new Error("credential source contains an unstorable record");
  entries.push({ subject: key, bytes: Buffer.from(encoded), get: "get-record", set: "set-record", unset: "unset-record" });
}

async function runHelper(command, subject, input = Buffer.alloc(0)) {
  await assertMigrationLease();
  return await new Promise((resolve, reject) => {
    // Keep the check synchronous and immediately adjacent to spawn. The same
    // identity is checked again after child completion before its output is
    // admitted, so a replacement during helper work cannot authorize commit.
    assertMigrationLeaseSynchronously();
    const child = spawn(helperPath, [command, subject], {
      env: {
        HOME: process.env.HOME,
        USER: process.env.USER,
        LOGNAME: process.env.LOGNAME,
        PATH: "/usr/bin:/bin",
        ...(process.env.LOCAL_HARNESS_MIGRATION_TEST_STATE === undefined ? {} : { LOCAL_HARNESS_MIGRATION_TEST_STATE: process.env.LOCAL_HARNESS_MIGRATION_TEST_STATE }),
        ...(process.env.LOCAL_HARNESS_MIGRATION_TEST_CONTROL === undefined ? {} : { LOCAL_HARNESS_MIGRATION_TEST_CONTROL: process.env.LOCAL_HARNESS_MIGRATION_TEST_CONTROL })
      },
      stdio: ["pipe", "pipe", "pipe"]
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let exceededLimit = false;
    const collect = (chunks, chunk, current) => {
      const next = current + chunk.length;
      if (next > maximumHelperOutputBytes) {
        exceededLimit = true;
        child.kill("SIGKILL");
      } else {
        chunks.push(chunk);
      }
      return next;
    };
    child.stdout.on("data", (chunk) => { stdoutBytes = collect(stdout, chunk, stdoutBytes); });
    child.stderr.on("data", (chunk) => { stderrBytes = collect(stderr, chunk, stderrBytes); });
    child.on("error", () => reject(new Error("Keychain helper could not be started")));
    child.on("close", async (code, signal) => {
      try {
        await assertMigrationLease();
        if (exceededLimit) return reject(new Error("Keychain helper returned too much data"));
        if (signal !== null) return reject(new Error("Keychain helper terminated unexpectedly"));
        resolve({ code: code ?? 2, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
      } catch (error) {
        reject(error);
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

async function readEntry(entry) {
  const result = await runHelper(entry.get, entry.subject);
  if (result.code === 3) return undefined;
  if (result.code !== 0) throw new Error("Keychain helper rejected an entry");
  return result.stdout;
}

async function writeAndVerify(entry, bytes) {
  const written = await runHelper(entry.set, entry.subject, bytes);
  if (written.code !== 0) throw new Error("Keychain helper rejected an entry");
  const readback = await readEntry(entry);
  if (readback === undefined || !readback.equals(bytes)) throw new Error("Keychain byte-for-byte verification failed");
}

async function removeAndVerify(entry) {
  const removed = await runHelper(entry.unset, entry.subject);
  if (removed.code !== 0) throw new Error("Keychain helper rejected rollback");
  if ((await readEntry(entry)) !== undefined) throw new Error("Keychain rollback verification failed");
}

async function assertSourceUnchanged() {
  const descriptorBefore = await sourceHandle.stat({ bigint: true });
  const pathBefore = await lstat(sourcePath, { bigint: true });
  if (!isRegularOwnerOnly(descriptorBefore)
      || !isRegularOwnerOnly(pathBefore)
      || !sameSourceIdentityAndVersion(sourceInfo, descriptorBefore)
      || !sameSourceIdentityAndVersion(sourceInfo, pathBefore)) {
    throw new Error("credential source changed during migration");
  }
  const currentBytes = await readBounded(sourceHandle, maximumSourceBytes);
  const descriptorAfter = await sourceHandle.stat({ bigint: true });
  const pathAfter = await lstat(sourcePath, { bigint: true });
  if (!sameSourceIdentityAndVersion(sourceInfo, descriptorAfter)
      || !sameSourceIdentityAndVersion(sourceInfo, pathAfter)) {
    throw new Error("credential source changed during migration");
  }
  if (!currentBytes.equals(sourceBytes)) throw new Error("credential source changed during migration");
}

function runBeforeSourceScrubTestHook() {
  const controlPath = process.env.LOCAL_HARNESS_MIGRATION_TEST_CONTROL;
  if (controlPath === undefined) return;
  try {
    const control = JSON.parse(readFileSync(controlPath, "utf8"));
    if (control.replaceSourceBeforeScrub !== true) return;
    const replacement = `${sourcePath}.${process.pid}.replacement`;
    writeFileSync(replacement, "version: 1\nrefs:\n  REPLACEMENT: preserved\n", {
      flag: "wx",
      mode: 0o600
    });
    renameSync(replacement, sourcePath);
  } catch {
    throw new Error("credential migration test boundary failed");
  }
}

// Snapshot every target before making the first mutation. A migration either
// commits all exact values and removes the unchanged source, or restores every
// prior Keychain value and leaves the source in place.
const prior = new Map();
for (const entry of entries) prior.set(entry, await readEntry(entry));
const changed = [];
let committed = false;
try {
  for (const entry of entries) {
    // Treat a helper invocation as mutating even when it reports failure: a
    // crashing helper could have committed the Keychain write first.
    changed.push(entry);
    await writeAndVerify(entry, entry.bytes);
  }
  for (const entry of entries) {
    const readback = await readEntry(entry);
    if (readback === undefined || !readback.equals(entry.bytes)) throw new Error("Keychain final verification failed");
  }
  await assertSourceUnchanged();
  await assertMigrationLease();
  runBeforeSourceScrubTestHook();
  // Never unlink by path after a separate identity check: a concurrent atomic
  // writer could replace the name in that gap and lose new, unmigrated data.
  // Truncation acts on the exact descriptor opened and pinned before any
  // Keychain access. A post-truncate path proof admits success only when that
  // same inode still owns the canonical source name; replacements are kept.
  await sourceHandle.truncate(0);
  await sourceHandle.sync();
  const scrubbedDescriptor = await sourceHandle.stat({ bigint: true });
  const scrubbedPath = await lstat(sourcePath, { bigint: true });
  if (!isRegularOwnerOnly(scrubbedDescriptor)
      || !isRegularOwnerOnly(scrubbedPath)
      || scrubbedDescriptor.dev !== sourceInfo.dev
      || scrubbedDescriptor.ino !== sourceInfo.ino
      || scrubbedDescriptor.size !== 0n
      || scrubbedPath.dev !== scrubbedDescriptor.dev
      || scrubbedPath.ino !== scrubbedDescriptor.ino
      || scrubbedPath.size !== 0n) {
    throw new Error("credential source path changed before its exact descriptor was scrubbed");
  }
  committed = true;
} catch (error) {
  const rollbackErrors = [];
  for (const entry of changed.reverse()) {
    try {
      const previous = prior.get(entry);
      if (previous === undefined) await removeAndVerify(entry);
      else await writeAndVerify(entry, previous);
    } catch (rollbackError) {
      rollbackErrors.push(rollbackError);
    }
  }
  if (rollbackErrors.length > 0) throw new Error("credential migration failed and Keychain rollback was incomplete; the plaintext source was preserved", { cause: error });
  throw new Error("credential migration failed; Keychain changes were rolled back and the plaintext source was preserved", { cause: error });
}

if (!committed) throw new Error("credential migration did not commit");
await sourceHandle.close();
process.stdout.write(JSON.stringify({ references: Object.keys(refs).length, records: Object.keys(records).length }));
