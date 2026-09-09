#!/usr/bin/env node

import { constants as fsConstants, createReadStream } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  realpath
} from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";
import { publishAttestedRegularFileSync, readAttestedRegularFile } from "./attested-regular-file.mjs";

export const NATIVE_PRODUCTS = Object.freeze([
  Object.freeze({
    name: "LocalHarness",
    bundlePath: "Contents/MacOS/LocalHarness"
  }),
  Object.freeze({
    name: "LocalHarnessCredentialHelper",
    bundlePath: "Contents/MacOS/LocalHarnessCredentialHelper"
  }),
  Object.freeze({
    name: "LocalHarnessCredentialBrokerService",
    bundlePath: "Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/MacOS/LocalHarnessCredentialBrokerService"
  }),
  Object.freeze({
    name: "LocalHarnessCredentialMigrationService",
    bundlePath: "Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService"
  }),
  Object.freeze({
    name: "LocalHarnessRuntimeLease",
    bundlePath: "Contents/MacOS/LocalHarnessRuntimeLease"
  }),
  Object.freeze({
    name: "LocalHarnessSandboxRunner",
    bundlePath: "Contents/MacOS/LocalHarnessSandboxRunner"
  }),
  Object.freeze({
    name: "LocalHarnessSchedulerHelper",
    bundlePath: "Contents/MacOS/LocalHarnessSchedulerHelper"
  }),
  Object.freeze({
    name: "LocalHarnessUpdateHelper",
    bundlePath: "Contents/MacOS/LocalHarnessUpdateHelper"
  })
]);

const TREE_LIMITS = Object.freeze({
  maximumEntries: 100_000,
  maximumDepth: 96,
  maximumPathBytes: 4_096,
  maximumSymlinkTargetBytes: 65_536,
  maximumFileBytes: 2n * 1_024n * 1_024n * 1_024n,
  maximumAggregateBytes: 4n * 1_024n * 1_024n * 1_024n,
  maximumInventoryBytes: 64 * 1_024 * 1_024
});

const INVALID_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function fail(message) {
  throw new Error(`Unsigned reproducibility verification failed: ${message}`);
}

function compareNames(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function pathIsInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === ""
    || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function decodeName(rawName) {
  let name;
  try {
    name = UTF8_DECODER.decode(rawName);
  } catch {
    fail("a tree entry name is not valid UTF-8");
  }
  if (!name || name === "." || name === ".." || name.includes("/")
      || name.includes("\\") || INVALID_TEXT.test(name)) {
    fail("a tree entry name is unsafe");
  }
  return name;
}

function safeRelativePath(components) {
  const relativePath = components.length === 0 ? "." : components.join("/");
  if (path.posix.isAbsolute(relativePath)
      || components.some((component) => !component || component === "." || component === "..")
      || Buffer.byteLength(relativePath, "utf8") > TREE_LIMITS.maximumPathBytes) {
    fail("a tree entry path is unsafe or oversized");
  }
  return relativePath;
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.uid === right.uid
    && left.gid === right.gid
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function requireOwnerControlled(info, label, { ignoreWriteBits = false } = {}) {
  const effectiveUID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : info.uid;
  if (info.uid !== effectiveUID || (!ignoreWriteBits && (info.mode & 0o022n) !== 0n)) {
    fail(`${label} is not owner-controlled`);
  }
}

async function hashRegularFile(absolutePath, expected, state) {
  if (expected.size < 0n || expected.size > TREE_LIMITS.maximumFileBytes) {
    fail("a captured regular file exceeds its byte limit");
  }
  if (state.aggregateBytes + expected.size > TREE_LIMITS.maximumAggregateBytes) {
    fail("a captured tree exceeds its aggregate-byte limit");
  }
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    fail("the host does not expose O_NOFOLLOW");
  }

  let handle;
  try {
    handle = await open(absolutePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(expected, opened)) {
      fail("a captured regular file changed identity before hashing");
    }
    requireOwnerControlled(opened, "a captured regular file");

    const digest = createHash("sha256");
    let bytesRead = 0n;
    const stream = createReadStream(absolutePath, {
      fd: handle.fd,
      autoClose: false,
      highWaterMark: 1024 * 1024
    });
    for await (const chunk of stream) {
      bytesRead += BigInt(chunk.length);
      if (bytesRead > opened.size) {
        stream.destroy();
        fail("a captured regular file grew while hashing");
      }
      digest.update(chunk);
    }
    const finished = await handle.stat({ bigint: true });
    if (bytesRead !== opened.size || !sameIdentity(opened, finished)) {
      fail("a captured regular file changed while hashing");
    }
    state.aggregateBytes += bytesRead;
    return { bytes: Number(bytesRead), sha256: digest.digest("hex") };
  } finally {
    await handle?.close().catch(() => {});
  }
}

function addEntry(state, entry) {
  state.entries.push(entry);
  if (state.entries.length > TREE_LIMITS.maximumEntries) {
    fail("a captured tree exceeds its entry limit");
  }
}

async function visit(root, absolutePath, components, depth, state) {
  if (depth > TREE_LIMITS.maximumDepth || !pathIsInside(root, absolutePath)) {
    fail("a captured tree exceeds its depth or containment limit");
  }
  const relativePath = safeRelativePath(components);
  const normalizedIdentity = relativePath.normalize("NFC").toLocaleLowerCase("en-US");
  if (state.identities.has(normalizedIdentity)) {
    fail(`a captured tree contains a case- or normalization-colliding path: ${relativePath}`);
  }
  state.identities.add(normalizedIdentity);

  const before = await lstat(absolutePath, { bigint: true })
    .catch(() => fail(`could not inspect captured path: ${relativePath}`));
  const mode = Number(before.mode & 0o7777n);

  if (before.isFile()) {
    requireOwnerControlled(before, `captured path ${relativePath}`);
    if (before.nlink !== 1n) fail(`captured file is hard linked: ${relativePath}`);
    const descriptor = await hashRegularFile(absolutePath, before, state);
    addEntry(state, { path: relativePath, type: "file", mode, ...descriptor });
    return;
  }

  if (before.isSymbolicLink()) {
    // Darwin symbolic-link mode bits are conventionally 0777 and do not grant
    // mutation through an owner-controlled parent. Bind ownership, entry type,
    // exact link target and lexical containment instead.
    requireOwnerControlled(before, `captured path ${relativePath}`, { ignoreWriteBits: true });
    let target;
    try {
      target = UTF8_DECODER.decode(await readlink(absolutePath, { encoding: "buffer" }));
    } catch {
      fail(`could not read captured symbolic link: ${relativePath}`);
    }
    if (!target || path.isAbsolute(target) || INVALID_TEXT.test(target)
        || Buffer.byteLength(target, "utf8") > TREE_LIMITS.maximumSymlinkTargetBytes) {
      fail(`captured symbolic link is unsafe: ${relativePath}`);
    }
    const resolvedTarget = path.resolve(path.dirname(absolutePath), target);
    if (!pathIsInside(root, resolvedTarget)) {
      fail(`captured symbolic link escapes its tree: ${relativePath}`);
    }
    const after = await lstat(absolutePath, { bigint: true })
      .catch(() => fail(`captured symbolic link disappeared: ${relativePath}`));
    if (!after.isSymbolicLink() || !sameIdentity(before, after)) {
      fail(`captured symbolic link changed while reading: ${relativePath}`);
    }
    addEntry(state, { path: relativePath, type: "symlink", mode, target });
    return;
  }

  if (!before.isDirectory()) fail(`captured tree contains a special file: ${relativePath}`);
  requireOwnerControlled(before, `captured path ${relativePath}`);
  addEntry(state, { path: relativePath, type: "directory", mode });
  const children = await readdir(absolutePath, { encoding: "buffer" })
    .catch(() => fail(`could not enumerate captured directory: ${relativePath}`));
  children.sort(Buffer.compare);
  for (const rawName of children) {
    const name = decodeName(rawName);
    await visit(root, path.join(absolutePath, name), [...components, name], depth + 1, state);
  }
  const after = await lstat(absolutePath, { bigint: true })
    .catch(() => fail(`captured directory disappeared: ${relativePath}`));
  if (!after.isDirectory() || !sameIdentity(before, after)) {
    fail(`captured directory changed while enumerating: ${relativePath}`);
  }
}

export async function inventoryTree(rootArgument) {
  const root = path.resolve(rootArgument);
  const rootInfo = await lstat(root, { bigint: true })
    .catch(() => fail("a required capture tree is missing"));
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    fail("a required capture tree is not a real directory");
  }
  requireOwnerControlled(rootInfo, "capture tree root");
  const canonical = await realpath(root);
  if (canonical !== root) fail("a capture tree root is not canonical");

  const state = { entries: [], identities: new Set(), aggregateBytes: 0n };
  await visit(root, root, [], 0, state);
  state.entries.sort((left, right) => compareNames(left.path, right.path));
  const payload = Buffer.from(`${JSON.stringify(state.entries)}\n`, "utf8");
  return {
    entries: state.entries,
    totals: {
      entries: state.entries.length,
      fileBytes: Number(state.aggregateBytes)
    },
    inventorySHA256: createHash("sha256").update(payload).digest("hex")
  };
}

function entryMap(tree) {
  return new Map(tree.entries.map((entry) => [entry.path, entry]));
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expected) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validateInventoryTree(tree, label) {
  if (!hasExactKeys(tree, ["entries", "totals", "inventorySHA256"])
      || !Array.isArray(tree.entries) || tree.entries.length < 1
      || tree.entries.length > TREE_LIMITS.maximumEntries
      || !hasExactKeys(tree.totals, ["entries", "fileBytes"])
      || tree.totals.entries !== tree.entries.length
      || !Number.isSafeInteger(tree.totals.fileBytes) || tree.totals.fileBytes < 0
      || typeof tree.inventorySHA256 !== "string"
      || !/^[a-f0-9]{64}$/u.test(tree.inventorySHA256)) {
    fail(`${label} inventory schema is malformed`);
  }
  let previous;
  let fileBytes = 0;
  const identities = new Set();
  for (const entry of tree.entries) {
    const common = isPlainObject(entry)
      && typeof entry.path === "string"
      && typeof entry.type === "string"
      && Number.isInteger(entry.mode) && entry.mode >= 0 && entry.mode <= 0o7777;
    if (!common) fail(`${label} contains a malformed entry`);
    const components = entry.path === "." ? [] : entry.path.split("/");
    if (safeRelativePath(components) !== entry.path) fail(`${label} contains an unsafe path`);
    if (previous !== undefined && compareNames(previous, entry.path) >= 0) {
      fail(`${label} paths are duplicated or not canonically sorted`);
    }
    previous = entry.path;
    const identity = entry.path.normalize("NFC").toLocaleLowerCase("en-US");
    if (identities.has(identity)) fail(`${label} contains a path-identity collision`);
    identities.add(identity);

    if (entry.type === "directory") {
      if (!hasExactKeys(entry, ["path", "type", "mode"])) {
        fail(`${label} contains a malformed directory entry`);
      }
    } else if (entry.type === "file") {
      if (!hasExactKeys(entry, ["path", "type", "mode", "bytes", "sha256"])
          || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0
          || entry.bytes > Number(TREE_LIMITS.maximumFileBytes)
          || typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(entry.sha256)) {
        fail(`${label} contains a malformed file entry`);
      }
      fileBytes += entry.bytes;
      if (!Number.isSafeInteger(fileBytes)
          || fileBytes > Number(TREE_LIMITS.maximumAggregateBytes)) {
        fail(`${label} exceeds its aggregate-byte limit`);
      }
    } else if (entry.type === "symlink") {
      if (!hasExactKeys(entry, ["path", "type", "mode", "target"])
          || typeof entry.target !== "string" || !entry.target
          || path.posix.isAbsolute(entry.target) || INVALID_TEXT.test(entry.target)
          || Buffer.byteLength(entry.target, "utf8") > TREE_LIMITS.maximumSymlinkTargetBytes) {
        fail(`${label} contains a malformed symbolic-link entry`);
      }
      const linkParent = entry.path === "." ? "." : path.posix.dirname(entry.path);
      const resolved = path.posix.normalize(path.posix.join(linkParent, entry.target));
      if (resolved === ".." || resolved.startsWith("../") || path.posix.isAbsolute(resolved)) {
        fail(`${label} contains an escaping symbolic-link entry`);
      }
    } else {
      fail(`${label} contains an unsupported entry type`);
    }
  }
  if (tree.entries[0].path !== "." || tree.entries[0].type !== "directory"
      || fileBytes !== tree.totals.fileBytes) {
    fail(`${label} totals or root entry are malformed`);
  }
  const digest = createHash("sha256")
    .update(Buffer.from(`${JSON.stringify(tree.entries)}\n`, "utf8"))
    .digest("hex");
  if (digest !== tree.inventorySHA256) fail(`${label} digest does not match its entries`);
}

function validateCaptureTopology(capture) {
  if (!hasExactKeys(capture, ["schemaVersion", "profile", "nativeProductCount", "trees"])
      || capture.schemaVersion !== 1 || capture.profile !== "fulmar-pre-sign-two-root-v1"
      || capture.nativeProductCount !== NATIVE_PRODUCTS.length
      || !hasExactKeys(capture.trees, ["compilerProducts", "symbols", "appBundle"])) {
    fail("a capture inventory schema is unsupported or malformed");
  }
  validateInventoryTree(capture.trees.compilerProducts, "compilerProducts");
  validateInventoryTree(capture.trees.symbols, "symbols");
  validateInventoryTree(capture.trees.appBundle, "appBundle");
  const compilerEntries = entryMap(capture.trees.compilerProducts);
  const symbolEntries = entryMap(capture.trees.symbols);
  const appEntries = entryMap(capture.trees.appBundle);
  const compilerTopLevel = capture.trees.compilerProducts.entries
    .filter((entry) => entry.path !== "." && !entry.path.includes("/"));
  const symbolTopLevel = capture.trees.symbols.entries
    .filter((entry) => entry.path !== "." && !entry.path.includes("/"));
  if (compilerTopLevel.length !== NATIVE_PRODUCTS.length
      || symbolTopLevel.length !== NATIVE_PRODUCTS.length) {
    fail("a capture does not contain exactly eight compiler products and eight dSYM bundles");
  }

  for (const product of NATIVE_PRODUCTS) {
    const compiler = compilerEntries.get(product.name);
    const symbol = symbolEntries.get(`${product.name}.dSYM`);
    const bundled = appEntries.get(product.bundlePath);
    if (compiler?.type !== "file" || (compiler.mode & 0o111) === 0
        || symbol?.type !== "directory"
        || bundled?.type !== "file" || (bundled.mode & 0o111) === 0) {
      fail(`a capture is missing the exact executable/dSYM topology for ${product.name}`);
    }
  }
  for (const forbidden of [
    "Contents/_CodeSignature",
    "Contents/CodeResources",
    "Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/_CodeSignature",
    "Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/_CodeSignature"
  ]) {
    if (appEntries.has(forbidden)) fail(`a capture has already entered Fulmar signing: ${forbidden}`);
  }
}

export async function captureUnsignedBuild(captureRootArgument) {
  const captureRoot = path.resolve(captureRootArgument);
  const [compilerProducts, symbols, appBundle] = await Promise.all([
    inventoryTree(path.join(captureRoot, "CompilerProducts")),
    inventoryTree(path.join(captureRoot, "Fulmar.dSYMs")),
    inventoryTree(path.join(captureRoot, "Fulmar.app"))
  ]);
  const capture = {
    schemaVersion: 1,
    profile: "fulmar-pre-sign-two-root-v1",
    nativeProductCount: NATIVE_PRODUCTS.length,
    trees: { compilerProducts, symbols, appBundle }
  };
  validateCaptureTopology(capture);
  return capture;
}

function firstTreeDifference(left, right) {
  if (left.entries.length !== right.entries.length) {
    return `entry count ${left.entries.length} != ${right.entries.length}`;
  }
  for (let index = 0; index < left.entries.length; index += 1) {
    if (JSON.stringify(left.entries[index]) !== JSON.stringify(right.entries[index])) {
      return left.entries[index]?.path ?? right.entries[index]?.path ?? `entry ${index}`;
    }
  }
  if (JSON.stringify(left.totals) !== JSON.stringify(right.totals)
      || left.inventorySHA256 !== right.inventorySHA256) {
    return "tree summary";
  }
  return undefined;
}

export function compareUnsignedBuildCaptures(left, right, sourceIdentity = undefined) {
  validateCaptureTopology(left);
  validateCaptureTopology(right);
  for (const section of ["compilerProducts", "symbols", "appBundle"]) {
    const difference = firstTreeDifference(left.trees[section], right.trees[section]);
    if (difference !== undefined) fail(`${section} differs at ${difference}`);
  }
  const sections = {};
  for (const section of ["compilerProducts", "symbols", "appBundle"]) {
    sections[section] = {
      entries: left.trees[section].totals.entries,
      fileBytes: left.trees[section].totals.fileBytes,
      inventorySHA256: left.trees[section].inventorySHA256
    };
  }
  const aggregateSHA256 = createHash("sha256")
    .update(`${sections.compilerProducts.inventorySHA256}\n`)
    .update(`${sections.symbols.inventorySHA256}\n`)
    .update(`${sections.appBundle.inventorySHA256}\n`)
    .digest("hex");
  const result = {
    schemaVersion: 1,
    profile: "fulmar-pre-sign-two-root-v1",
    result: "passed",
    nativeProductCount: NATIVE_PRODUCTS.length,
    sections,
    aggregateSHA256
  };
  if (sourceIdentity !== undefined) {
    const { commit, tree } = sourceIdentity;
    if (typeof commit !== "string" || commit.length !== 40 || /[^a-f0-9]/u.test(commit)
        || typeof tree !== "string" || tree.length !== 40 || /[^a-f0-9]/u.test(tree)) {
      fail("the source commit identity is malformed");
    }
    result.source = { commit, tree };
  }
  return result;
}

async function writeCanonical(destinationArgument, value) {
  const destination = path.resolve(destinationArgument);
  const parent = path.dirname(destination);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const payload = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  if (payload.length > TREE_LIMITS.maximumInventoryBytes) {
    fail("reproducibility evidence exceeds its byte limit");
  }
  // The isolated synchronous worker safely creates or descriptor-rewrites the
  // persistent comparison evidence inside the already-attested directory vnode.
  try {
    publishAttestedRegularFileSync(parent, path.basename(destination), payload, {
      label: "reproducibility evidence directory",
      publishMode: "upsert",
      fileMode: 0o600,
      maximumBytes: TREE_LIMITS.maximumInventoryBytes,
      requireCurrentUser: true,
      requireOwnerControlledMode: true,
      requireCanonicalPath: true
    });
  } catch (error) {
    if (/not owned by the current user|group- or world-writable/u.test(error?.message ?? "")) {
      fail("reproducibility evidence directory is not owner-controlled");
    }
    if (/canonical|symbolic|ELOOP|ENOTDIR|not one directory/iu.test(error?.message ?? "")) {
      fail("the reproducibility evidence directory is not a canonical real directory");
    }
    throw error;
  }
}

async function readBoundedCapture(sourceArgument) {
  const source = path.resolve(sourceArgument);
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) fail("the host does not expose O_NOFOLLOW");
  // Open-first through the attested reader: the no-follow descriptor's own
  // metadata is the reviewed shape (owner-controlled, single link, bounded)
  // and the pathname is re-attested before and after the bytes are read.
  let input;
  try {
    input = await readAttestedRegularFile(source, {
      label: "reproducibility inventory",
      minimumBytes: 1,
      maximumBytes: TREE_LIMITS.maximumInventoryBytes,
      requireCurrentUser: true,
      requireOwnerControlledMode: true,
      requireSingleLink: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    if (/not owned by the current user|group- or world-writable/u.test(error?.message ?? "")) {
      fail("reproducibility inventory is not owner-controlled");
    }
    fail("a reproducibility inventory is not a bounded single-link regular file");
  }
  return JSON.parse(UTF8_DECODER.decode(input.bytes));
}

async function runCLI() {
  const [command, ...argumentsList] = process.argv.slice(2);
  if (command === "emit-products" && argumentsList.length === 0) {
    process.stdout.write(`${NATIVE_PRODUCTS.map(({ name }) => name).join("\n")}\n`);
    return;
  }
  if (command === "create" && argumentsList.length === 2) {
    await writeCanonical(argumentsList[1], await captureUnsignedBuild(argumentsList[0]));
    return;
  }
  if (command === "compare-inventories" && argumentsList.length === 5) {
    const [left, right] = await Promise.all([
      readBoundedCapture(argumentsList[0]),
      readBoundedCapture(argumentsList[1])
    ]);
    const summary = compareUnsignedBuildCaptures(left, right, {
      commit: argumentsList[2],
      tree: argumentsList[3]
    });
    await writeCanonical(argumentsList[4], summary);
    process.stdout.write(
      `Verified ${summary.nativeProductCount} compiler products, ${summary.nativeProductCount} dSYMs, `
      + `${summary.sections.appBundle.entries} pre-sign app entries, and exact byte/mode/type/link-target equality.\n`
    );
    return;
  }
  fail("usage: unsigned-reproducibility-inventory.mjs emit-products | create <capture-root> <inventory> | compare-inventories <left> <right> <source-commit> <source-tree> <summary>");
}

const isMain = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  runCLI().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
