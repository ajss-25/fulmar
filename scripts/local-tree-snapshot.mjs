#!/usr/bin/env node

import { constants as fsConstants, createReadStream } from "node:fs";
import { lstat, open, readlink, readdir, realpath, rename, rm } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

const DEFAULT_LIMITS = Object.freeze({
  maxEntries: 250_000,
  maxDepth: 128,
  maxPathBytes: 4_096,
  maxSymlinkTargetBytes: 65_536,
  maxFileBytes: 64n * 1024n * 1024n * 1024n,
  maxTotalFileBytes: 256n * 1024n * 1024n * 1024n,
  maxMetadataBytes: 256n * 1024n * 1024n
});

const INVALID_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

export class LocalTreeSnapshotError extends Error {
  constructor(code) {
    super("Local tree snapshot rejected.");
    this.name = "LocalTreeSnapshotError";
    this.code = code;
  }
}

function reject(code) {
  throw new LocalTreeSnapshotError(code);
}

function boundedInteger(value, fallback, code) {
  const candidate = value ?? fallback;
  if (!Number.isSafeInteger(candidate) || candidate < 1) reject(code);
  return candidate;
}

function boundedBigInt(value, fallback, code) {
  const candidate = value ?? fallback;
  if (typeof candidate !== "bigint" || candidate < 1n) reject(code);
  return candidate;
}

function normalizedLimits(options = {}) {
  return {
    maxEntries: boundedInteger(options.maxEntries, DEFAULT_LIMITS.maxEntries, "INVALID_LIMIT"),
    maxDepth: boundedInteger(options.maxDepth, DEFAULT_LIMITS.maxDepth, "INVALID_LIMIT"),
    maxPathBytes: boundedInteger(options.maxPathBytes, DEFAULT_LIMITS.maxPathBytes, "INVALID_LIMIT"),
    maxSymlinkTargetBytes: boundedInteger(
      options.maxSymlinkTargetBytes,
      DEFAULT_LIMITS.maxSymlinkTargetBytes,
      "INVALID_LIMIT"
    ),
    maxFileBytes: boundedBigInt(options.maxFileBytes, DEFAULT_LIMITS.maxFileBytes, "INVALID_LIMIT"),
    maxTotalFileBytes: boundedBigInt(
      options.maxTotalFileBytes,
      DEFAULT_LIMITS.maxTotalFileBytes,
      "INVALID_LIMIT"
    ),
    maxMetadataBytes: boundedBigInt(
      options.maxMetadataBytes,
      DEFAULT_LIMITS.maxMetadataBytes,
      "INVALID_LIMIT"
    )
  };
}

function decodeComponent(rawName) {
  let name;
  try {
    name = UTF8_DECODER.decode(rawName);
  } catch {
    reject("INVALID_PATH");
  }
  if (
    name.length === 0
    || name === "."
    || name === ".."
    || name.includes("/")
    || name.includes("\\")
    || INVALID_TEXT.test(name)
  ) {
    reject("INVALID_PATH");
  }
  return name;
}

function validateRelativePath(components, limits) {
  if (components.some((component) => component === "." || component === "..")) reject("PATH_TRAVERSAL");
  const relativePath = components.length === 0 ? "." : components.join("/");
  if (path.posix.isAbsolute(relativePath) || relativePath.startsWith("../") || relativePath.includes("/../")) {
    reject("PATH_TRAVERSAL");
  }
  if (Buffer.byteLength(relativePath, "utf8") > limits.maxPathBytes) reject("PATH_LIMIT");
  return relativePath;
}

function pathIsInside(rootPath, candidatePath) {
  const relative = path.relative(rootPath, candidatePath);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function metadataFor(relativePath, type, info) {
  return {
    path: relativePath,
    type,
    mode: Number(info.mode & 0o7777n),
    uid: info.uid.toString(),
    gid: info.gid.toString(),
    size: info.size.toString(),
    mtimeNs: info.mtimeNs.toString()
  };
}

function sameIdentityAndMetadata(left, right) {
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

async function digestRegularFile(absolutePath, expected, limits, state) {
  if (expected.size > limits.maxFileBytes) reject("FILE_SIZE_LIMIT");
  if (state.totalFileBytes + expected.size > limits.maxTotalFileBytes) reject("TOTAL_SIZE_LIMIT");

  let handle;
  try {
    if (!Number.isInteger(fsConstants.O_NOFOLLOW)) reject("UNSUPPORTED_PLATFORM");
    handle = await open(absolutePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentityAndMetadata(expected, opened)) reject("TREE_MUTATED");

    const hasher = createHash("sha256");
    let bytesRead = 0n;
    const stream = createReadStream(absolutePath, {
      fd: handle.fd,
      autoClose: false,
      highWaterMark: 1024 * 1024
    });
    for await (const chunk of stream) {
      bytesRead += BigInt(chunk.length);
      if (bytesRead > expected.size || state.totalFileBytes + bytesRead > limits.maxTotalFileBytes) {
        stream.destroy();
        reject("TOTAL_SIZE_LIMIT");
      }
      hasher.update(chunk);
    }

    const finished = await handle.stat({ bigint: true });
    if (bytesRead !== expected.size || !sameIdentityAndMetadata(opened, finished)) reject("TREE_MUTATED");
    state.totalFileBytes += bytesRead;
    return hasher.digest("hex");
  } catch (error) {
    if (error instanceof LocalTreeSnapshotError) throw error;
    reject("FILE_READ_FAILED");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function accountForEntry(entry, limits, state) {
  state.entryCount += 1;
  if (state.entryCount > limits.maxEntries) reject("ENTRY_LIMIT");
  const serializedBytes = BigInt(Buffer.byteLength(JSON.stringify(entry), "utf8") + 1);
  state.metadataBytes += serializedBytes;
  if (state.metadataBytes > limits.maxMetadataBytes) reject("METADATA_LIMIT");
  state.entries.push(entry);
}

async function visit(absolutePath, components, depth, limits, state) {
  if (depth > limits.maxDepth) reject("DEPTH_LIMIT");
  if (state.entryCount >= limits.maxEntries) reject("ENTRY_LIMIT");
  const relativePath = validateRelativePath(components, limits);
  if (!pathIsInside(state.absoluteRoot, absolutePath)) reject("PATH_TRAVERSAL");

  let before;
  try {
    before = await lstat(absolutePath, { bigint: true });
  } catch {
    reject("TREE_READ_FAILED");
  }

  if (before.isFile()) {
    const entry = metadataFor(relativePath, "file", before);
    entry.sha256 = await digestRegularFile(absolutePath, before, limits, state);
    accountForEntry(entry, limits, state);
    return;
  }

  if (before.isSymbolicLink()) {
    let target;
    try {
      target = UTF8_DECODER.decode(await readlink(absolutePath, { encoding: "buffer" }));
    } catch {
      reject("TREE_READ_FAILED");
    }
    if (INVALID_TEXT.test(target)) reject("INVALID_SYMLINK");
    if (Buffer.byteLength(target, "utf8") > limits.maxSymlinkTargetBytes) reject("SYMLINK_LIMIT");
    const after = await lstat(absolutePath, { bigint: true }).catch(() => reject("TREE_MUTATED"));
    if (!after.isSymbolicLink() || !sameIdentityAndMetadata(before, after)) reject("TREE_MUTATED");
    const entry = metadataFor(relativePath, "symlink", before);
    entry.target = target;
    accountForEntry(entry, limits, state);
    return;
  }

  if (!before.isDirectory()) reject("SPECIAL_FILE");

  accountForEntry(metadataFor(relativePath, "directory", before), limits, state);
  let names;
  try {
    names = await readdir(absolutePath, { encoding: "buffer" });
  } catch {
    reject("TREE_READ_FAILED");
  }
  names.sort(Buffer.compare);
  for (const rawName of names) {
    const name = decodeComponent(rawName);
    await visit(path.join(absolutePath, name), [...components, name], depth + 1, limits, state);
  }

  const after = await lstat(absolutePath, { bigint: true }).catch(() => reject("TREE_MUTATED"));
  if (!after.isDirectory() || !sameIdentityAndMetadata(before, after)) reject("TREE_MUTATED");
}

export async function snapshotLocalTree(rootPath, options = {}) {
  if (typeof rootPath !== "string" || rootPath.length === 0 || INVALID_TEXT.test(rootPath)) {
    reject("INVALID_ROOT");
  }
  const limits = normalizedLimits(options);
  const absoluteRoot = path.resolve(rootPath);
  const rootInfo = await lstat(absoluteRoot, { bigint: true }).catch(() => reject("INVALID_ROOT"));
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) reject("INVALID_ROOT");

  const state = {
    absoluteRoot,
    entries: [],
    entryCount: 0,
    totalFileBytes: 0n,
    metadataBytes: 0n
  };
  await visit(absoluteRoot, [], 0, limits, state);
  return Buffer.from(`${JSON.stringify({ schemaVersion: 1, entries: state.entries })}\n`, "utf8");
}

export async function writeLocalTreeSnapshot(rootPath, outputPath, options = {}) {
  if (typeof outputPath !== "string" || outputPath.length === 0 || INVALID_TEXT.test(outputPath)) {
    reject("INVALID_OUTPUT");
  }
  const absoluteRoot = path.resolve(rootPath);
  const absoluteOutput = path.resolve(outputPath);
  const outputDirectory = path.dirname(absoluteOutput);
  const outputDirectoryInfo = await lstat(outputDirectory, { bigint: true }).catch(() => reject("INVALID_OUTPUT"));
  if (!outputDirectoryInfo.isDirectory() || outputDirectoryInfo.isSymbolicLink()) reject("INVALID_OUTPUT");
  const [canonicalRoot, canonicalOutputDirectory] = await Promise.all([
    realpath(absoluteRoot).catch(() => reject("INVALID_ROOT")),
    realpath(outputDirectory).catch(() => reject("INVALID_OUTPUT"))
  ]);
  if (pathIsInside(canonicalRoot, path.join(canonicalOutputDirectory, path.basename(absoluteOutput)))) {
    reject("OUTPUT_INSIDE_ROOT");
  }

  const snapshot = await snapshotLocalTree(absoluteRoot, options);
  const temporaryOutput = path.join(outputDirectory, `.${path.basename(absoluteOutput)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporaryOutput, "wx", 0o600);
    await handle.writeFile(snapshot);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryOutput, absoluteOutput);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporaryOutput, { force: true }).catch(() => {});
    if (error instanceof LocalTreeSnapshotError) throw error;
    reject("OUTPUT_WRITE_FAILED");
  }
}

async function runCLI() {
  if (process.argv.length !== 4) reject("INVALID_ARGUMENTS");
  await writeLocalTreeSnapshot(process.argv[2], process.argv[3]);
}

const isMain = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
  runCLI().catch(() => {
    process.stderr.write("Local tree snapshot failed.\n");
    process.exitCode = 1;
  });
}
