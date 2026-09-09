#!/usr/bin/env node

import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readSync,
  writeSync
} from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const stableDirectoryFields = Object.freeze(["dev", "ino", "mode", "uid", "gid"]);
const maximumWorkerPayloadBytes = 64 * 1024 * 1024;

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${label} has an unexpected schema`);
  }
}

function safeLeaf(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128
      || value === "." || value === ".." || basename(value) !== value
      || value.includes("/") || value.includes("\\")
      || /[\u0000-\u001f\u007f]/u.test(value)
      || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)) {
    throw new Error(`${label} is not one bounded safe leaf name`);
  }
  return value;
}

function safeLabel(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 160
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error("publication label is not one bounded display value");
  }
  return value;
}

function safeInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} is not one bounded non-negative integer`);
  }
  return value;
}

function parseIdentity(value, label) {
  exactKeys(value, stableDirectoryFields, label);
  return Object.freeze(Object.fromEntries(stableDirectoryFields.map((field) => {
    const raw = value[field];
    if (typeof raw !== "string" || !/^(?:0|[1-9][0-9]{0,39})$/u.test(raw)) {
      throw new Error(`${label} ${field} is malformed`);
    }
    return [field, BigInt(raw)];
  })));
}

function parseSpecification(value) {
  exactKeys(value, [
    "schemaVersion", "canonicalDirectory", "destinationLeaf", "publishMode",
    "fileMode", "maximumBytes", "label", "directoryIdentity"
  ], "publication specification");
  if (value.schemaVersion !== 1) throw new Error("publication specification schema is unsupported");
  const canonicalDirectory = resolve(value.canonicalDirectory);
  if (canonicalDirectory !== value.canonicalDirectory) {
    throw new Error("publication directory is not one absolute normalized path");
  }
  const publishMode = value.publishMode;
  if (publishMode !== "create" && publishMode !== "upsert") {
    throw new Error("publication mode is unsupported");
  }
  const fileMode = safeInteger(value.fileMode, "publication file mode", 0o777);
  if ((fileMode & 0o022) !== 0) throw new Error("publication file mode is not owner-controlled");
  const maximumBytes = safeInteger(value.maximumBytes, "publication byte limit", maximumWorkerPayloadBytes);
  if (maximumBytes < 1) throw new Error("publication byte limit must be positive");
  return Object.freeze({
    schemaVersion: 1,
    canonicalDirectory,
    destinationLeaf: safeLeaf(value.destinationLeaf, "publication destination"),
    publishMode,
    fileMode,
    maximumBytes,
    label: safeLabel(value.label),
    directoryIdentity: parseIdentity(value.directoryIdentity, "publication directory identity")
  });
}

function sameStableDirectoryIdentity(left, right) {
  return stableDirectoryFields.every((field) => left[field] === right[field]);
}

function sameFileObject(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function validateDirectory(details, expected, label) {
  if (!details.isDirectory() || details.nlink < 1n || !sameStableDirectoryIdentity(details, expected)) {
    throw new Error(`${label} is not the exact reviewed publication directory`);
  }
}

function validateExistingDestination(details, specification) {
  if (!details.isFile() || details.nlink !== 1n
      || details.uid !== specification.directoryIdentity.uid
      || (details.mode & 0o022n) !== 0n
      || details.size < 0n || details.size > BigInt(specification.maximumBytes)) {
    throw new Error(`${specification.label} existing destination is unsafe for descriptor-bound upsert`);
  }
}

function validatePublishedFile(details, payload, specification, identity) {
  if (!details.isFile() || details.nlink !== 1n || !sameFileObject(details, identity)
      || details.uid !== identity.uid || details.gid !== identity.gid
      || details.size !== BigInt(payload.length)
      || (details.mode & 0o777n) !== BigInt(specification.fileMode)) {
    throw new Error(`${specification.label} is not the exact publication file`);
  }
}

function invokeHook(hook, context, label) {
  if (hook === undefined) return;
  if (typeof hook !== "function" || hook.constructor?.name === "AsyncFunction") {
    throw new Error(`${label} must be synchronous`);
  }
  const result = hook(context);
  if (result && typeof result.then === "function") throw new Error(`${label} must not return a promise`);
}

function verifyDescriptorBytes(descriptor, payload, identity, specification) {
  const actual = Buffer.allocUnsafe(payload.length);
  let offset = 0;
  while (offset < actual.length) {
    const bytesRead = readSync(descriptor, actual, offset, actual.length - offset, offset);
    if (bytesRead <= 0) throw new Error(`${specification.label} ended before its published size`);
    offset += bytesRead;
  }
  const trailing = Buffer.allocUnsafe(1);
  if (readSync(descriptor, trailing, 0, 1, payload.length) !== 0 || !actual.equals(payload)) {
    throw new Error(`${specification.label} has unexpected published bytes`);
  }
  validatePublishedFile(fstatSync(descriptor, { bigint: true }), payload, specification, identity);
}

function openDestination(specification) {
  const common = constants.O_RDWR | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0);
  if (specification.publishMode === "create") {
    try {
      return Object.freeze({
        descriptor: openSync(
          specification.destinationLeaf,
          common | constants.O_CREAT | constants.O_EXCL,
          0o600
        ),
        created: true
      });
    } catch (error) {
      if (error?.code === "EEXIST") {
        throw new Error("attested publication destination already exists", { cause: error });
      }
      throw error;
    }
  }

  try {
    return Object.freeze({ descriptor: openSync(specification.destinationLeaf, common), created: false });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    try {
      return Object.freeze({
        descriptor: openSync(
          specification.destinationLeaf,
          common | constants.O_CREAT | constants.O_EXCL,
          0o600
        ),
        created: true
      });
    } catch (createError) {
      if (createError?.code === "EEXIST") {
        throw new Error("attested publication destination changed during exclusive creation", { cause: createError });
      }
      throw createError;
    }
  }
}

export function publishFromAnchoredWorkingDirectorySync(
  specificationArgument,
  payloadArgument,
  { directoryDescriptor = 3, hooks = {} } = {}
) {
  const specification = parseSpecification(specificationArgument);
  const payload = Buffer.isBuffer(payloadArgument) ? payloadArgument : Buffer.from(payloadArgument);
  if (payload.length < 1 || payload.length > specification.maximumBytes) {
    throw new Error("publication payload exceeds its permitted byte bounds");
  }
  exactKeys(hooks, ["afterAnchor", "afterWrite", "beforeCommit", "afterCommit"].filter(
    (key) => Object.hasOwn(hooks, key)
  ), "publication test hooks");

  const inheritedDirectory = fstatSync(directoryDescriptor, { bigint: true });
  validateDirectory(inheritedDirectory, specification.directoryIdentity, "inherited directory descriptor");
  validateDirectory(lstatSync(".", { bigint: true }), specification.directoryIdentity, "worker current directory");
  validateDirectory(
    lstatSync(specification.canonicalDirectory, { bigint: true }),
    specification.directoryIdentity,
    "canonical publication path"
  );
  const context = Object.freeze({
    canonicalDirectory: specification.canonicalDirectory,
    destinationLeaf: specification.destinationLeaf
  });
  invokeHook(hooks.afterAnchor, context, "afterAnchor");
  validateDirectory(
    lstatSync(specification.canonicalDirectory, { bigint: true }),
    specification.directoryIdentity,
    "canonical publication path"
  );

  const { descriptor, created } = openDestination(specification);
  try {
    const openedIdentity = fstatSync(descriptor, { bigint: true });
    if (!created) validateExistingDestination(openedIdentity, specification);
    const openedPath = lstatSync(specification.destinationLeaf, { bigint: true });
    if (!sameFileObject(openedIdentity, openedPath)) {
      throw new Error(`${specification.label} destination changed before descriptor-bound publication`);
    }
    ftruncateSync(descriptor, 0);
    let offset = 0;
    while (offset < payload.length) {
      offset += writeSync(descriptor, payload, offset, payload.length - offset, offset);
    }
    fchmodSync(descriptor, specification.fileMode);
    fsyncSync(descriptor);
    const publishedIdentity = fstatSync(descriptor, { bigint: true });
    validatePublishedFile(
      lstatSync(specification.destinationLeaf, { bigint: true }),
      payload,
      specification,
      publishedIdentity
    );
    invokeHook(hooks.afterWrite, context, "afterWrite");
    verifyDescriptorBytes(descriptor, payload, publishedIdentity, specification);
    validatePublishedFile(
      lstatSync(specification.destinationLeaf, { bigint: true }),
      payload,
      specification,
      publishedIdentity
    );
    invokeHook(hooks.beforeCommit, context, "beforeCommit");
    verifyDescriptorBytes(descriptor, payload, publishedIdentity, specification);
    validatePublishedFile(
      lstatSync(specification.destinationLeaf, { bigint: true }),
      payload,
      specification,
      publishedIdentity
    );
    fsyncSync(directoryDescriptor);
    invokeHook(hooks.afterCommit, context, "afterCommit");
    verifyDescriptorBytes(descriptor, payload, publishedIdentity, specification);
    validatePublishedFile(
      lstatSync(specification.destinationLeaf, { bigint: true }),
      payload,
      specification,
      publishedIdentity
    );
    validateDirectory(fstatSync(directoryDescriptor, { bigint: true }), specification.directoryIdentity, "inherited directory descriptor");
    validateDirectory(lstatSync(".", { bigint: true }), specification.directoryIdentity, "worker current directory");
    validateDirectory(
      lstatSync(specification.canonicalDirectory, { bigint: true }),
      specification.directoryIdentity,
      "canonical publication path"
    );
    fsyncSync(directoryDescriptor);
  } finally {
    closeSync(descriptor);
  }
  return Object.freeze({ schemaVersion: 1, bytes: payload.length, destinationLeaf: specification.destinationLeaf });
}

function decodeSpecification(argument) {
  if (typeof argument !== "string" || argument.length < 8 || argument.length > 16 * 1024
      || !/^[A-Za-z0-9_-]+$/u.test(argument)) {
    throw new Error("publication worker specification argument is malformed");
  }
  const bytes = Buffer.from(argument, "base64url");
  if (bytes.length < 2 || bytes.length > 12 * 1024) throw new Error("publication worker specification is oversized");
  return JSON.parse(bytes.toString("utf8"));
}

function readStandardInputBounded(maximumBytes) {
  const chunks = [];
  let total = 0;
  const buffer = Buffer.allocUnsafe(Math.min(maximumBytes + 1, 1024 * 1024));
  while (true) {
    const bytesRead = readSync(0, buffer, 0, buffer.length);
    if (bytesRead === 0) break;
    total += bytesRead;
    if (total > maximumBytes) throw new Error("publication payload exceeds its permitted byte bounds");
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
  }
  return Buffer.concat(chunks, total);
}

function main() {
  if (process.argv.length !== 3 || process.execArgv.length !== 0) {
    throw new Error("usage: attested-publication-worker.mjs <base64url-specification>");
  }
  const specification = decodeSpecification(process.argv[2]);
  const validated = parseSpecification(specification);
  const payload = readStandardInputBounded(validated.maximumBytes);
  const result = publishFromAnchoredWorkingDirectorySync(specification, payload);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
