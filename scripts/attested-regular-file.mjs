import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync
} from "node:fs";
import { lstat, open } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { createHash } from "node:crypto";

const identityFields = Object.freeze([
  "dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"
]);
// APFS updates a directory's reported nlink alongside ordinary child-file
// creation/removal. Mutating output scopes therefore bind the directory object,
// owner, group, and mode while separately validating nlink remains positive.
const stableDirectoryFields = Object.freeze(["dev", "ino", "mode", "uid", "gid"]);
const maximumSafeFileSize = BigInt(Number.MAX_SAFE_INTEGER);

function sameIdentity(left, right) {
  return identityFields.every((field) => left[field] === right[field]);
}

function sameDirectoryIdentity(left, right, allowContentMutation) {
  const fields = allowContentMutation ? stableDirectoryFields : identityFields;
  return fields.every((field) => left[field] === right[field]);
}

function boundedInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be one non-negative safe integer`);
  }
  return BigInt(value);
}

function validateShape(details, options, canonical) {
  const {
    label,
    minimumBytes,
    maximumBytes,
    requireCurrentUser,
    requirePrivateMode,
    requireSingleLink
  } = options;
  if (!details.isFile()) throw new Error(`${label} is not one regular file: ${basename(canonical)}`);
  if (requireSingleLink && details.nlink !== 1n) {
    throw new Error(`${label} must not be hard linked: ${basename(canonical)}`);
  }
  if (details.nlink < 1n) throw new Error(`${label} is no longer linked at its reviewed path: ${basename(canonical)}`);
  if (requireCurrentUser && typeof process.getuid === "function"
      && details.uid !== BigInt(process.getuid())) {
    throw new Error(`${label} is not owned by the current user: ${basename(canonical)}`);
  }
  if (requirePrivateMode && (details.mode & 0o077n) !== 0n) {
    throw new Error(`${label} is not owner-private: ${basename(canonical)}`);
  }
  if (details.size < minimumBytes || details.size > maximumBytes || details.size > maximumSafeFileSize) {
    throw new Error(`${label} exceeds its permitted byte bounds: ${basename(canonical)}`);
  }
}

function validateDirectoryShape(details, options, canonical) {
  const { label, requireCurrentUser, requirePrivateMode } = options;
  if (!details.isDirectory()) throw new Error(`${label} is not one directory: ${basename(canonical)}`);
  if (details.nlink < 1n) throw new Error(`${label} is no longer linked at its reviewed path: ${basename(canonical)}`);
  if (requireCurrentUser && typeof process.getuid === "function"
      && details.uid !== BigInt(process.getuid())) {
    throw new Error(`${label} is not owned by the current user: ${basename(canonical)}`);
  }
  if (requirePrivateMode && (details.mode & 0o077n) !== 0n) {
    throw new Error(`${label} is not owner-private: ${basename(canonical)}`);
  }
}

export async function withAttestedDirectory(path, options = {}, operation = async () => undefined) {
  const canonical = resolve(path);
  const normalized = Object.freeze({
    label: options.label ?? "attested directory",
    allowContentMutation: options.allowContentMutation === true,
    requireCurrentUser: options.requireCurrentUser !== false,
    requirePrivateMode: options.requirePrivateMode === true
  });
  const flags = fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
    | (fsConstants.O_CLOEXEC ?? 0);
  const handle = await open(canonical, flags);
  try {
    const before = await handle.stat({ bigint: true });
    validateDirectoryShape(before, normalized, canonical);
    const openedPath = await lstat(canonical, { bigint: true });
    if (!sameDirectoryIdentity(before, openedPath, normalized.allowContentMutation)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }

    await options.afterOpen?.(Object.freeze({ canonical, handle, before }));
    const beforeOperationPath = await lstat(canonical, { bigint: true });
    if (!sameDirectoryIdentity(before, beforeOperationPath, normalized.allowContentMutation)) {
      throw new Error(`${normalized.label} path changed before traversal: ${basename(canonical)}`);
    }

    let value;
    let operationError;
    try {
      value = await operation(Object.freeze({ canonical, handle, metadata: before }));
    } catch (error) {
      operationError = error;
    }
    let attestationError;
    try {
      await options.afterOperation?.(Object.freeze({ canonical, handle, before }));
      const after = await handle.stat({ bigint: true });
      const finalPath = await lstat(canonical, { bigint: true });
      if (!sameDirectoryIdentity(before, after, normalized.allowContentMutation)
          || !sameDirectoryIdentity(before, finalPath, normalized.allowContentMutation)) {
        throw new Error(`${normalized.label} changed during traversal: ${basename(canonical)}`);
      }
      validateDirectoryShape(after, normalized, canonical);
    } catch (error) {
      attestationError = error;
    }
    if (operationError && attestationError) {
      throw new AggregateError(
        [operationError, attestationError],
        `${normalized.label} operation failed and its directory identity also changed`
      );
    }
    if (attestationError) throw attestationError;
    if (operationError) throw operationError;
    return value;
  } finally {
    await handle.close();
  }
}

export async function withAttestedDirectories(paths, options = {}, operation = async () => undefined) {
  const directories = [...new Set(paths.map((path) => resolve(path)))].sort();
  async function visit(index) {
    if (index === directories.length) return operation();
    const directory = directories[index];
    const currentOptions = typeof options === "function" ? options(directory) : options;
    return withAttestedDirectory(directory, currentOptions, async () => visit(index + 1));
  }
  return visit(0);
}

/**
 * Read one exact regular file through the descriptor whose metadata was
 * reviewed. The pathname is re-attested before and after the read so an atomic
 * rename cannot silently substitute different bytes while the original open
 * descriptor remains stable.
 *
 * Hooks are intentionally function values rather than environment controls;
 * they exist only for deterministic adversarial unit tests and cannot be
 * activated by a release subprocess.
 */
export async function consumeAttestedRegularFile(path, options = {}, consumeChunk = async () => {}) {
  const canonical = resolve(path);
  const normalized = Object.freeze({
    label: options.label ?? "attested artifact",
    minimumBytes: boundedInteger(options.minimumBytes ?? 1, "minimumBytes"),
    maximumBytes: boundedInteger(options.maximumBytes ?? 64 * 1024 * 1024, "maximumBytes"),
    requireCurrentUser: options.requireCurrentUser !== false,
    requirePrivateMode: options.requirePrivateMode === true,
    requireSingleLink: options.requireSingleLink !== false
  });
  if (normalized.minimumBytes > normalized.maximumBytes) {
    throw new TypeError("minimumBytes must not exceed maximumBytes");
  }

  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0);
  const handle = await open(canonical, flags);
  try {
    const before = await handle.stat({ bigint: true });
    validateShape(before, normalized, canonical);
    const openedPath = await lstat(canonical, { bigint: true });
    if (!sameIdentity(before, openedPath)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }

    await options.afterOpen?.(Object.freeze({ canonical, handle, before }));
    const beforeReadPath = await lstat(canonical, { bigint: true });
    if (!sameIdentity(before, beforeReadPath)) {
      throw new Error(`${normalized.label} path changed before its bytes were read: ${basename(canonical)}`);
    }

    const chunkBytes = Math.max(1, Math.min(options.chunkBytes ?? 1024 * 1024, 1024 * 1024));
    let offset = 0;
    let chunkIndex = 0;
    const expectedBytes = Number(before.size);
    const buffer = Buffer.allocUnsafe(Math.min(chunkBytes, Math.max(1, expectedBytes)));
    while (offset < expectedBytes) {
      const requested = Math.min(buffer.length, expectedBytes - offset);
      const { bytesRead } = await handle.read(buffer, 0, requested, offset);
      if (bytesRead <= 0) {
        throw new Error(`${normalized.label} ended before its attested size: ${basename(canonical)}`);
      }
      await consumeChunk(buffer.subarray(0, bytesRead), offset);
      offset += bytesRead;
      await options.afterChunk?.(Object.freeze({ canonical, handle, before, chunkIndex, offset }));
      chunkIndex += 1;
    }
    const trailing = Buffer.allocUnsafe(1);
    const { bytesRead: trailingBytes } = await handle.read(trailing, 0, 1, expectedBytes);
    if (trailingBytes !== 0) {
      throw new Error(`${normalized.label} grew while its bytes were read: ${basename(canonical)}`);
    }

    const after = await handle.stat({ bigint: true });
    const finalPath = await lstat(canonical, { bigint: true });
    if (!sameIdentity(before, after) || !sameIdentity(before, finalPath)) {
      throw new Error(`${normalized.label} changed while its bytes were read: ${basename(canonical)}`);
    }
    validateShape(after, normalized, canonical);
    return Object.freeze({ bytes: expectedBytes, metadata: before, path: canonical });
  } finally {
    await handle.close();
  }
}

export async function readAttestedRegularFile(path, options = {}) {
  const chunks = [];
  const result = await consumeAttestedRegularFile(path, options, async (chunk) => {
    chunks.push(Buffer.from(chunk));
  });
  return Object.freeze({ ...result, bytes: Buffer.concat(chunks, result.bytes) });
}

export function readAttestedRegularFileSync(path, options = {}) {
  const canonical = resolve(path);
  const normalized = Object.freeze({
    label: options.label ?? "attested artifact",
    minimumBytes: boundedInteger(options.minimumBytes ?? 1, "minimumBytes"),
    maximumBytes: boundedInteger(options.maximumBytes ?? 64 * 1024 * 1024, "maximumBytes"),
    requireCurrentUser: options.requireCurrentUser !== false,
    requirePrivateMode: options.requirePrivateMode === true,
    requireSingleLink: options.requireSingleLink !== false
  });
  if (normalized.minimumBytes > normalized.maximumBytes) {
    throw new TypeError("minimumBytes must not exceed maximumBytes");
  }

  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0);
  const descriptor = openSync(canonical, flags);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    validateShape(before, normalized, canonical);
    const openedPath = lstatSync(canonical, { bigint: true });
    if (!sameIdentity(before, openedPath)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }

    const expectedBytes = Number(before.size);
    const bytes = Buffer.allocUnsafe(expectedBytes);
    let offset = 0;
    while (offset < expectedBytes) {
      const count = readSync(descriptor, bytes, offset, expectedBytes - offset, offset);
      if (count <= 0) {
        throw new Error(`${normalized.label} ended before its attested size: ${basename(canonical)}`);
      }
      offset += count;
    }
    const trailing = Buffer.allocUnsafe(1);
    if (readSync(descriptor, trailing, 0, 1, expectedBytes) !== 0) {
      throw new Error(`${normalized.label} grew while its bytes were read: ${basename(canonical)}`);
    }

    const after = fstatSync(descriptor, { bigint: true });
    const finalPath = lstatSync(canonical, { bigint: true });
    if (!sameIdentity(before, after) || !sameIdentity(before, finalPath)) {
      throw new Error(`${normalized.label} changed while its bytes were read: ${basename(canonical)}`);
    }
    validateShape(after, normalized, canonical);
    return Object.freeze({ bytes, metadata: before, path: canonical });
  } finally {
    closeSync(descriptor);
  }
}

export async function sha256AttestedRegularFile(path, options = {}) {
  const digest = createHash("sha256");
  const result = await consumeAttestedRegularFile(path, options, async (chunk) => digest.update(chunk));
  return Object.freeze({ ...result, sha256: digest.digest("hex") });
}

export const attestedRegularFileIdentityFields = identityFields;
