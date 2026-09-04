import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync
} from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
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

function acceptedOwnerSet(value) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length < 1 || value.length > 8
      || value.some((uid) => !Number.isSafeInteger(uid) || uid < 0)) {
    throw new TypeError("acceptedOwnerUIDs must be one bounded array of non-negative safe integers");
  }
  return Object.freeze(new Set(value.map((uid) => BigInt(uid))));
}

function optionalLinkBound(value) {
  if (value === undefined || value === null) return null;
  const bound = boundedInteger(value, "maximumLinks");
  if (bound < 1n) throw new TypeError("maximumLinks must be at least one");
  return bound;
}

// Shared ownership/mode predicates for files and directories. `acceptedOwnerUIDs`
// is an exact reviewed owner set (for example root plus one pinned hosted uid)
// and replaces the current-user rule when present.
function validateOwnership(details, options, canonical) {
  const { label, requireCurrentUser, acceptedOwnerUIDs, requirePrivateMode, requireOwnerControlledMode } = options;
  if (acceptedOwnerUIDs) {
    if (!acceptedOwnerUIDs.has(details.uid)) {
      throw new Error(`${label} is not owned by one accepted reviewed owner: ${basename(canonical)}`);
    }
  } else if (requireCurrentUser && typeof process.getuid === "function"
      && details.uid !== BigInt(process.getuid())) {
    throw new Error(`${label} is not owned by the current user: ${basename(canonical)}`);
  }
  if (requirePrivateMode && (details.mode & 0o077n) !== 0n) {
    throw new Error(`${label} is not owner-private: ${basename(canonical)}`);
  }
  if (requireOwnerControlledMode && (details.mode & 0o022n) !== 0n) {
    throw new Error(`${label} is group- or world-writable: ${basename(canonical)}`);
  }
}

function validateShape(details, options, canonical) {
  const { label, minimumBytes, maximumBytes, requireSingleLink, maximumLinks } = options;
  if (!details.isFile()) throw new Error(`${label} is not one regular file: ${basename(canonical)}`);
  if (requireSingleLink && details.nlink !== 1n) {
    throw new Error(`${label} must not be hard linked: ${basename(canonical)}`);
  }
  if (maximumLinks !== null && details.nlink > maximumLinks) {
    throw new Error(`${label} exceeds its permitted link count: ${basename(canonical)}`);
  }
  if (details.nlink < 1n) throw new Error(`${label} is no longer linked at its reviewed path: ${basename(canonical)}`);
  validateOwnership(details, options, canonical);
  if (details.size < minimumBytes || details.size > maximumBytes || details.size > maximumSafeFileSize) {
    throw new Error(`${label} exceeds its permitted byte bounds: ${basename(canonical)}`);
  }
}

function validateDirectoryShape(details, options, canonical) {
  const { label } = options;
  if (!details.isDirectory()) throw new Error(`${label} is not one directory: ${basename(canonical)}`);
  if (details.nlink < 1n) throw new Error(`${label} is no longer linked at its reviewed path: ${basename(canonical)}`);
  validateOwnership(details, options, canonical);
}

function normalizeFileOptions(options) {
  const normalized = Object.freeze({
    label: options.label ?? "attested artifact",
    minimumBytes: boundedInteger(options.minimumBytes ?? 1, "minimumBytes"),
    maximumBytes: boundedInteger(options.maximumBytes ?? 64 * 1024 * 1024, "maximumBytes"),
    requireCurrentUser: options.requireCurrentUser !== false,
    acceptedOwnerUIDs: acceptedOwnerSet(options.acceptedOwnerUIDs),
    requirePrivateMode: options.requirePrivateMode === true,
    requireOwnerControlledMode: options.requireOwnerControlledMode === true,
    requireSingleLink: options.requireSingleLink !== false,
    maximumLinks: optionalLinkBound(options.maximumLinks),
    requireCanonicalPath: options.requireCanonicalPath === true
  });
  if (normalized.minimumBytes > normalized.maximumBytes) {
    throw new TypeError("minimumBytes must not exceed maximumBytes");
  }
  return normalized;
}

function normalizeDirectoryOptions(options) {
  return Object.freeze({
    label: options.label ?? "attested directory",
    allowContentMutation: options.allowContentMutation === true,
    requireCurrentUser: options.requireCurrentUser !== false,
    acceptedOwnerUIDs: acceptedOwnerSet(options.acceptedOwnerUIDs),
    requirePrivateMode: options.requirePrivateMode === true,
    requireOwnerControlledMode: options.requireOwnerControlledMode === true,
    requireCanonicalPath: options.requireCanonicalPath === true
  });
}

function requireCanonical(actual, canonical, label) {
  if (actual !== canonical) {
    throw new Error(`${label} is not one canonical real path: ${basename(canonical)}`);
  }
}

const directoryFlags = fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
  | (fsConstants.O_CLOEXEC ?? 0);
// O_NONBLOCK only matters if the leaf is a FIFO: it makes the open return so the
// descriptor shape check can reject it instead of blocking for a writer.
const fileFlags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0)
  | (fsConstants.O_NONBLOCK ?? 0);

/**
 * Run one operation inside an already-open, no-follow directory descriptor whose
 * metadata was bound to the pathname before descent and re-attested afterwards.
 * With `allowContentMutation` the operation may publish expected children (the
 * directory object, owner, group and mode stay bound); without it the directory
 * must not change at all. The descriptor is handed to the operation so callers
 * can fsync through it instead of reopening a path they already checked.
 */
export async function withAttestedDirectory(path, options = {}, operation = async () => undefined) {
  const canonical = resolve(path);
  const normalized = normalizeDirectoryOptions(options);
  const handle = await open(canonical, directoryFlags);
  try {
    const before = await handle.stat({ bigint: true });
    validateDirectoryShape(before, normalized, canonical);
    const openedPath = await lstat(canonical, { bigint: true });
    if (!sameDirectoryIdentity(before, openedPath, normalized.allowContentMutation)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }
    if (normalized.requireCanonicalPath) requireCanonical(await realpath(canonical), canonical, normalized.label);

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

/** Synchronous twin of withAttestedDirectory for the synchronous release scripts. */
export function withAttestedDirectorySync(path, options = {}, operation = () => undefined) {
  const canonical = resolve(path);
  const normalized = normalizeDirectoryOptions(options);
  const descriptor = openSync(canonical, directoryFlags);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    validateDirectoryShape(before, normalized, canonical);
    const openedPath = lstatSync(canonical, { bigint: true });
    if (!sameDirectoryIdentity(before, openedPath, normalized.allowContentMutation)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }
    if (normalized.requireCanonicalPath) requireCanonical(realpathSync(canonical), canonical, normalized.label);

    options.afterOpen?.(Object.freeze({ canonical, descriptor, before }));
    const beforeOperationPath = lstatSync(canonical, { bigint: true });
    if (!sameDirectoryIdentity(before, beforeOperationPath, normalized.allowContentMutation)) {
      throw new Error(`${normalized.label} path changed before traversal: ${basename(canonical)}`);
    }

    let value;
    let operationError;
    try {
      value = operation(Object.freeze({ canonical, descriptor, metadata: before }));
    } catch (error) {
      operationError = error;
    }
    let attestationError;
    try {
      options.afterOperation?.(Object.freeze({ canonical, descriptor, before }));
      const after = fstatSync(descriptor, { bigint: true });
      const finalPath = lstatSync(canonical, { bigint: true });
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
    closeSync(descriptor);
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
  const normalized = normalizeFileOptions(options);
  const handle = await open(canonical, fileFlags);
  try {
    const before = await handle.stat({ bigint: true });
    validateShape(before, normalized, canonical);
    const openedPath = await lstat(canonical, { bigint: true });
    if (!sameIdentity(before, openedPath)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }
    if (normalized.requireCanonicalPath) requireCanonical(await realpath(canonical), canonical, normalized.label);

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
    if (normalized.requireCanonicalPath) requireCanonical(await realpath(canonical), canonical, normalized.label);
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
  const normalized = normalizeFileOptions(options);
  const descriptor = openSync(canonical, fileFlags);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    validateShape(before, normalized, canonical);
    const openedPath = lstatSync(canonical, { bigint: true });
    if (!sameIdentity(before, openedPath)) {
      throw new Error(`${normalized.label} path changed while its descriptor was opened: ${basename(canonical)}`);
    }
    if (normalized.requireCanonicalPath) requireCanonical(realpathSync(canonical), canonical, normalized.label);

    options.afterOpen?.(Object.freeze({ canonical, descriptor, before }));
    const beforeReadPath = lstatSync(canonical, { bigint: true });
    if (!sameIdentity(before, beforeReadPath)) {
      throw new Error(`${normalized.label} path changed before its bytes were read: ${basename(canonical)}`);
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
    if (normalized.requireCanonicalPath) requireCanonical(realpathSync(canonical), canonical, normalized.label);
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
