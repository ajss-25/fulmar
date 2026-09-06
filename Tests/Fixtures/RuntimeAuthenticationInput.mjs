import { randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, constants, fstatSync, fsyncSync, openSync, readSync, unlinkSync, writeSync
} from "node:fs";

export const runtimeAuthenticationVersion = "FULMAR_RUNTIME_AUTH_V1";
export const maximumRuntimeAuthenticationBytes = 384;
export const fixtureAuthToken = "fixture-auth-token-0123456789_ABCDE";
export const fixtureInstanceNonce = "fixture-instance-nonce-0123456789";

export function runtimeAuthenticationFrame(authToken, nonce) {
  const material = /^[A-Za-z0-9_-]{22,128}$/u;
  if (!material.test(authToken) || !material.test(nonce)) {
    throw new Error("invalid runtime authentication fixture material");
  }
  const frame = Buffer.from(`${runtimeAuthenticationVersion}:${authToken}:${nonce}\n`, "utf8");
  if (frame.length > maximumRuntimeAuthenticationBytes) {
    throw new Error("oversized runtime authentication fixture");
  }
  return frame;
}

/// Returns an owner-only, already-unlinked regular descriptor positioned at
/// byte zero. An explicit-position write preserves the open description's
/// current offset, so no close/reopen pathname race is needed.
export function openRuntimeAuthenticationInput(
  authToken = fixtureAuthToken,
  nonce = fixtureInstanceNonce
) {
  return openRuntimeAuthenticationFixture(runtimeAuthenticationFrame(authToken, nonce)).descriptor;
}

export function openRuntimeAuthenticationFixture(
  bytes,
  { linked = false, mode = 0o600, consumeBytes = 0 } = {}
) {
  const path = `/private/tmp/fulmar-runtime-auth-test.${process.pid}.${randomBytes(16).toString("hex")}`;
  const flags = constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW;
  const descriptor = openSync(path, flags, mode);
  let published = false;
  try {
    chmodSync(path, mode);
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== process.getuid()
        || (before.mode & 0o777) !== mode || before.size !== 0) {
      throw new Error("unsafe runtime authentication fixture descriptor");
    }
    if (!linked) {
      unlinkSync(path);
      const unpublished = fstatSync(descriptor);
      if (unpublished.dev !== before.dev || unpublished.ino !== before.ino
          || unpublished.nlink !== 0 || unpublished.size !== 0) {
        throw new Error("runtime authentication fixture was not unlinked before write");
      }
    }
    if (!Buffer.isBuffer(bytes) || writeSync(descriptor, bytes, 0, bytes.length, 0) !== bytes.length) {
      throw new Error("incomplete runtime authentication fixture write");
    }
    fsyncSync(descriptor);
    if (consumeBytes > 0) {
      const consumed = Buffer.alloc(consumeBytes);
      if (readSync(descriptor, consumed, 0, consumeBytes, null) !== consumeBytes) {
        throw new Error("runtime authentication replay fixture could not advance");
      }
      consumed.fill(0);
    }
    const after = fstatSync(descriptor);
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino
        || after.nlink !== (linked ? 1 : 0) || after.uid !== before.uid
        || (after.mode & 0o777) !== mode || after.size !== bytes.length) {
      throw new Error("runtime authentication fixture changed before publication");
    }
    published = true;
    return { descriptor, linkedPath: linked ? path : undefined };
  } finally {
    if (!published) {
      try { unlinkSync(path); } catch {}
      closeSync(descriptor);
    }
  }
}
