#!/usr/bin/env node
import {
  closeSync, constants, fchmodSync, fstatSync, lstatSync,
  openSync, readSync, realpathSync
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

const [planPath, hostPath, bundlePath, eventRoot, rawHostMajor, releasePlanPath,
  fixtureProfile, verifierPath] = process.argv.slice(2);
const hostMajor = Number(rawHostMajor);
const privateRootPattern = /^\/private\/tmp\/fulmar-swift-tests\.[A-Za-z0-9]{6}$/u;
const planPattern = /^\/private\/tmp\/fulmar-swift-tests\.[A-Za-z0-9]{6}\/swift-test-plan-[a-f0-9]{32}\.txt$/u;
const hostSuffix = "/FulmarSwiftTestingHost.app/Contents/MacOS/FulmarSwiftTestingHost";
const projectDirectory = dirname(dirname(resolve(verifierPath ?? "/invalid")));

if (process.argv.length !== 10
    || !planPattern.test(planPath ?? "")
    || !privateRootPattern.test(eventRoot ?? "")
    || dirname(planPath) !== eventRoot
    || hostPath !== `${eventRoot}${hostSuffix}`
    || typeof bundlePath !== "string" || !bundlePath.startsWith(`${projectDirectory}/.build/`)
    || !bundlePath.endsWith("/LocalHarnessPackageTests.xctest/Contents/MacOS/LocalHarnessPackageTests")
    || !Number.isSafeInteger(hostMajor) || hostMajor < 15 || hostMajor > 99
    || releasePlanPath !== `${projectDirectory}/Config/SwiftTestPlan.json`
    || !["ordinary", "release-fixtures"].includes(fixtureProfile)
    || resolve(verifierPath ?? "") !== `${projectDirectory}/scripts/verify-swift-test-events.mjs`) {
  throw new Error("usage: run-swift-test-shards.mjs <plan> <host> <bundle> <private-root> <host-major> <release-plan> <fixture-profile> <verifier>");
}

process.umask(0o077);

function safeSnapshot(path, maximumBytes, { privateFile = false, executable = false } = {}) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const mode = Number(before.mode & 0o777n);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
        || before.uid !== BigInt(process.getuid())
        || (privateFile && mode !== 0o600)
        || (executable && (mode & 0o111) === 0)
        || before.size < 1n || before.size > BigInt(maximumBytes)) {
      throw new Error(`unsafe native-shard input: ${path}`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count < 1) throw new Error(`truncated native-shard input: ${path}`);
      offset += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    for (const key of ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs"]) {
      if (after[key] !== before[key]) throw new Error(`changed native-shard input: ${path}`);
    }
    return {
      bytes,
      identity: Object.fromEntries(["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs"]
        .map((key) => [key, before[key].toString()])),
      sha256: createHash("sha256").update(bytes).digest("hex")
    };
  } finally {
    closeSync(descriptor);
  }
}

function unchanged(path, snapshot, maximumBytes, options) {
  const current = safeSnapshot(path, maximumBytes, options);
  return current.sha256 === snapshot.sha256
    && Object.keys(snapshot.identity).every((key) => current.identity[key] === snapshot.identity[key]);
}

const rootMetadata = lstatSync(eventRoot);
if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()
    || rootMetadata.uid !== process.getuid() || (rootMetadata.mode & 0o777) !== 0o700
    || realpathSync(eventRoot) !== eventRoot) {
  throw new Error("the native-shard event root is unsafe");
}

const planSnapshot = safeSnapshot(planPath, 8 * 1024 * 1024, { privateFile: true });
const hostSnapshot = safeSnapshot(hostPath, 4 * 1024 * 1024, { executable: true });
const bundleSnapshot = safeSnapshot(bundlePath, 512 * 1024 * 1024, { executable: true });
const releasePlanSnapshot = safeSnapshot(releasePlanPath, 16 * 1024);
if (planSnapshot.bytes.at(-1) !== 0x0a || planSnapshot.bytes.includes(0) || planSnapshot.bytes.includes(0x0d)) {
  throw new Error("the native-shard plan has invalid framing");
}

const specifiers = planSnapshot.bytes.toString("utf8").split("\n").slice(0, -1);
const suffixPattern = /\((?:[A-Za-z_][A-Za-z0-9_]*:)*\)$/u;
if (specifiers.length < 1 || specifiers.length > 10_000
    || new Set(specifiers).size !== specifiers.length
    || specifiers.some((value) => value.length < 3 || value.length > 4096 || !suffixPattern.test(value))) {
  throw new Error("the native-shard plan contains malformed or duplicate specifiers");
}

const selectors = specifiers.map((specifier) => {
  const separator = Math.max(specifier.lastIndexOf("/"), specifier.lastIndexOf("."));
  const leaf = specifier.slice(separator + 1);
  const suffix = leaf.match(suffixPattern)?.[0];
  const name = suffix ? leaf.slice(0, -suffix.length) : "";
  if (!name || name.length > 1024 || /[\u0000-\u001f\u007f]/u.test(name)) {
    throw new Error("the native-shard plan contains an unsafe function selector");
  }
  return { specifier, name };
});
for (let left = 0; left < selectors.length; left += 1) {
  for (let right = left + 1; right < selectors.length; right += 1) {
    if (selectors[left].name.includes(selectors[right].name)
        || selectors[right].name.includes(selectors[left].name)) {
      throw new Error("native-shard function selectors are not substring-unique");
    }
  }
}

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function failChild(label, result) {
  if (result.stdout) process.stderr.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  const detail = result.error ? `: ${result.error.message}` : "";
  throw new Error(`${label} failed${detail}`);
}

for (const [index, selector] of selectors.entries()) {
  const nonce = randomBytes(16).toString("hex");
  const eventPath = `${eventRoot}/swift-events-${nonce}.jsonl`;
  const result = spawnSync(hostPath, [
    "--test-bundle-path", bundlePath,
    "--filter", escapeRegularExpression(selector.name),
    "--no-parallel",
    "--event-stream-output-path", eventPath,
    "--event-stream-version", "0",
    "--testing-library", "swift-testing"
  ], {
    encoding: "utf8",
    env: process.env,
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.error || result.signal || result.status !== 0) {
    failChild(`native test shard ${index + 1}/${selectors.length} (${selector.name})`, result);
  }
  const eventDescriptor = openSync(eventPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fchmodSync(eventDescriptor, 0o600); } finally { closeSync(eventDescriptor); }
  const eventBytes = safeSnapshot(eventPath, 64 * 1024 * 1024, { privateFile: true }).bytes;
  if (eventBytes.at(-1) !== 0x0a || eventBytes.length > 64 * 1024 * 1024) {
    throw new Error(`native test shard ${index + 1} has invalid event framing`);
  }
  const functions = eventBytes.toString("utf8").split("\n").slice(0, -1).flatMap((line) => {
    let record;
    try { record = JSON.parse(line); } catch { return []; }
    return record?.kind === "test" && record?.payload?.kind === "function" ? [record.payload] : [];
  });
  if (functions.length !== 1
      || typeof functions[0].id !== "string"
      || (!functions[0].id.includes(`.${selector.name}(`)
        && !functions[0].id.includes(`/${selector.name}(`))) {
    throw new Error(`native test shard ${index + 1} did not discover its exact planned function`);
  }

  const verified = spawnSync(process.execPath, [
    verifierPath, eventPath, String(hostMajor), "focused", releasePlanPath, fixtureProfile
  ], { encoding: "utf8", env: process.env, maxBuffer: 2 * 1024 * 1024 });
  if (verified.error || verified.signal || verified.status !== 0) {
    failChild(`native event verification ${index + 1}/${selectors.length} (${selector.name})`, verified);
  }
  if ((index + 1) % 25 === 0 || index + 1 === selectors.length) {
    process.stdout.write(`Verified native test shard ${index + 1}/${selectors.length}.\n`);
  }
}

if (!unchanged(planPath, planSnapshot, 8 * 1024 * 1024, { privateFile: true })
    || !unchanged(hostPath, hostSnapshot, 4 * 1024 * 1024, { executable: true })
    || !unchanged(bundlePath, bundleSnapshot, 512 * 1024 * 1024, { executable: true })
    || !unchanged(releasePlanPath, releasePlanSnapshot, 16 * 1024)) {
  throw new Error("a native-shard authority changed during qualification");
}
process.stdout.write(`Swift full-suite isolation passed: ${selectors.length} exact function shards.\n`);
