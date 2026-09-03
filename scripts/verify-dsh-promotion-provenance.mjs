#!/usr/bin/env node

import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultProjectRoot = resolve(scriptDirectory, "..");
const repository = "deepseek-ai/deepseek-harness";
const registryOrigin = "https://registry.npmjs.org";
const githubAPIOrigin = "https://api.github.com";
const githubOrigin = "https://github.com";
const promotionFilename = "Config/DSHPromotionProvenance.json";
const maximumJSONBytes = 64 * 1024 * 1024;
const maximumGitHubReleaseBytes = 4 * 1024 * 1024;
const maximumGitHubReferenceBytes = 1024 * 1024;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function byteOrder(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertExactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort(byteOrder)) !== JSON.stringify([...expected].sort(byteOrder))) {
    throw new Error(`${label} does not match the reviewed schema`);
  }
}

function validateSHA256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${label} is not an exact SHA-256 digest`);
  }
  return value;
}

function validateSHA512Integrity(value, label) {
  if (typeof value !== "string" || value.length > 512
      || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error(`${label} is not an exact npm SHA-512 integrity value`);
  }
  const encoded = value.slice("sha512-".length);
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== encoded) {
    throw new Error(`${label} is not an exact npm SHA-512 integrity value`);
  }
  return value;
}

async function readBoundedRegularFile(path, maximumBytes = maximumJSONBytes) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.size < 2 || before.size > maximumBytes) {
    throw new Error(`expected one bounded regular file: ${path}`);
  }
  // O_NOFOLLOW plus descriptor fstat before/after binds every consumed byte.
  const descriptor = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); // codeql[js/file-system-race]
  try {
    const opened = await descriptor.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size
        || opened.nlink !== 1 || !opened.isFile()) {
      throw new Error(`file identity changed before read: ${path}`);
    }
    const bytes = await descriptor.readFile();
    const after = await descriptor.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
        || after.nlink !== 1 || bytes.length !== opened.size) {
      throw new Error(`file identity changed while read: ${path}`);
    }
    return bytes;
  } finally {
    await descriptor.close();
  }
}

async function readBoundedRegularJSON(path, maximumBytes = maximumJSONBytes) {
  const bytes = await readBoundedRegularFile(path, maximumBytes);
  return { bytes, value: JSON.parse(bytes.toString("utf8")) };
}

export function validatePromotionRecordShape(record) {
  assertExactKeys(record, ["schemaVersion", "repository", "npm", "github"], "DSH promotion record");
  if (record.schemaVersion !== 1 || record.repository !== repository) {
    throw new Error("DSH promotion record identifies an unsupported schema or repository");
  }
  assertExactKeys(
    record.npm,
    ["registryOrigin", "package", "version", "tarball", "integrity", "cohort"],
    "DSH npm promotion record"
  );
  if (record.npm.registryOrigin !== registryOrigin || record.npm.package !== "@deepseek-ai/dsh"
      || typeof record.npm.version !== "string"
      || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.test(record.npm.version)) {
    throw new Error("DSH npm promotion identity is invalid");
  }
  const expectedTarball = `${registryOrigin}/@deepseek-ai/dsh/-/dsh-${record.npm.version}.tgz`;
  if (record.npm.tarball !== expectedTarball) {
    throw new Error("DSH npm promotion tarball does not match the exact promoted version");
  }
  validateSHA512Integrity(record.npm.integrity, "DSH npm promotion integrity");
  assertExactKeys(
    record.npm.cohort,
    ["version", "packageCount", "canonicalization", "sha256", "lockSHA256"],
    "DSH npm cohort record"
  );
  if (record.npm.cohort.version !== record.npm.version
      || !Number.isSafeInteger(record.npm.cohort.packageCount)
      || record.npm.cohort.packageCount < 1 || record.npm.cohort.packageCount > 1024
      || record.npm.cohort.canonicalization !== "sorted-package-version-resolved-integrity-json-v1") {
    throw new Error("DSH npm cohort identity is invalid");
  }
  validateSHA256(record.npm.cohort.sha256, "DSH npm cohort digest");
  validateSHA256(record.npm.cohort.lockSHA256, "DSH npm cohort lock digest");

  assertExactKeys(
    record.github,
    ["apiOrigin", "tag", "commitSHA", "releaseAPIURL", "releaseObjectAPIURL", "releaseURL", "releaseNotes"],
    "DSH GitHub promotion record"
  );
  const expectedTag = `dsh-v${record.npm.version}`;
  const encodedTag = encodeURIComponent(expectedTag);
  const releaseObjectPrefix = `${githubAPIOrigin}/repos/${repository}/releases/`;
  const releaseObjectID = typeof record.github.releaseObjectAPIURL === "string"
    && record.github.releaseObjectAPIURL.startsWith(releaseObjectPrefix)
    ? record.github.releaseObjectAPIURL.slice(releaseObjectPrefix.length)
    : "";
  if (record.github.apiOrigin !== githubAPIOrigin || record.github.tag !== expectedTag
      || typeof record.github.commitSHA !== "string" || !/^[a-f0-9]{40}$/u.test(record.github.commitSHA)
      || record.github.releaseAPIURL !== `${githubAPIOrigin}/repos/${repository}/releases/tags/${encodedTag}`
      || !/^[1-9][0-9]{0,19}$/u.test(releaseObjectID)
      || record.github.releaseURL !== `${githubOrigin}/${repository}/releases/tag/${encodedTag}`) {
    throw new Error("DSH GitHub promotion identity is invalid");
  }
  assertExactKeys(record.github.releaseNotes, ["source", "byteCount", "sha256"], "DSH release-note record");
  if (record.github.releaseNotes.source !== "github-release-body-utf8"
      || !Number.isSafeInteger(record.github.releaseNotes.byteCount)
      || record.github.releaseNotes.byteCount < 0
      || record.github.releaseNotes.byteCount > maximumGitHubReleaseBytes) {
    throw new Error("DSH release-note metadata is invalid");
  }
  validateSHA256(record.github.releaseNotes.sha256, "DSH release-note digest");
  return record;
}

export function exactDSHCohortFromLock(lock, targetVersion) {
  if (lock === null || typeof lock !== "object" || Array.isArray(lock)
      || lock.packages === null || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
    throw new Error("DSH promotion lock does not contain a package map");
  }
  const cohort = [];
  const names = new Set();
  for (const [lockPath, entry] of Object.entries(lock.packages)) {
    const match = lockPath.match(/(?:^|\/)node_modules\/(@deepseek-ai\/dsh(?:-[^/]+)?)$/u);
    if (!match) continue;
    const packageName = match[1];
    if (names.has(packageName)) throw new Error(`DSH promotion cohort contains duplicate ${packageName}`);
    names.add(packageName);
    if (entry?.version !== targetVersion) {
      throw new Error(`DSH promotion cohort version drifted for ${packageName}`);
    }
    const unscoped = packageName.slice("@deepseek-ai/".length);
    const expectedResolved = `${registryOrigin}/${packageName}/-/${unscoped}-${targetVersion}.tgz`;
    if (entry.resolved !== expectedResolved) {
      throw new Error(`DSH promotion cohort origin drifted for ${packageName}`);
    }
    validateSHA512Integrity(entry.integrity, `DSH promotion cohort integrity for ${packageName}`);
    cohort.push({
      package: packageName,
      version: entry.version,
      resolved: entry.resolved,
      integrity: entry.integrity
    });
  }
  cohort.sort((left, right) => byteOrder(left.package, right.package));
  if (!names.has("@deepseek-ai/dsh")) throw new Error("DSH promotion cohort omits the root package");
  return cohort;
}

export function validatePromotionAgainstInputs(recordValue, {
  releaseIdentity,
  packageLock,
  packageLockBytes,
  runtimeManifest,
  vendorPatchManifest
}) {
  const record = validatePromotionRecordShape(recordValue);
  if (releaseIdentity?.runtime?.deepseekHarnessVersion !== record.npm.version
      || releaseIdentity?.runtime?.deepseekMCPClientVersion !== record.npm.version
      || runtimeManifest?.dependencies?.[record.npm.package] !== record.npm.version) {
    throw new Error("DSH promotion record does not match the release/runtime pin");
  }
  const cohort = exactDSHCohortFromLock(packageLock, record.npm.version);
  const cohortDigest = sha256(Buffer.from(JSON.stringify(cohort), "utf8"));
  if (cohort.length !== record.npm.cohort.packageCount || cohortDigest !== record.npm.cohort.sha256
      || sha256(packageLockBytes) !== record.npm.cohort.lockSHA256) {
    throw new Error("DSH promotion cohort or lock digest does not match the tracked record");
  }
  const root = cohort.find((entry) => entry.package === record.npm.package);
  if (root?.resolved !== record.npm.tarball || root?.integrity !== record.npm.integrity) {
    throw new Error("DSH promotion root npm provenance does not match the exact cohort");
  }
  if (vendorPatchManifest?.reviewedLockSHA256 !== record.npm.cohort.lockSHA256
      || !Array.isArray(vendorPatchManifest?.upstreamTarballs)) {
    throw new Error("DSH promotion record does not match the vendored patch review");
  }
  const patchedRoot = vendorPatchManifest.upstreamTarballs.filter((entry) => entry?.package === record.npm.package);
  if (patchedRoot.length !== 1 || patchedRoot[0].version !== record.npm.version
      || patchedRoot[0].resolved !== record.npm.tarball || patchedRoot[0].integrity !== record.npm.integrity) {
    throw new Error("DSH promotion npm provenance does not match the vendored patch record");
  }
  return {
    version: record.npm.version,
    cohortPackageCount: cohort.length,
    cohortSHA256: cohortDigest,
    lockSHA256: record.npm.cohort.lockSHA256,
    githubTag: record.github.tag,
    githubCommitSHA: record.github.commitSHA,
    releaseNotesSHA256: record.github.releaseNotes.sha256
  };
}

export async function loadVerifiedDSHPromotionProvenanceAtRoot(projectRootArgument = defaultProjectRoot) {
  const projectRoot = resolve(projectRootArgument);
  const [promotion, identity, lock, runtimeManifest, patchManifest] = await Promise.all([
    readBoundedRegularJSON(join(projectRoot, promotionFilename), 1024 * 1024),
    readBoundedRegularJSON(join(projectRoot, "Config/ReleaseIdentity.json"), 1024 * 1024),
    readBoundedRegularJSON(join(projectRoot, "VendorRuntime/package-lock.json"), maximumJSONBytes),
    readBoundedRegularJSON(join(projectRoot, "VendorRuntime/package.json"), 1024 * 1024),
    readBoundedRegularJSON(join(projectRoot, "Config/VendorRuntimePatches.json"), 4 * 1024 * 1024)
  ]);
  const summary = validatePromotionAgainstInputs(promotion.value, {
    releaseIdentity: identity.value,
    packageLock: lock.value,
    packageLockBytes: lock.bytes,
    runtimeManifest: runtimeManifest.value,
    vendorPatchManifest: patchManifest.value
  });
  return { record: promotion.value, summary };
}

export async function verifyDSHPromotionProvenanceAtRoot(projectRootArgument = defaultProjectRoot) {
  return (await loadVerifiedDSHPromotionProvenanceAtRoot(projectRootArgument)).summary;
}

async function fetchBoundedOfficialJSON(url, maximumBytes, fetchImplementation) {
  if (typeof fetchImplementation !== "function") throw new Error("HTTPS fetch is unavailable");
  const response = await fetchImplementation(url, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(20_000),
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  if (response.url !== url || response.status !== 200) {
    throw new Error("official GitHub request did not return the exact reviewed resource");
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json" && contentType !== "application/vnd.github+json") {
    throw new Error("official GitHub response was not JSON");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^[0-9]+$/u.test(declared) || Number(declared) > maximumBytes)) {
    throw new Error("official GitHub response exceeded its declared bound");
  }
  if (!response.body) throw new Error("official GitHub response omitted its body");
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > maximumBytes) throw new Error("official GitHub response exceeded its body bound");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
}

async function resolveOfficialTagCommit(record, fetchImplementation) {
  const encodedTag = encodeURIComponent(record.github.tag);
  const refURL = `${githubAPIOrigin}/repos/${repository}/git/refs/tags/${encodedTag}`;
  const reference = await fetchBoundedOfficialJSON(refURL, maximumGitHubReferenceBytes, fetchImplementation);
  if (reference?.ref !== `refs/tags/${record.github.tag}` || reference?.url !== refURL
      || reference.object === null || typeof reference.object !== "object") {
    throw new Error("official GitHub tag response has an unexpected identity");
  }
  let object = reference.object;
  const visited = new Set();
  for (let depth = 0; depth < 4; depth += 1) {
    if (typeof object.sha !== "string" || !/^[a-f0-9]{40}$/u.test(object.sha)
        || typeof object.type !== "string" || typeof object.url !== "string") {
      throw new Error("official GitHub tag object is invalid");
    }
    if (object.type === "commit") {
      const expected = `${githubAPIOrigin}/repos/${repository}/git/commits/${object.sha}`;
      if (object.url !== expected) throw new Error("official GitHub commit URL is unexpected");
      return object.sha;
    }
    if (object.type !== "tag" || visited.has(object.sha)) {
      throw new Error("official GitHub tag does not resolve to one bounded commit chain");
    }
    visited.add(object.sha);
    const expected = `${githubAPIOrigin}/repos/${repository}/git/tags/${object.sha}`;
    if (object.url !== expected) throw new Error("official GitHub annotated-tag URL is unexpected");
    const tagObject = await fetchBoundedOfficialJSON(expected, maximumGitHubReferenceBytes, fetchImplementation);
    if (tagObject?.sha !== object.sha || tagObject?.tag !== record.github.tag
        || tagObject.object === null || typeof tagObject.object !== "object") {
      throw new Error("official GitHub annotated-tag response is invalid");
    }
    object = tagObject.object;
  }
  throw new Error("official GitHub tag chain exceeded its bound");
}

export async function fetchOfficialGitHubPromotionObservation(recordValue, fetchImplementation = globalThis.fetch) {
  const record = validatePromotionRecordShape(recordValue);
  const [release, commitSHA] = await Promise.all([
    fetchBoundedOfficialJSON(record.github.releaseAPIURL, maximumGitHubReleaseBytes, fetchImplementation),
    resolveOfficialTagCommit(record, fetchImplementation)
  ]);
  if (release === null || typeof release !== "object" || Array.isArray(release)
      || release.tag_name !== record.github.tag || release.html_url !== record.github.releaseURL
      || release.url !== record.github.releaseObjectAPIURL || release.draft !== false
      || typeof release.body !== "string") {
    throw new Error("official GitHub release response has an unexpected identity");
  }
  const releaseNotes = Buffer.from(release.body, "utf8");
  const observed = {
    commitSHA,
    releaseNotesByteCount: releaseNotes.length,
    releaseNotesSHA256: sha256(releaseNotes)
  };
  const mismatches = [];
  if (observed.commitSHA !== record.github.commitSHA) mismatches.push("commitSHA");
  if (observed.releaseNotesByteCount !== record.github.releaseNotes.byteCount) mismatches.push("releaseNotes.byteCount");
  if (observed.releaseNotesSHA256 !== record.github.releaseNotes.sha256) mismatches.push("releaseNotes.sha256");
  return { tag: record.github.tag, observed, mismatches };
}

async function main() {
  if (process.argv.length > 3) throw new Error("usage: verify-dsh-promotion-provenance.mjs [project-root]");
  const result = await verifyDSHPromotionProvenanceAtRoot(process.argv[2] ?? defaultProjectRoot);
  process.stdout.write(
    `Verified promoted DSH ${result.version}: ${result.cohortPackageCount} exact cohort packages, `
      + `GitHub ${result.githubTag}@${result.githubCommitSHA}.\n`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`DSH promotion provenance failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
