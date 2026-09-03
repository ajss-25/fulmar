import { createHash } from "node:crypto";
import { chmod, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  readAttestedRegularFile, withAttestedDirectories, withAttestedDirectory
} from "./attested-regular-file.mjs";

const [profile, identityPath, manifestPath, auditPath, destination] = process.argv.slice(2);
if (!profile || !identityPath || !manifestPath || !auditPath || !destination) {
  throw new Error("usage: generate-ci-evidence-summary.mjs <deterministic-ci|full-hardware> <release-identity> <release-manifest> <dependency-audit> <destination>");
}
if (!new Set(["deterministic-ci", "full-hardware"]).has(profile)) {
  throw new Error("CI evidence profile is unsupported");
}

async function boundedJSON(path, maximumBytes = 16 * 1024 * 1024) {
  const { bytes } = await readAttestedRegularFile(resolve(path), {
    label: "CI evidence input",
    minimumBytes: 2,
    maximumBytes,
    requireCurrentUser: true,
    requireSingleLink: true
  });
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`CI evidence input is not valid JSON: ${basename(path)}`); }
  return {
    value,
    descriptor: {
      file: basename(path),
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex")
    }
  };
}

const [identityInput, manifestInput, auditInput] = await withAttestedDirectories(
  [dirname(identityPath), dirname(manifestPath), dirname(auditPath)],
  { label: "CI evidence input directory", requireCurrentUser: true },
  async () => Promise.all([
    boundedJSON(identityPath, 64 * 1024),
    boundedJSON(manifestPath, 1024 * 1024),
    boundedJSON(auditPath, 32 * 1024 * 1024)
  ])
);
const identity = identityInput.value;
const manifest = manifestInput.value;
const audit = auditInput.value;

function safePublicString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`CI evidence ${label} is not one bounded public value`);
  }
  return value;
}

function safeArtifactName(value, label) {
  if (typeof value !== "string" || value !== basename(value) || value === "." || value === "..") {
    throw new Error(`CI evidence ${label} is not one path-free artifact name`);
  }
  safePublicString(value, /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u, label);
  return value;
}

safePublicString(manifest.product, /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/u, "product");
safePublicString(manifest.bundleIdentifier, /^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+){1,15}$/u, "bundle identifier");
safePublicString(manifest.version, /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/u, "version");
safePublicString(manifest.minimumMacOS, /^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/u, "minimum macOS version");
safeArtifactName(manifest.archive, "archive name");
if (!Number.isSafeInteger(manifest.build) || manifest.build <= 0) {
  throw new Error("CI evidence build is not one positive safe integer");
}

if (manifest.schemaVersion !== 6 || identity.productDisplayName !== manifest.product
    || identity.bundleIdentifier !== manifest.bundleIdentifier
    || identity.appVersion !== manifest.version
    || identity.appBuild !== manifest.build
    || identity.minimumMacOS !== manifest.minimumMacOS
    || identity.releaseArchiveName !== manifest.archive
    || typeof manifest.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(manifest.sha256)
    || !Number.isSafeInteger(manifest.archiveBytes) || manifest.archiveBytes <= 0) {
  throw new Error("CI evidence manifest does not match the reviewed release identity");
}
if (audit.schemaVersion !== 1 || audit.productionOnly !== true
    || audit.vulnerabilities?.total !== 0 || !Array.isArray(audit.unresolved)
    || audit.unresolved.length !== 0
    || typeof audit.packageLockSHA256 !== "string"
    || !/^[a-f0-9]{64}$/u.test(audit.packageLockSHA256)) {
  throw new Error("CI evidence requires a complete zero-finding production dependency audit");
}
if (!manifest.inventories || Array.isArray(manifest.inventories)
    || typeof manifest.inventories !== "object"
    || Object.keys(manifest.inventories).length < 1) {
  throw new Error("CI evidence manifest has no bounded inventory descriptor map");
}
for (const [key, descriptor] of [["symbols", manifest.symbols], ...Object.entries(manifest.inventories)]) {
  safePublicString(key, /^[A-Za-z][A-Za-z0-9]{0,63}$/u, "inventory key");
  if (!descriptor || typeof descriptor.file !== "string"
      || !Number.isSafeInteger(descriptor.bytes) || descriptor.bytes <= 0
      || typeof descriptor.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(descriptor.sha256)) {
    throw new Error("CI evidence manifest contains an invalid artifact descriptor");
  }
  safeArtifactName(descriptor.file, "artifact descriptor filename");
}
if (manifest.inventories.staticSecurity?.file !== "static-security-summary.json"
    || manifest.inventories.buildInputs?.file !== "source-build-inputs.json") {
  throw new Error("CI evidence manifest is not bound to exact static-security and source-input artifacts");
}
safePublicString(audit.nodeVersion, /^v[0-9]+\.[0-9]+\.[0-9]+$/u, "Node version");
safePublicString(audit.npmVersion, /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/u, "npm version");

const hardwareExecuted = profile === "full-hardware";
const summary = {
  schemaVersion: 1,
  evidenceType: "fulmar-candidate-qualification",
  profile,
  product: manifest.product,
  bundleIdentifier: manifest.bundleIdentifier,
  version: manifest.version,
  build: manifest.build,
  minimumMacOS: manifest.minimumMacOS,
  candidate: {
    archive: manifest.archive,
    bytes: manifest.archiveBytes,
    sha256: manifest.sha256,
    symbols: manifest.symbols
  },
  evidence: {
    releaseManifest: manifestInput.descriptor,
    dependencyAudit: auditInput.descriptor,
    inventories: manifest.inventories,
    productionPackageLockSHA256: audit.packageLockSHA256,
    nodeVersion: audit.nodeVersion,
    npmVersion: audit.npmVersion
  },
  gates: {
    deterministicCandidate: "passed",
    physicalQwenHardware: hardwareExecuted ? "passed" : "required-not-run",
    developerIDAndNotarization: "external-not-established",
    minimumOSCleanInstall: "external-not-established",
    fullGitHistory: "external-not-established"
  },
  finalPublicReleaseQualified: false
};

const payload = `${JSON.stringify(summary, null, 2)}\n`;
if (Buffer.byteLength(payload) > 64 * 1024) throw new Error("CI evidence summary exceeds its public byte limit");
const output = resolve(destination);
const temporary = join(dirname(output), `.${basename(output)}.${process.pid}.tmp`);
await withAttestedDirectory(dirname(output), {
  label: "CI evidence output directory",
  allowContentMutation: true,
  requireCurrentUser: true
}, async () => {
  await writeFile(temporary, payload, { mode: 0o600, flag: "wx" });
  await chmod(temporary, 0o644);
  await rename(temporary, output);
});
process.stdout.write(`Wrote safe canonical ${profile} evidence to ${basename(output)}.\n`);
