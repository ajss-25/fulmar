import { createHash } from "node:crypto";
import { chmod, readdir, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  readAttestedRegularFile, sha256AttestedRegularFile, withAttestedDirectory
} from "./attested-regular-file.mjs";

const mode = process.argv[2];
const argumentsList = process.argv.slice(3);
const transportFilename = "ci-candidate-transport.json";
const manifestFilename = "release-manifest.json";
const evidenceFilename = "ci-evidence-summary.json";
const signablesFilename = "runtime-signables.json";

function failUsage() {
  throw new Error(
    "usage: ci-candidate-transport.mjs create <release-identity> <release-manifest> "
      + "<archive> <canonical-evidence> <runtime-signables> <source-revision> <destination>\n"
      + "   or: ci-candidate-transport.mjs verify <release-identity> <release-manifest> "
      + "<archive> <canonical-evidence> <runtime-signables> <transport> <source-revision> "
      + "<archive-upload-sha256> <manifest-upload-sha256> <evidence-upload-sha256> "
      + "<signables-upload-sha256> <transport-upload-sha256>"
  );
}

function exactSHA256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${label} is not one lowercase SHA-256 digest`);
  }
  return value;
}

function exactSourceRevision(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/u.test(value)) {
    throw new Error("hosted candidate source revision is not one full lowercase Git commit");
  }
  return value;
}

function safeArtifactName(value, expected, label) {
  if (value !== expected || value !== basename(value) || value === "." || value === ".."
      || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u.test(value)) {
    throw new Error(`${label} is not the exact path-free artifact name`);
  }
  return value;
}

function rejectPrivatePresentation(value, label = "hosted candidate evidence") {
  if (typeof value === "string") {
    if (/\x00|[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/u.test(value)
        || /(?:^|[\\/])(?:Users|home|private|tmp)(?:[\\/]|$)/u.test(value)
        || value.startsWith("/")) {
      throw new Error(`${label} contains a private path or control character`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) rejectPrivatePresentation(entry, label);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(key)) {
        throw new Error(`${label} contains an unsafe field name`);
      }
      rejectPrivatePresentation(entry, label);
    }
  }
}

async function boundedJSON(path, label, maximumBytes = 1024 * 1024) {
  const input = await readAttestedRegularFile(resolve(path), {
    label,
    minimumBytes: 2,
    maximumBytes,
    requireCurrentUser: true,
    requireSingleLink: true
  });
  let value;
  try {
    value = JSON.parse(input.bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON: ${basename(path)}`);
  }
  return {
    value,
    descriptor: {
      file: basename(path),
      bytes: input.bytes.length,
      sha256: createHash("sha256").update(input.bytes).digest("hex")
    }
  };
}

function sameDescriptor(left, right) {
  return Boolean(left && right
    && left.file === right.file
    && left.bytes === right.bytes
    && left.sha256 === right.sha256);
}

function byteOrder(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function validateSignables(signables) {
  if (signables.schemaVersion !== 1 || signables.root !== "Runtime"
      || !Number.isSafeInteger(signables.count) || signables.count <= 0
      || !Array.isArray(signables.paths) || signables.paths.length !== signables.count
      || signables.paths.length > 4096) {
    throw new Error("hosted candidate Runtime Mach-O inventory is unsupported");
  }
  const identities = new Set();
  for (const path of signables.paths) {
    if (typeof path !== "string" || path.length === 0 || path.length > 2048
        || path.startsWith("/") || path.includes("\\") || /[\x00-\x1f\x7f]/u.test(path)) {
      throw new Error("hosted candidate Runtime Mach-O inventory contains an unsafe path");
    }
    const segments = path.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error("hosted candidate Runtime Mach-O inventory contains traversal");
    }
    const identity = path.normalize("NFC").toLocaleLowerCase("en-US");
    if (identities.has(identity)) {
      throw new Error("hosted candidate Runtime Mach-O inventory contains a normalized collision");
    }
    identities.add(identity);
  }
  if ([...signables.paths].sort(byteOrder).some((path, index) => path !== signables.paths[index])) {
    throw new Error("hosted candidate Runtime Mach-O inventory is not canonically ordered");
  }
}

function validateIdentity(identity) {
  if (identity.schemaVersion !== 1
      || typeof identity.productDisplayName !== "string"
      || typeof identity.applicationBundleName !== "string"
      || typeof identity.bundleIdentifier !== "string"
      || typeof identity.appVersion !== "string"
      || !Number.isSafeInteger(identity.appBuild) || identity.appBuild <= 0
      || !/^[0-9]+\.0$/u.test(identity.minimumMacOS)
      || typeof identity.releaseArchiveName !== "string") {
    throw new Error("hosted candidate release identity is unsupported");
  }
  safeArtifactName(
    identity.applicationBundleName, identity.applicationBundleName, "application bundle"
  );
  safeArtifactName(identity.releaseArchiveName, identity.releaseArchiveName, "release archive");
}

function validateBoundEvidence(identity, manifestInput, archiveDescriptor, evidenceInput, signablesInput) {
  const manifest = manifestInput.value;
  const evidence = evidenceInput.value;
  validateSignables(signablesInput.value);
  if (manifest.schemaVersion !== 6
      || manifest.product !== identity.productDisplayName
      || manifest.bundleIdentifier !== identity.bundleIdentifier
      || manifest.version !== identity.appVersion
      || manifest.build !== identity.appBuild
      || manifest.minimumMacOS !== identity.minimumMacOS
      || manifest.archive !== identity.releaseArchiveName
      || manifest.archive !== archiveDescriptor.file
      || manifest.archiveBytes !== archiveDescriptor.bytes
      || manifest.sha256 !== archiveDescriptor.sha256
      || !sameDescriptor(manifest.inventories?.runtimeSignables, signablesInput.descriptor)) {
    throw new Error("hosted candidate manifest is not bound to the exact archive, identity, and Mach-O inventory");
  }
  if (evidence.schemaVersion !== 1
      || evidence.evidenceType !== "fulmar-candidate-qualification"
      || evidence.profile !== "deterministic-ci"
      || evidence.product !== identity.productDisplayName
      || evidence.bundleIdentifier !== identity.bundleIdentifier
      || evidence.version !== identity.appVersion
      || evidence.build !== identity.appBuild
      || evidence.minimumMacOS !== identity.minimumMacOS
      || evidence.candidate?.archive !== archiveDescriptor.file
      || evidence.candidate?.bytes !== archiveDescriptor.bytes
      || evidence.candidate?.sha256 !== archiveDescriptor.sha256
      || !sameDescriptor(evidence.evidence?.releaseManifest, manifestInput.descriptor)
      || !sameDescriptor(evidence.evidence?.inventories?.runtimeSignables, signablesInput.descriptor)
      || evidence.gates?.deterministicCandidate !== "passed"
      || evidence.gates?.physicalQwenHardware !== "required-not-run"
      || evidence.finalPublicReleaseQualified !== false) {
    throw new Error("hosted candidate canonical evidence is not bound to the exact deterministic candidate");
  }
  rejectPrivatePresentation(manifest, "hosted candidate manifest");
  rejectPrivatePresentation(evidence, "hosted candidate canonical evidence");
}

async function readInputs(identityPath, manifestPath, archivePath, evidencePath, signablesPath) {
  const [identityInput, manifestInput, archiveInput, evidenceInput, signablesInput] = await Promise.all([
    boundedJSON(identityPath, "hosted candidate release identity", 64 * 1024),
    boundedJSON(manifestPath, "hosted candidate release manifest"),
    sha256AttestedRegularFile(resolve(archivePath), {
      label: "hosted candidate archive",
      minimumBytes: 1,
      maximumBytes: 2 * 1024 * 1024 * 1024,
      requireCurrentUser: true,
      requireSingleLink: true
    }),
    boundedJSON(evidencePath, "hosted candidate canonical evidence", 64 * 1024),
    boundedJSON(signablesPath, "hosted candidate Runtime Mach-O inventory", 4 * 1024 * 1024)
  ]);
  validateIdentity(identityInput.value);
  const archiveDescriptor = {
    file: basename(archivePath),
    bytes: archiveInput.bytes,
    sha256: archiveInput.sha256
  };
  safeArtifactName(archiveDescriptor.file, identityInput.value.releaseArchiveName, "candidate archive");
  safeArtifactName(manifestInput.descriptor.file, manifestFilename, "release manifest");
  safeArtifactName(evidenceInput.descriptor.file, evidenceFilename, "canonical evidence");
  safeArtifactName(signablesInput.descriptor.file, signablesFilename, "Runtime Mach-O inventory");
  validateBoundEvidence(
    identityInput.value, manifestInput, archiveDescriptor, evidenceInput, signablesInput
  );
  return { identityInput, manifestInput, archiveDescriptor, evidenceInput, signablesInput };
}

function transportPayload(inputs, sourceRevision) {
  return {
    schemaVersion: 1,
    evidenceType: "fulmar-hosted-candidate-transport",
    sourceRevision: exactSourceRevision(sourceRevision),
    producer: {
      runnerImage: "macos-26",
      architecture: "arm64"
    },
    product: inputs.identityInput.value.productDisplayName,
    bundleIdentifier: inputs.identityInput.value.bundleIdentifier,
    version: inputs.identityInput.value.appVersion,
    build: inputs.identityInput.value.appBuild,
    minimumMacOS: inputs.identityInput.value.minimumMacOS,
    artifacts: {
      archive: inputs.archiveDescriptor,
      releaseManifest: inputs.manifestInput.descriptor,
      canonicalEvidence: inputs.evidenceInput.descriptor,
      runtimeSignables: inputs.signablesInput.descriptor
    }
  };
}

async function exactArtifactDirectory(paths, expectedFiles) {
  const directories = new Set(paths.map((path) => dirname(resolve(path))));
  if (directories.size !== 1) throw new Error("hosted candidate artifacts do not share one directory");
  const directory = [...directories][0];
  await withAttestedDirectory(directory, {
    label: "hosted candidate artifact directory",
    requireCurrentUser: true
  }, async () => {
    const entries = (await readdir(directory)).sort(byteOrder);
    const expected = [...expectedFiles].sort(byteOrder);
    if (JSON.stringify(entries) !== JSON.stringify(expected)) {
      throw new Error("hosted candidate artifact directory contains an unexpected entry");
    }
  });
  return directory;
}

async function createTransport() {
  if (argumentsList.length !== 7) failUsage();
  const [identityPath, manifestPath, archivePath, evidencePath, signablesPath, sourceRevision, destination] = argumentsList;
  safeArtifactName(basename(destination), transportFilename, "transport evidence");
  await exactArtifactDirectory(
    [manifestPath, archivePath, evidencePath, signablesPath, destination],
    [basename(archivePath), manifestFilename, evidenceFilename, signablesFilename]
  );
  const inputs = await readInputs(identityPath, manifestPath, archivePath, evidencePath, signablesPath);
  const payloadValue = transportPayload(inputs, sourceRevision);
  rejectPrivatePresentation(payloadValue, "hosted candidate transport evidence");
  const payload = `${JSON.stringify(payloadValue, null, 2)}\n`;
  if (Buffer.byteLength(payload) > 64 * 1024) {
    throw new Error("hosted candidate transport evidence exceeds its public byte limit");
  }
  const output = resolve(destination);
  const temporary = join(dirname(output), `.${transportFilename}.${process.pid}.tmp`);
  await withAttestedDirectory(dirname(output), {
    label: "hosted candidate artifact directory",
    allowContentMutation: true,
    requireCurrentUser: true
  }, async () => {
    await writeFile(temporary, payload, { mode: 0o600, flag: "wx" });
    await chmod(temporary, 0o644);
    await rename(temporary, output);
  });
  await exactArtifactDirectory(
    [manifestPath, archivePath, evidencePath, signablesPath, destination],
    [basename(archivePath), manifestFilename, evidenceFilename, signablesFilename, transportFilename]
  );
  process.stdout.write("Created path-free hosted candidate transport evidence.\n");
}

async function verifyTransport() {
  if (argumentsList.length !== 12) failUsage();
  const [
    identityPath, manifestPath, archivePath, evidencePath, signablesPath, transportPath,
    sourceRevision, archiveUploadSHA, manifestUploadSHA, evidenceUploadSHA,
    signablesUploadSHA, transportUploadSHA
  ] = argumentsList;
  await exactArtifactDirectory(
    [manifestPath, archivePath, evidencePath, signablesPath, transportPath],
    [basename(archivePath), manifestFilename, evidenceFilename, signablesFilename, transportFilename]
  );
  const inputs = await readInputs(identityPath, manifestPath, archivePath, evidencePath, signablesPath);
  const transportInput = await boundedJSON(
    transportPath, "hosted candidate transport evidence", 64 * 1024
  );
  safeArtifactName(transportInput.descriptor.file, transportFilename, "transport evidence");
  const expected = transportPayload(inputs, sourceRevision);
  if (JSON.stringify(transportInput.value) !== JSON.stringify(expected)) {
    throw new Error("hosted candidate transport evidence does not match the downloaded candidate");
  }
  rejectPrivatePresentation(transportInput.value, "hosted candidate transport evidence");
  const actionDigests = [
    [archiveUploadSHA, inputs.archiveDescriptor.sha256, "archive"],
    [manifestUploadSHA, inputs.manifestInput.descriptor.sha256, "manifest"],
    [evidenceUploadSHA, inputs.evidenceInput.descriptor.sha256, "canonical evidence"],
    [signablesUploadSHA, inputs.signablesInput.descriptor.sha256, "Runtime Mach-O inventory"],
    [transportUploadSHA, transportInput.descriptor.sha256, "transport evidence"]
  ];
  for (const [reported, actual, label] of actionDigests) {
    if (exactSHA256(reported, `${label} upload digest`) !== actual) {
      throw new Error(`${label} upload digest does not match the downloaded bytes`);
    }
  }
  process.stdout.write(
    `Verified exact hosted candidate transport for ${expected.product} ${expected.version} (${expected.build}).\n`
  );
}

if (mode === "create") await createTransport();
else if (mode === "verify") await verifyTransport();
else failUsage();
