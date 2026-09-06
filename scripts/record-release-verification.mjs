#!/usr/bin/env node
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  readAttestedRegularFile, sha256AttestedRegularFile, withAttestedDirectories,
  withAttestedDirectory
} from "./attested-regular-file.mjs";

const [identityPath, manifestPath, transcriptPath, summaryPath, destination, summaryDestination] = process.argv.slice(2);
if (!summaryDestination) {
  throw new Error("usage: record-release-verification.mjs <identity> <manifest> <transcript> <ci-summary> <destination> <summary-destination>");
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function boundedArtifact(path, maximumBytes) {
  return (await readAttestedRegularFile(path, {
    label: "release evidence artifact",
    minimumBytes: 2,
    maximumBytes,
    requireCurrentUser: true,
    requireSingleLink: true
  })).bytes;
}
const captured = await withAttestedDirectories(
  [dirname(identityPath), dirname(manifestPath), dirname(transcriptPath), dirname(summaryPath)],
  { label: "release evidence input directory", requireCurrentUser: true },
  async () => {
const identityBytes = await boundedArtifact(identityPath, 64 * 1024);
const manifestBytes = await boundedArtifact(manifestPath, 1024 * 1024);
const identity = JSON.parse(identityBytes.toString("utf8"));
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const staticSecurity = manifest.inventories?.staticSecurity;
const buildInputs = manifest.inventories?.buildInputs;
const validDescriptor = (descriptor, expectedFile) => descriptor?.file === expectedFile
  && Number.isSafeInteger(descriptor.bytes) && descriptor.bytes > 1
  && typeof descriptor.sha256 === "string" && /^[a-f0-9]{64}$/u.test(descriptor.sha256);
if (!/^\d+\.\d+\.\d+$/u.test(identity.appVersion)
    || !Number.isSafeInteger(identity.appBuild) || identity.appBuild < 1
    || manifest.version !== identity.appVersion || manifest.build !== identity.appBuild
    || manifest.archive !== identity.releaseArchiveName
    || !/^[a-f0-9]{64}$/u.test(manifest.sha256) || manifest.schemaVersion !== 6
    || !validDescriptor(staticSecurity, "static-security-summary.json")
    || !validDescriptor(buildInputs, "source-build-inputs.json")) {
  throw new Error("release identity and manifest are not the same valid candidate");
}
const archivePath = join(dirname(manifestPath), manifest.archive);
const transcript = (await readAttestedRegularFile(transcriptPath, {
  label: "release transcript",
  minimumBytes: 1,
  maximumBytes: 64 * 1024 * 1024,
  requireCurrentUser: true,
  requirePrivateMode: true,
  requireSingleLink: true
})).bytes;
const [archive, summaryBytes, staticSecurityBytes, buildInputBytes] = await Promise.all([
  sha256AttestedRegularFile(archivePath, {
    label: "candidate archive",
    minimumBytes: 1,
    maximumBytes: 1024 * 1024 * 1024,
    requireCurrentUser: true,
    requirePrivateMode: true,
    requireSingleLink: true
  }),
  boundedArtifact(summaryPath, 64 * 1024),
  boundedArtifact(join(dirname(manifestPath), staticSecurity.file), 512 * 1024),
  boundedArtifact(join(dirname(manifestPath), buildInputs.file), 32 * 1024 * 1024)
]);
if (transcript.length < 1 || archive.bytes !== manifest.archiveBytes || archive.sha256 !== manifest.sha256) {
  throw new Error("verified candidate archive no longer matches its manifest");
}
let staticSecurityValue;
try { staticSecurityValue = JSON.parse(staticSecurityBytes.toString("utf8")); }
catch { throw new Error("static-security release evidence is not valid JSON"); }
if (staticSecurityBytes.length !== staticSecurity.bytes || sha256(staticSecurityBytes) !== staticSecurity.sha256
    || buildInputBytes.length !== buildInputs.bytes || sha256(buildInputBytes) !== buildInputs.sha256
    || staticSecurityValue.schemaVersion !== 1 || staticSecurityValue.passed !== true
    || staticSecurityValue.unreviewedFindingCount !== 0) {
  throw new Error("static-security release evidence no longer matches the exact source inventory and manifest");
}
let summary;
try { summary = JSON.parse(summaryBytes.toString("utf8")); }
catch { throw new Error("full-hardware CI evidence is not valid JSON"); }
if (summary.schemaVersion !== 1 || summary.evidenceType !== "fulmar-candidate-qualification"
    || summary.profile !== "full-hardware" || summary.product !== identity.productDisplayName
    || summary.version !== identity.appVersion || summary.build !== identity.appBuild
    || summary.candidate?.archive !== manifest.archive
    || summary.candidate?.bytes !== manifest.archiveBytes
    || summary.candidate?.sha256 !== manifest.sha256
    || summary.evidence?.releaseManifest?.sha256 !== sha256(manifestBytes)
    || JSON.stringify(summary.evidence?.inventories?.staticSecurity) !== JSON.stringify(staticSecurity)
    || summary.gates?.deterministicCandidate !== "passed"
    || summary.gates?.physicalQwenHardware !== "passed"
    || summary.finalPublicReleaseQualified !== false) {
  throw new Error("CI evidence is not the exact successful full-hardware candidate summary");
}
const transcriptText = transcript.toString("utf8");
const expectedManifestLine = `Release manifest verified for ${identity.appVersion} (${identity.appBuild}), ${manifest.archiveBytes} bytes, ${manifest.sha256}.`;
if (!transcriptText.includes(expectedManifestLine)
    || !transcriptText.includes("Release verification passed against the extracted archive:")) {
  throw new Error("release transcript is not cryptographically bound to this successful candidate");
}
const expectedBase = `release-verify-${identity.appVersion}-build${identity.appBuild}`;
const record = {
  schemaVersion: 3,
  product: identity.productDisplayName,
  version: identity.appVersion,
  build: identity.appBuild,
  candidate: {
    archive: manifest.archive,
    bytes: archive.bytes,
    sha256: manifest.sha256,
    manifest: basename(manifestPath),
    manifestSHA256: sha256(manifestBytes)
  },
  staticSecurity: {
    ...staticSecurity,
    sourceBuildInputsSHA256: buildInputs.sha256
  },
  transcript: {
    file: `${expectedBase}.log`,
    bytes: transcript.length,
    sha256: sha256(transcript)
  },
  fullHardwareSummary: {
    file: `${expectedBase}-ci-evidence.json`,
    bytes: summaryBytes.length,
    sha256: sha256(summaryBytes)
  }
};
return { record, summaryBytes };
});
const { record, summaryBytes } = captured;
async function writePrivate(path, bytes) {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}
await withAttestedDirectory(dirname(destination), {
  label: "release evidence output directory",
  allowContentMutation: true,
  requireCurrentUser: true,
  requirePrivateMode: true
}, async () => {
  await writePrivate(destination, `${JSON.stringify(record, null, 2)}\n`);
  await writePrivate(summaryDestination, summaryBytes);
  const evidenceDirectory = await open(dirname(destination), constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await evidenceDirectory.sync(); } finally { await evidenceDirectory.close(); }
});
