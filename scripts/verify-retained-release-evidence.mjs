#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  readAttestedRegularFile, sha256AttestedRegularFile, withAttestedDirectory
} from "./attested-regular-file.mjs";

const [identityPath, manifestPath, buildDirectoryArgument, stagedSetArgument] = process.argv.slice(2);
const buildDirectory = resolve(buildDirectoryArgument ?? "");
if (!identityPath || !manifestPath || !buildDirectoryArgument) {
  throw new Error("usage: verify-retained-release-evidence.mjs <identity> <manifest> <build-directory> [private-staged-set]");
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function boundedRegular(path, maximumBytes, privateMode = false) {
  return (await readAttestedRegularFile(path, {
    label: "release evidence",
    minimumBytes: 1,
    maximumBytes,
    requireCurrentUser: true,
    requirePrivateMode: privateMode,
    requireSingleLink: true
  })).bytes;
}

const verificationMessage = await withAttestedDirectory(buildDirectory, {
  label: "release evidence build directory",
  requireCurrentUser: true,
  requirePrivateMode: true
}, async () => {

const [identityBytes, manifestBytes] = await Promise.all([
  boundedRegular(identityPath, 64 * 1024),
  boundedRegular(manifestPath, 1024 * 1024)
]);
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
    || !Number.isSafeInteger(manifest.archiveBytes) || manifest.archiveBytes < 1
    || !/^[a-f0-9]{64}$/u.test(manifest.sha256) || manifest.schemaVersion !== 6
    || !validDescriptor(staticSecurity, "static-security-summary.json")
    || !validDescriptor(buildInputs, "source-build-inputs.json")) {
  throw new Error("retained evidence identity and manifest are not one valid candidate");
}

const base = `release-verify-${identity.appVersion}-build${identity.appBuild}`;
const expectedSetName = `${base}-${manifest.sha256}.evidence`;
const setDirectory = stagedSetArgument ? resolve(stagedSetArgument) : join(buildDirectory, expectedSetName);
return withAttestedDirectory(setDirectory, {
  label: "release evidence set directory",
  requireCurrentUser: true,
  requirePrivateMode: true
}, async ({ metadata: setDetails }) => {
const expectedUID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : setDetails.uid;
const stagedName = basename(setDirectory);
const validStagedName = stagedSetArgument
  && dirname(setDirectory) === buildDirectory
  && stagedName.startsWith(`.${base}-set.`)
  && stagedName.length <= base.length + 64;
if (!setDetails.isDirectory() || setDetails.isSymbolicLink() || setDetails.uid !== expectedUID
    || (setDetails.mode & 0o077n) !== 0n
    || (stagedSetArgument ? !validStagedName : stagedName !== expectedSetName)) {
  throw new Error("release evidence set is not one private candidate-specific directory");
}
const expectedEntries = [`${base}-ci-evidence.json`, `${base}.json`, `${base}.log`];
const entries = (await readdir(setDirectory)).sort();
if (JSON.stringify(entries) !== JSON.stringify(expectedEntries)) {
  throw new Error("release evidence set does not contain exactly its three reviewed files");
}
const recordPath = join(setDirectory, `${base}.json`);
const transcriptPath = join(setDirectory, `${base}.log`);
const summaryPath = join(setDirectory, `${base}-ci-evidence.json`);
const archivePath = join(buildDirectory, manifest.archive);
const [recordBytes, transcript, summaryBytes, archive, staticSecurityBytes, buildInputBytes] = await Promise.all([
  boundedRegular(recordPath, 1024 * 1024, true),
  boundedRegular(transcriptPath, 64 * 1024 * 1024, true),
  boundedRegular(summaryPath, 64 * 1024, true),
  sha256AttestedRegularFile(archivePath, {
    label: "retained candidate archive",
    minimumBytes: 1,
    maximumBytes: 1024 * 1024 * 1024,
    requireCurrentUser: true,
    requirePrivateMode: true,
    requireSingleLink: true
  }),
  boundedRegular(join(buildDirectory, staticSecurity.file), 512 * 1024),
  boundedRegular(join(buildDirectory, buildInputs.file), 32 * 1024 * 1024)
]);
const record = JSON.parse(recordBytes.toString("utf8"));
const summary = JSON.parse(summaryBytes.toString("utf8"));
let staticSecurityValue;
try { staticSecurityValue = JSON.parse(staticSecurityBytes.toString("utf8")); }
catch { throw new Error("retained static-security evidence is not valid JSON"); }
if (archive.bytes !== manifest.archiveBytes || archive.sha256 !== manifest.sha256) {
  throw new Error("retained candidate archive no longer matches its release manifest");
}
if (staticSecurityBytes.length !== staticSecurity.bytes
    || sha256(staticSecurityBytes) !== staticSecurity.sha256
    || staticSecurityValue.schemaVersion !== 1 || staticSecurityValue.passed !== true
    || staticSecurityValue.unreviewedFindingCount !== 0) {
  throw new Error("retained static-security evidence no longer matches its release manifest");
}
if (buildInputBytes.length !== buildInputs.bytes || sha256(buildInputBytes) !== buildInputs.sha256) {
  throw new Error("retained source-build evidence no longer matches its release manifest");
}
if (record.schemaVersion !== 3 || record.product !== identity.productDisplayName
    || record.version !== identity.appVersion || record.build !== identity.appBuild
    || record.candidate?.archive !== manifest.archive
    || record.candidate?.bytes !== archive.bytes || record.candidate?.sha256 !== manifest.sha256
    || record.candidate?.manifest !== basename(manifestPath)
    || record.candidate?.manifestSHA256 !== sha256(manifestBytes)
    || JSON.stringify(record.staticSecurity) !== JSON.stringify({
      ...staticSecurity,
      sourceBuildInputsSHA256: buildInputs.sha256
    })
    || record.transcript?.file !== `${base}.log`
    || record.transcript?.bytes !== transcript.length
    || record.transcript?.sha256 !== sha256(transcript)
    || record.fullHardwareSummary?.file !== `${base}-ci-evidence.json`
    || record.fullHardwareSummary?.bytes !== summaryBytes.length
    || record.fullHardwareSummary?.sha256 !== sha256(summaryBytes)
    || summary.schemaVersion !== 1
    || summary.evidenceType !== "fulmar-candidate-qualification"
    || summary.profile !== "full-hardware"
    || summary.product !== identity.productDisplayName
    || summary.version !== identity.appVersion || summary.build !== identity.appBuild
    || summary.candidate?.archive !== manifest.archive
    || summary.candidate?.bytes !== manifest.archiveBytes
    || summary.candidate?.sha256 !== manifest.sha256
    || summary.evidence?.releaseManifest?.sha256 !== sha256(manifestBytes)
    || JSON.stringify(summary.evidence?.inventories?.staticSecurity) !== JSON.stringify(staticSecurity)
    || summary.gates?.deterministicCandidate !== "passed"
    || summary.gates?.physicalQwenHardware !== "passed"
    || summary.finalPublicReleaseQualified !== false) {
  throw new Error("retained full-hardware evidence no longer matches the exact candidate");
}
const transcriptText = transcript.toString("utf8");
const expectedManifestLine = `Release manifest verified for ${identity.appVersion} (${identity.appBuild}), ${manifest.archiveBytes} bytes, ${manifest.sha256}.`;
if (!transcriptText.includes(expectedManifestLine)
    || !transcriptText.includes("Release verification passed against the extracted archive:")) {
  throw new Error("retained transcript does not prove the exact successful candidate");
}
return `Verified retained full-hardware evidence for ${identity.appVersion} build ${identity.appBuild}.\n`;
});
});
process.stdout.write(verificationMessage);
