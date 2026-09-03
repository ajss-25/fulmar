#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const [summaryPath, inventoryPath, policyPath] = process.argv.slice(2);
if (!summaryPath || !inventoryPath || !policyPath) {
  throw new Error("usage: verify-static-security-summary.mjs <static-summary> <source-build-inputs> <SemgrepRules.json>");
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const compareText = (left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
const exactJSON = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const digestPattern = /^[a-f0-9]{64}$/u;

async function boundedJSON(pathArgument, expectedName, maximumBytes) {
  const path = resolve(pathArgument);
  const details = await lstat(path);
  const effectiveUID = typeof process.geteuid === "function" ? process.geteuid() : details.uid;
  if (basename(path) !== expectedName || !details.isFile() || details.isSymbolicLink()
      || details.nlink !== 1 || details.uid !== effectiveUID || (details.mode & 0o022) !== 0
      || details.size < 2 || details.size > maximumBytes) {
    throw new Error(`static-security evidence input is unsafe or unbounded: ${expectedName}`);
  }
  const bytes = await readFile(path);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`static-security evidence is not valid JSON: ${expectedName}`); }
  return { bytes, value };
}

function fail(message) {
  throw new Error(`Static security evidence failed: ${message}`);
}

const [summaryInput, inventoryInput, policyInput] = await Promise.all([
  boundedJSON(summaryPath, "static-security-summary.json", 512 * 1024),
  boundedJSON(inventoryPath, "source-build-inputs.json", 32 * 1024 * 1024),
  boundedJSON(policyPath, "SemgrepRules.json", 1024 * 1024)
]);
const summary = summaryInput.value;
const inventory = inventoryInput.value;
const policy = policyInput.value;

if (summary?.schemaVersion !== 1 || summary.passed !== true
    || summary.engineVersion !== policy.engineVersion || summary.unreviewedFindingCount !== 0) {
  fail("summary is absent, failed, or uses an unreviewed schema/engine");
}
if (inventory?.schemaVersion !== 1 || inventory.rootLabel !== "LocalHarnessBuildInputs"
    || inventory.algorithm !== "sha256" || !Array.isArray(inventory.inputRoots)
    || !Array.isArray(inventory.entries) || !inventory.totals) {
  fail("source-build inventory has an unsupported schema");
}
if (!Array.isArray(policy.secretScanTargets) || !Array.isArray(policy.binaryScanExclusions)
    || !Array.isArray(policy.topLevelExcludedEntries)
    || !Array.isArray(policy.vendorRuntimeGeneratedEntries)
    || !Array.isArray(policy.vendorRuntimeGeneratedPrefixes)
    || !Array.isArray(policy.reportWarningAllowlist) || !Array.isArray(policy.rules)) {
  fail("static-analysis policy has an unsupported schema");
}
const sortedInputRoots = [...inventory.inputRoots].sort(compareText);
const sortedScanRoots = [...policy.secretScanTargets].sort(compareText);
if (new Set(sortedInputRoots).size !== sortedInputRoots.length
    || new Set(sortedScanRoots).size !== sortedScanRoots.length
    || !exactJSON(sortedInputRoots, sortedScanRoots)) {
  fail("secret-scan roots do not exactly equal the frozen source-input roots");
}

const inventoryByPath = new Map();
for (const entry of inventory.entries) {
  if (!entry || typeof entry.path !== "string" || inventoryByPath.has(entry.path)) {
    fail("source-build inventory contains a malformed or duplicate path");
  }
  inventoryByPath.set(entry.path, entry);
}
const presentRoots = policy.secretScanTargets.filter((path) => inventoryByPath.has(path));
const coverage = summary.coverage;
if (!coverage || !Array.isArray(coverage.files)
    || !exactJSON(coverage.roots, presentRoots)
    || !exactJSON(coverage.excludedTopLevelEntries, policy.topLevelExcludedEntries)
    || !exactJSON(coverage.excludedVendorRuntimeEntries, policy.vendorRuntimeGeneratedEntries)
    || !exactJSON(coverage.excludedVendorRuntimePrefixes, policy.vendorRuntimeGeneratedPrefixes)
    || !exactJSON(coverage.reviewedBinaryExclusions, policy.binaryScanExclusions)) {
  fail("summary coverage policy no longer matches the frozen source policy");
}

const binaryPaths = new Set();
for (const exclusion of policy.binaryScanExclusions) {
  const frozen = inventoryByPath.get(exclusion?.path);
  if (!frozen || frozen.type !== "file" || frozen.sha256 !== exclusion.sha256
      || !digestPattern.test(exclusion.sha256 ?? "") || binaryPaths.has(exclusion.path)) {
    fail("a reviewed binary exclusion is absent, stale, or duplicated");
  }
  binaryPaths.add(exclusion.path);
}
const expectedFiles = inventory.entries
  .filter((entry) => entry.type === "file" && !binaryPaths.has(entry.path))
  .map(({ path, bytes, sha256: digest }) => ({ path, bytes, sha256: digest }));
const actualFiles = coverage.files;
for (let index = 0; index < actualFiles.length; index += 1) {
  const entry = actualFiles[index];
  if (!entry || typeof entry.path !== "string" || !Number.isSafeInteger(entry.bytes)
      || entry.bytes < 0 || !digestPattern.test(entry.sha256 ?? "")
      || (index > 0 && compareText(actualFiles[index - 1].path, entry.path) >= 0)) {
    fail("summary contains an unsafe, malformed, or duplicate source descriptor");
  }
}
if (!exactJSON(actualFiles, expectedFiles)) {
  fail("summary does not describe the exact frozen source-input file set");
}
const coveragePayload = Buffer.from(
  expectedFiles.map((entry) => `${entry.path}\u0000${entry.bytes}\u0000${entry.sha256}\n`).join(""),
  "utf8"
);
const expectedTextBytes = expectedFiles.reduce((total, entry) => total + entry.bytes, 0);
if (coverage.textFileCount !== expectedFiles.length || coverage.textFileBytes !== expectedTextBytes
    || coverage.sha256 !== sha256(coveragePayload)) {
  fail("summary aggregate coverage digest or counts are stale");
}

const expectedWarnings = policy.reportWarningAllowlist.map((entry) => ({
  scan: entry.scan,
  path: entry.path,
  rule: entry.rule,
  level: entry.level,
  code: entry.code,
  reason: entry.reason,
  sourceSha256: entry.sourceSha256
}));
const warningKey = (entry) => `${entry.scan}\u0000${entry.path}\u0000${entry.rule}`;
const actualWarnings = Array.isArray(summary.reviewedReportWarnings)
  ? [...summary.reviewedReportWarnings].sort((left, right) => compareText(warningKey(left), warningKey(right)))
  : [];
expectedWarnings.sort((left, right) => compareText(warningKey(left), warningKey(right)));
if (new Set(actualWarnings.map(warningKey)).size !== actualWarnings.length
    || !exactJSON(actualWarnings, expectedWarnings)) {
  fail("reviewed parser-warning evidence is absent or stale");
}
for (const warning of expectedWarnings) {
  if (inventoryByPath.get(warning.path)?.sha256 !== warning.sourceSha256) {
    fail("a reviewed parser warning is not bound to the frozen source bytes");
  }
}

const expectedRules = new Map(policy.rules.map((rule) => [rule.id, rule]));
if (!Array.isArray(summary.rules) || summary.rules.length !== expectedRules.size) {
  fail("pinned rule-material evidence is incomplete");
}
for (const material of summary.rules) {
  const reviewed = expectedRules.get(material?.id);
  if (!reviewed || material.digestMode !== reviewed.digestMode
      || material.digest !== reviewed.sha256 || material.byteCount !== reviewed.byteCount
      || material.ruleCount !== reviewed.ruleCount || !digestPattern.test(material.rawDigest ?? "")) {
    fail("pinned rule-material evidence drifted");
  }
}

const scans = [summary.scans?.default, summary.scans?.secretsLanguageSpecific, summary.scans?.secretsFullText];
if (scans.some((scan) => !scan || !digestPattern.test(scan.reportSha256 ?? "")
    || !Number.isSafeInteger(scan.scannedPathCount) || scan.scannedPathCount < 0
    || !Number.isSafeInteger(scan.rawFindingCount) || scan.rawFindingCount < 0
    || !Number.isSafeInteger(scan.reviewedWarningCount) || scan.reviewedWarningCount < 0)
    || summary.scans.secretsLanguageSpecific.scannedPathCount !== expectedFiles.length
    || summary.scans.secretsFullText.scannedPathCount !== expectedFiles.length
    || summary.scans.secretsLanguageSpecific.rawFindingCount !== 0
    || summary.scans.secretsFullText.rawFindingCount !== 0) {
  fail("Semgrep report evidence is incomplete or does not cover every frozen text input");
}

process.stdout.write(
  `Verified static-security evidence for ${expectedFiles.length} frozen source text file(s), ${summaryInput.bytes.length} summary bytes.\n`
);
