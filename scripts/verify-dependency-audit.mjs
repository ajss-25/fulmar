import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  advisoryBatchSize,
  advisoryEndpoint,
  osvFallbackProvenance,
  osvQueryBatchEndpoint,
  osvQueryBatchSize,
  productionAdvisoryPayload,
  publicNPMRegistry,
  splitAdvisoryBatches,
  splitOSVQueryBatches
} from "./audit-dependencies.mjs";

const [summaryPath, lockPath] = process.argv.slice(2);
if (!summaryPath || !lockPath) throw new Error("usage: verify-dependency-audit.mjs <summary.json> <package-lock.json>");

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected) {
  return plainObject(value)
    && Object.keys(value).sort().join("\u0000") === [...expected].sort().join("\u0000");
}

function digestJSON(value) {
  return createHash("sha256").update(Buffer.from(JSON.stringify(value), "utf8")).digest("hex");
}

const summary = JSON.parse(await readFile(summaryPath, "utf8"));
const lockBytes = await readFile(lockPath);
const lockDocument = JSON.parse(lockBytes);
const lockHash = createHash("sha256").update(lockBytes).digest("hex");
const graph = productionAdvisoryPayload(
  JSON.parse(await readFile(join(dirname(lockPath), "package.json"), "utf8")),
  lockDocument
);
const expectedNPMBatches = splitAdvisoryBatches(graph.payload);
const expectedOSVBatches = splitOSVQueryBatches(graph.payload);
const generated = Date.parse(summary.generatedAt);
const age = Date.now() - generated;
let registry;
try { registry = new URL(summary.registry); }
catch { throw new Error("dependency audit summary has an invalid registry identity"); }

const zeroVulnerabilities = exactKeys(summary.vulnerabilities, [
  "info", "low", "moderate", "high", "critical", "unknown", "total"
]) && Object.values(summary.vulnerabilities).every((value) => value === 0);
const commonSummaryKeys = Object.freeze([
  "schemaVersion", "generatedAt", "productionOnly", "packageLockSHA256", "nodeVersion",
  "npmVersion", "registry", "auditTransport", "auditEndpoint", "auditReportVersion",
  "packageNameCount", "packageVersionCount", "packageGraphSHA256", "batchCount", "batches",
  "vulnerabilities", "unresolved"
]);

function validNPMEvidence() {
  const batchesAreComplete = Array.isArray(summary.batches)
    && summary.batches.length === expectedNPMBatches.length
    && summary.batches.every((batch, index) => exactKeys(batch, [
      "index", "packageNameCount", "attemptCount", "requestSHA256", "responseSHA256"
    ])
      && batch.index === index
      && batch.packageNameCount === Object.keys(expectedNPMBatches[index]).length
      && Number.isSafeInteger(batch.attemptCount) && batch.attemptCount >= 1 && batch.attemptCount <= 2
      && batch.requestSHA256 === digestJSON(expectedNPMBatches[index])
      && /^[a-f0-9]{64}$/u.test(batch.responseSHA256))
    && summary.batches.reduce((total, batch) => total + batch.packageNameCount, 0)
      === graph.packageNameCount;
  return exactKeys(summary, [...commonSummaryKeys, "advisoryBatchSize"])
    && summary.auditTransport === "npm-bulk-advisory-v1"
    && summary.auditEndpoint === advisoryEndpoint(registry).href
    && summary.advisoryBatchSize === advisoryBatchSize
    && summary.batchCount === expectedNPMBatches.length
    && summary.fallbackFrom === undefined
    && summary.queryBatchSize === undefined
    && summary.queryCount === undefined
    && summary.packageNodeCount === undefined
    && summary.packageNodeProvenanceSHA256 === undefined
    && batchesAreComplete;
}

function validOSVEvidence() {
  if (registry.href !== publicNPMRegistry || summary.auditEndpoint !== osvQueryBatchEndpoint) return false;
  let provenance;
  try { provenance = osvFallbackProvenance(lockDocument); }
  catch { return false; }
  const allowedFailureClasses = new Set([
    "deadline-exceeded", "network-unavailable", "retryable-http"
  ]);
  const fallback = summary.fallbackFrom;
  const fallbackIsExact = exactKeys(fallback, [
    "auditTransport", "auditEndpoint", "reason", "failureClass", "failedBatchIndex",
    "attemptCount", "requestSHA256"
  ])
    && fallback.auditTransport === "npm-bulk-advisory-v1"
    && fallback.auditEndpoint === advisoryEndpoint(registry).href
    && fallback.reason === "primary-service-unavailable"
    && allowedFailureClasses.has(fallback.failureClass)
    && Number.isSafeInteger(fallback.failedBatchIndex)
    && fallback.failedBatchIndex >= 0 && fallback.failedBatchIndex < expectedNPMBatches.length
    && fallback.attemptCount === 2
    && fallback.requestSHA256 === digestJSON(expectedNPMBatches[fallback.failedBatchIndex]);
  const batchesAreComplete = Array.isArray(summary.batches)
    && summary.batches.length === expectedOSVBatches.length
    && summary.batches.every((batch, index) => exactKeys(batch, [
      "index", "queryCount", "resultCount", "findingCount", "attemptCount",
      "requestSHA256", "responseSHA256"
    ])
      && batch.index === index
      && batch.queryCount === expectedOSVBatches[index].queries.length
      && batch.resultCount === batch.queryCount
      && batch.findingCount === 0
      && Number.isSafeInteger(batch.attemptCount) && batch.attemptCount >= 1 && batch.attemptCount <= 2
      && batch.requestSHA256 === digestJSON(expectedOSVBatches[index])
      && /^[a-f0-9]{64}$/u.test(batch.responseSHA256))
    && summary.batches.reduce((total, batch) => total + batch.queryCount, 0)
      === graph.packageVersionCount;
  return exactKeys(summary, [
    ...commonSummaryKeys, "queryBatchSize", "queryCount", "packageNodeCount",
    "packageNodeProvenanceSHA256", "fallbackFrom"
  ])
    && summary.auditTransport === "osv-querybatch-v1-fallback"
    && summary.advisoryBatchSize === undefined
    && summary.queryBatchSize === osvQueryBatchSize
    && summary.queryCount === graph.packageVersionCount
    && summary.packageNodeCount === provenance.packageNodeCount
    && summary.packageNodeProvenanceSHA256 === provenance.packageNodeProvenanceSHA256
    && summary.batchCount === expectedOSVBatches.length
    && fallbackIsExact
    && batchesAreComplete;
}

const transportEvidenceIsComplete = validNPMEvidence() || validOSVEvidence();
if (summary.schemaVersion !== 1
    || summary.productionOnly !== true
    || summary.packageLockSHA256 !== lockHash
    || summary.nodeVersion !== "v22.23.1"
    || summary.npmVersion !== "10.9.8"
    || registry.href !== summary.registry
    || registry.protocol !== "https:"
    || registry.username !== ""
    || registry.password !== ""
    || registry.search !== ""
    || registry.hash !== ""
    || summary.auditReportVersion !== 2
    || summary.packageNameCount !== graph.packageNameCount
    || summary.packageVersionCount !== graph.packageVersionCount
    || summary.packageGraphSHA256 !== graph.graphSHA256
    || summary.batchCount !== summary.batches?.length
    || !transportEvidenceIsComplete
    || !Number.isFinite(generated)
    || age < -300_000
    || age > 86_400_000
    || !zeroVulnerabilities
    || !Array.isArray(summary.unresolved)
    || summary.unresolved.length !== 0) {
  throw new Error("dependency audit summary is stale, incomplete, for another lockfile, or has unresolved production findings");
}
process.stdout.write(
  `Dependency audit evidence is current and records zero unresolved production vulnerabilities across ${summary.packageNameCount} packages (${summary.generatedAt}).\n`
);
