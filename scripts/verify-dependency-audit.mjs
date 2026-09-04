import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  advisoryBatchSize,
  advisoryEndpoint,
  productionAdvisoryPayload,
  splitAdvisoryBatches
} from "./audit-dependencies.mjs";

const [summaryPath, lockPath] = process.argv.slice(2);
if (!summaryPath || !lockPath) throw new Error("usage: verify-dependency-audit.mjs <summary.json> <package-lock.json>");
const summary = JSON.parse(await readFile(summaryPath, "utf8"));
const lockBytes = await readFile(lockPath);
const lockHash = createHash("sha256").update(lockBytes).digest("hex");
const graph = productionAdvisoryPayload(
  JSON.parse(await readFile(join(dirname(lockPath), "package.json"), "utf8")),
  JSON.parse(lockBytes)
);
const expectedBatches = splitAdvisoryBatches(graph.payload);
const generated = Date.parse(summary.generatedAt);
const age = Date.now() - generated;
let registry;
try { registry = new URL(summary.registry); }
catch { throw new Error("dependency audit summary has an invalid registry identity"); }
const batchesAreComplete = Array.isArray(summary.batches)
  && summary.batches.length === summary.batchCount
  && summary.batches.every((batch, index) => batch?.index === index
    && batch.packageNameCount === Object.keys(expectedBatches[index] ?? {}).length
    && Number.isSafeInteger(batch.attemptCount) && batch.attemptCount >= 1 && batch.attemptCount <= 64
    && batch.requestSHA256 === createHash("sha256")
      .update(Buffer.from(JSON.stringify(expectedBatches[index]), "utf8")).digest("hex")
    && /^[a-f0-9]{64}$/u.test(batch.responseSHA256))
  && summary.batches.reduce((total, batch) => total + batch.packageNameCount, 0) === graph.packageNameCount;
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
    || summary.auditTransport !== "npm-bulk-advisory-v1"
    || summary.auditEndpoint !== advisoryEndpoint(registry).href
    || summary.auditReportVersion !== 2
    || summary.advisoryBatchSize !== advisoryBatchSize
    || summary.packageNameCount !== graph.packageNameCount
    || summary.packageVersionCount !== graph.packageVersionCount
    || summary.packageGraphSHA256 !== graph.graphSHA256
    || summary.batchCount !== Math.ceil(graph.packageNameCount / advisoryBatchSize)
    || !batchesAreComplete
    || !Number.isFinite(generated)
    || age < -300_000
    || age > 86_400_000
    || summary.vulnerabilities?.info !== 0
    || summary.vulnerabilities?.low !== 0
    || summary.vulnerabilities?.moderate !== 0
    || summary.vulnerabilities?.high !== 0
    || summary.vulnerabilities?.critical !== 0
    || summary.vulnerabilities?.total !== 0
    || !Array.isArray(summary.unresolved)
    || summary.unresolved.length !== 0) {
  throw new Error("dependency audit summary is stale, incomplete, for another lockfile, or has unresolved production findings");
}
process.stdout.write(`Dependency audit evidence is current and records zero unresolved production vulnerabilities across ${summary.packageNameCount} packages (${summary.generatedAt}).\n`);
