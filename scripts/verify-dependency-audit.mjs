import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const [summaryPath, lockPath] = process.argv.slice(2);
if (!summaryPath || !lockPath) throw new Error("usage: verify-dependency-audit.mjs <summary.json> <package-lock.json>");
const summary = JSON.parse(await readFile(summaryPath, "utf8"));
const lockHash = createHash("sha256").update(await readFile(lockPath)).digest("hex");
const generated = Date.parse(summary.generatedAt);
const age = Date.now() - generated;
let registry;
try { registry = new URL(summary.registry); }
catch { throw new Error("dependency audit summary has an invalid registry identity"); }
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
    || !Number.isFinite(generated)
    || age < -300_000
    || age > 86_400_000
    || summary.vulnerabilities?.total !== 0
    || !Array.isArray(summary.unresolved)
    || summary.unresolved.length !== 0) {
  throw new Error("dependency audit summary is stale, incomplete, for another lockfile, or has unresolved production findings");
}
process.stdout.write(`Dependency audit evidence is current and records zero unresolved production vulnerabilities (${summary.generatedAt}).\n`);
