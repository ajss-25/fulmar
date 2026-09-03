import { basename } from "node:path";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";

const [path, expectedSHA, expectedVersion, rawBuild] = process.argv.slice(2);
const expectedBuild = Number(rawBuild);
if (process.argv.length !== 6 || !path || !/^[a-f0-9]{64}$/u.test(expectedSHA ?? "")
    || !/^\d+\.\d+\.\d+$/u.test(expectedVersion ?? "")
    || !Number.isSafeInteger(expectedBuild) || expectedBuild < 1) {
  throw new Error("usage: verify-public-external-evidence.mjs <evidence> <candidate-sha256> <version> <build>");
}
let evidenceFile;
try {
  evidenceFile = await readAttestedRegularFile(path, {
    label: "public external evidence",
    minimumBytes: 2,
    maximumBytes: 1024 * 1024,
    requireCurrentUser: true,
    requirePrivateMode: true,
    requireSingleLink: true
  });
} catch (error) {
  if (error?.code === "ENOENT") {
    throw new Error("public external evidence is missing for the exact candidate");
  }
  throw error;
}
let value;
try { value = JSON.parse(evidenceFile.bytes.toString("utf8")); }
catch { throw new Error("public external evidence is not valid JSON"); }
const requiredGates = [
  "cleanInstallCurrentMacOS", "cleanInstallMinimumMacOS", "fullGitHistoryAndSecretScan",
  "githubRepositoryControls", "legalAndTrademarkClearance", "permissionAndAccessibilityMatrix",
  "supportPrivacyAndExportReview", "twoVersionNotarizedUpdateRollback"
];
const exactKeys = (candidate, expected) => candidate && typeof candidate === "object"
  && !Array.isArray(candidate)
  && JSON.stringify(Object.keys(candidate).sort()) === JSON.stringify([...expected].sort());
if (!exactKeys(value, [
  "schemaVersion", "evidenceType", "version", "build", "candidate",
  "allRequiredGatesPassed", "gates"
]) || value.schemaVersion !== 1 || value.evidenceType !== "fulmar-public-external-evidence"
    || value.allRequiredGatesPassed !== true || !exactKeys(value.candidate, ["sha256"])
    || !exactKeys(value.gates, requiredGates)) {
  throw new Error("public external evidence is incomplete or belongs to another candidate");
}
if (value.version !== expectedVersion || value.build !== expectedBuild
    || value.candidate.sha256 !== expectedSHA) {
  throw new Error("public external evidence is stale or belongs to another candidate");
}
for (const gate of requiredGates) {
  const evidence = value.gates[gate];
  if (!exactKeys(evidence, ["status", "evidenceSHA256", "reference"])
      || evidence.status !== "passed" || !/^[a-f0-9]{64}$/u.test(evidence.evidenceSHA256 ?? "")
      || evidence.evidenceSHA256 === "0".repeat(64)
      || typeof evidence.reference !== "string" || evidence.reference.length < 1
      || evidence.reference.length > 200 || evidence.reference.trim() !== evidence.reference
      || /[\r\n\0]/u.test(evidence.reference)) {
    throw new Error(`public external gate is not closed with bounded evidence: ${gate}`);
  }
}
process.stdout.write(`${basename(evidenceFile.path)} is complete and candidate-bound across all 8 external gates.\n`);
