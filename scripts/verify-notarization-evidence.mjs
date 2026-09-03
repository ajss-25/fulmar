#!/usr/bin/env node

import { basename } from "node:path";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";

const [submissionPath, logPath] = process.argv.slice(2);
if (!submissionPath || !logPath) {
  throw new Error("usage: verify-notarization-evidence.mjs <submission.json> <log.json>");
}

async function boundedPrivateJSON(path, maximumBytes) {
  let input;
  try {
    input = await readAttestedRegularFile(path, {
      label: "notarization evidence",
      minimumBytes: 2,
      maximumBytes,
      requirePrivateMode: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`notarization evidence is missing: ${basename(path)}`);
    }
    throw new Error(`notarization evidence could not be inspected: ${basename(path)}`);
  }
  try { return JSON.parse(input.bytes.toString("utf8")); }
  catch { throw new Error(`notarization evidence is not valid JSON: ${basename(path)}`); }
}

const submission = await boundedPrivateJSON(submissionPath, 1024 * 1024);
const log = await boundedPrivateJSON(logPath, 16 * 1024 * 1024);
if (submission.status !== "Accepted" || typeof submission.id !== "string"
    || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iu.test(submission.id)) {
  throw new Error("notarization submission is not one Accepted UUID receipt");
}
const issueFree = log.issues === null
  || (Array.isArray(log.issues) && log.issues.length === 0);
if (log.jobId !== submission.id || log.status !== "Accepted" || !issueFree) {
  throw new Error("notarization log is mismatched, not Accepted, or contains unresolved issues");
}
process.stdout.write(`Verified Accepted issue-free notarization evidence for job ${submission.id}.\n`);
