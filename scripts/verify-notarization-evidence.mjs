#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { basename } from "node:path";

const [submissionPath, logPath] = process.argv.slice(2);
if (!submissionPath || !logPath) {
  throw new Error("usage: verify-notarization-evidence.mjs <submission.json> <log.json>");
}

async function boundedPrivateJSON(path, maximumBytes) {
  let details;
  try {
    details = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`notarization evidence is missing: ${basename(path)}`);
    }
    throw new Error(`notarization evidence could not be inspected: ${basename(path)}`);
  }
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || (details.mode & 0o077) !== 0 || details.size < 2 || details.size > maximumBytes) {
    throw new Error(`notarization evidence is not one bounded private regular file: ${basename(path)}`);
  }
  const bytes = await readFile(path);
  try { return JSON.parse(bytes.toString("utf8")); }
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
