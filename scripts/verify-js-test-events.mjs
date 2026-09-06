#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readSync, readdirSync, realpathSync } from "node:fs";
import { join, relative } from "node:path";

const [eventPath, profile, project] = process.argv.slice(2);
if (process.argv.length !== 5 || !["focused", "full-source", "full-candidate"].includes(profile)
    || !/^\/private\/tmp\/fulmar-js-tests\.[A-Za-z0-9]+\/events-[a-f0-9]{32}\.jsonl$/u.test(eventPath ?? "")
    || !project?.startsWith("/")) {
  throw new Error("usage: verify-js-test-events.mjs <private-events> <focused|full-source|full-candidate> <project>");
}
const canonicalProject = realpathSync(project);

const descriptor = openSync(eventPath, constants.O_RDONLY | constants.O_NOFOLLOW);
let bytes;
try {
  const before = fstatSync(descriptor);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== process.getuid() || (before.mode & 0o777) !== 0o600
      || before.size < 1 || before.size > 32 * 1024 * 1024) {
    throw new Error("JavaScript event stream has unsafe metadata");
  }
  bytes = Buffer.alloc(before.size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count < 1) throw new Error("JavaScript event stream was truncated while reading");
    offset += count;
  }
  const after = fstatSync(descriptor);
  if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) {
    throw new Error("JavaScript event stream changed while reading");
  }
} finally { closeSync(descriptor); }
if (bytes.at(-1) !== 0x0a) throw new Error("JavaScript event stream is unterminated");
const lines = bytes.toString("utf8").split("\n").slice(0, -1);
if (lines.length < 4 || lines.length > 65_536) throw new Error("JavaScript event stream has an invalid record count");
const records = lines.map((line, index) => {
  if (line.length < 2 || line.length > 64 * 1024) throw new Error(`invalid JavaScript event line ${index + 1}`);
  let value;
  try { value = JSON.parse(line); } catch { throw new Error(`malformed JavaScript event JSON on line ${index + 1}`); }
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.type !== "string") {
    throw new Error(`invalid JavaScript event record on line ${index + 1}`);
  }
  return value;
});

const starts = records.filter((record) => record.type === "test:start");
const passes = records.filter((record) => record.type === "test:pass");
const failures = records.filter((record) => record.type === "test:fail");
const plans = records.filter((record) => record.type === "test:plan" && record.nesting === 0);
const summaries = records.filter((record) => record.type === "test:summary");
const canonicalHelper = realpathSync(join(canonicalProject, "Tests", "JS", "RootWatchdogChildProcess.mjs"));
const relativeHelper = relative(canonicalProject, canonicalHelper);
const normalizedSyntheticHelperFile = (record) => {
  if (record.file !== undefined || typeof record.name !== "string" || record.nesting !== 0) return undefined;
  if (record.name !== relativeHelper && record.name !== canonicalHelper) return undefined;
  let candidate;
  try {
    candidate = realpathSync(record.name === relativeHelper
      ? join(canonicalProject, relativeHelper) : record.name);
  } catch { return undefined; }
  return candidate === canonicalHelper ? canonicalHelper : undefined;
};
const normalizedFile = (record) =>
  typeof record.file === "string" ? record.file : normalizedSyntheticHelperFile(record);
const missingFileStarts = starts.filter((record) => typeof record.file !== "string");
const missingFilePasses = passes.filter((record) => typeof record.file !== "string");
const syntheticHelperPairPresent = missingFileStarts.length !== 0 || missingFilePasses.length !== 0;
const syntheticHelperPairValid = !syntheticHelperPairPresent || (
  missingFileStarts.length === 1 && missingFilePasses.length === 1
  && normalizedSyntheticHelperFile(missingFileStarts[0]) === canonicalHelper
  && normalizedSyntheticHelperFile(missingFilePasses[0]) === canonicalHelper
  && missingFileStarts[0].testNumber === undefined
  && Number.isSafeInteger(missingFilePasses[0].testNumber)
  && missingFilePasses[0].testNumber > 0
  && missingFileStarts[0].skip === undefined && missingFileStarts[0].todo === undefined
  && missingFilePasses[0].skip === undefined && missingFilePasses[0].todo === undefined
);
const key = (record) => `${normalizedFile(record) ?? ""}\0${record.nesting ?? ""}\0${record.name ?? ""}`;
const startKeys = starts.map(key).sort();
const passKeys = passes.map(key).sort();
const invalidStartName = starts.filter((record) => typeof record.name !== "string").length;
const invalidStartFile = starts.filter((record) => typeof normalizedFile(record) !== "string").length;
const invalidStartNesting = starts.filter((record) =>
  !Number.isSafeInteger(record.nesting) || record.nesting < 0).length;
const invalidPassName = passes.filter((record) => typeof record.name !== "string").length;
const invalidPassFile = passes.filter((record) => typeof normalizedFile(record) !== "string").length;
const invalidPassNesting = passes.filter((record) =>
  !Number.isSafeInteger(record.nesting) || record.nesting < 0).length;
const invalidPassTestNumber = passes.filter((record) =>
  !Number.isSafeInteger(record.testNumber) || record.testNumber < 1).length;
const multisetEqual = JSON.stringify(startKeys) === JSON.stringify(passKeys);
if (starts.length < 1 || starts.length !== passes.length || invalidStartName !== 0
    || invalidStartFile !== 0 || invalidStartNesting !== 0 || invalidPassName !== 0
    || invalidPassFile !== 0 || invalidPassNesting !== 0 || invalidPassTestNumber !== 0
    || !syntheticHelperPairValid || !multisetEqual || failures.length !== 0) {
  throw new Error("JavaScript test lifecycle accounting is incomplete, duplicated, or failed: " +
    JSON.stringify({
      starts: starts.length,
      passes: passes.length,
      failures: failures.length,
      invalidStartName,
      invalidStartFile,
      invalidStartNesting,
      invalidPassName,
      invalidPassFile,
      invalidPassNesting,
      invalidPassTestNumber,
      syntheticHelperPairValid,
      multisetEqual
    }));
}
const outstandingByKey = new Map();
const terminalIndexes = [];
for (const [index, record] of records.entries()) {
  if (record.type === "test:start") {
    outstandingByKey.set(key(record), (outstandingByKey.get(key(record)) ?? 0) + 1);
  } else if (record.type === "test:pass") {
    const outstanding = outstandingByKey.get(key(record)) ?? 0;
    if (outstanding < 1) {
      throw new Error("JavaScript test terminal event preceded its matching start event");
    }
    outstandingByKey.set(key(record), outstanding - 1);
    terminalIndexes.push(index);
  }
}
if ([...outstandingByKey.values()].some((count) => count !== 0)) {
  throw new Error("JavaScript test lifecycle remained outstanding after run completion");
}
const topLevelStarts = starts.filter((record) => record.nesting === 0).length;
if (plans.length !== 1 || !Number.isSafeInteger(plans[0].count) || plans[0].count < 1
    || plans[0].count !== topLevelStarts) {
  throw new Error("JavaScript test run did not publish its exact final plan: " +
    JSON.stringify({
      totalStarts: starts.length,
      topLevelStarts,
      planRecords: plans.length,
      planCount: Number.isSafeInteger(plans[0]?.count) ? plans[0].count : null,
      planCountSafePositive: Number.isSafeInteger(plans[0]?.count) && plans[0].count > 0
    }));
}
if (summaries.length !== 1 || summaries[0].success !== true
    || summaries[0].counts?.tests !== starts.length
    || !Number.isSafeInteger(summaries[0].counts?.passed)
    || !Number.isSafeInteger(summaries[0].counts?.skipped)
    || summaries[0].counts?.failed !== 0 || summaries[0].counts?.cancelled !== 0
    || summaries[0].counts?.todo !== 0) {
  throw new Error("JavaScript test run did not publish one complete passing aggregate summary");
}
const planIndex = records.indexOf(plans[0]);
const summaryIndex = records.indexOf(summaries[0]);
if (planIndex <= Math.max(...terminalIndexes) || summaryIndex <= planIndex) {
  throw new Error("JavaScript test plan or aggregate summary was published out of order");
}

const skippedRecords = passes.filter((record) => record.skip === true || typeof record.skip === "string");
const skippedNames = skippedRecords.map((record) => record.name).sort();
const skipKey = (record) => {
  const canonicalFile = realpathSync(record.file);
  const sourceRelative = relative(canonicalProject, canonicalFile);
  if (sourceRelative.startsWith("..") || sourceRelative.startsWith("/")) {
    throw new Error("JavaScript skipped test escaped the reviewed source tree");
  }
  return `${sourceRelative}\0${record.nesting}\0${record.name}`;
};
const skippedKeys = skippedRecords.map(skipKey).sort();
if (summaries[0].counts.skipped !== skippedRecords.length
    || summaries[0].counts.passed !== passes.length - skippedRecords.length) {
  throw new Error("JavaScript aggregate summary disagreed with exact terminal skip accounting");
}
if (profile === "focused") {
  if (skippedNames.length !== 0) {
    throw new Error(`focused JavaScript qualification may not skip tests: ${JSON.stringify(skippedKeys)}`);
  }
} else {
  const watchdogSkippedNames = Object.freeze([
    "watchdog secret boundaries and malformed inherited markers fail closed",
    "watchdog secrets are absent from argv, environments, listings, logs, and relay parents",
    "nested inherited watchdogs relay each private descriptor exactly once",
    "watchdog preserves an ordinary command status",
    "fixed capability and drain-proof descriptors survive inherited descriptor pressure",
    "the public launcher strips hostile language and shell preload hooks",
    "the cross-session self-test monitor preserves status and drains a TERM-resistant session",
    "a transient descendant RSS spike inside the grace window is allowed",
    "sustained allocation terminates the exact supervised group",
    "aggregate RSS includes descendants rather than only the leader",
    "a leader that exits with an orphaned descendant fails closed and drains it",
    "an observed descendant that changes session cannot escape cleanup after its leader exits",
    "a timed-out observed session-changing descendant is killed before status 124 is published",
    "an external signal lets the tree owner drain an observed session-changing descendant",
    "memory enforcement never kills an unrelated process",
    "wall timeout returns 124 and drains descendants",
    "wall timeout escalates to KILL and drains TERM-ignoring descendants",
    "external SIGTERM is forwarded to the exact child group only",
    "external SIGINT is forwarded to the exact child group only",
    "external SIGHUP is forwarded to the exact child group only",
    "nested watchdog composition is rejected before a separately supervised command can escape",
    "stripping every marker and closing the capability FD cannot create a second root",
    "an inherited logical stage enforces its wall deadline without creating a session",
    "an inherited logical stage enforces a tighter aggregate RSS profile",
    "a supervisor-owned lock is removed only after descendant drain",
    "an ownerless pre-existing lock fails closed after one bounded publication window",
    "cleanup failure changes the final status receipt instead of publishing a stale zero",
    "unexpected capability removal fails closed and leaves no false success receipt",
    "missing tree-drain proof retains the lock and blocks a next contender"
  ]);
  const evidenceSkippedNames = Object.freeze([
    "successful release evidence is exact-candidate bound, private, and build named",
    "raw, copied, and published release evidence never retain emitted credentials or PEM bodies",
    "retained-evidence verification rejects a post-publication summary mutation",
    "pipefail preserves verifier failure and publishes no incomplete evidence",
    "a successful-looking verifier that leaks a descendant cannot publish evidence",
    "signal exit is exact and cleanup leaves no hidden or final evidence",
    "post-verification candidate drift fails closed and removes the transcript",
    "deterministic-only or stale CI evidence cannot be retained as full hardware proof",
    "a successful-looking transcript for another candidate cannot be associated",
    "a failed rerun preserves the complete previously retained candidate set byte-for-byte",
    "SIGKILL before publication cannot replace or mix an existing valid evidence set",
    "SIGKILL after the directory rename exposes one complete verifiable set, never mixed flat files",
    "concurrent same-candidate retention is serialized and cannot mix or nest evidence sets",
    "the parent publication lock blocks a candidate-manifest mutator through atomic rename and fsync",
    "partial and stale candidate-specific sets are rejected instead of being mistaken for retained proof",
    "retained-evidence verification rejects a symbolic evidence-set directory",
    "release-evidence fixture startup recovery is bounded, crash-safe, and exact-unit correlated"
  ]);
  const allowedSkippedKeys = [
    ...watchdogSkippedNames.map((name) => `Tests/JS/ReleaseWatchdogTests.mjs\0${0}\0${name}`),
    ...evidenceSkippedNames.map((name) => `Tests/JS/ReleaseEvidenceRetentionTests.mjs\0${0}\0${name}`)
  ];
  if (profile === "full-source") {
    allowedSkippedKeys.push("Tests/JS/PublicDistributionScriptsTests.mjs\0" +
      "0\0public verifier rejects the exact private candidate");
  }
  allowedSkippedKeys.sort();
  if (JSON.stringify(skippedKeys) !== JSON.stringify(allowedSkippedKeys)) {
    throw new Error(`full JavaScript qualification skip topology changed: ${JSON.stringify(skippedKeys)}`);
  }
  const expectedFiles = readdirSync(join(canonicalProject, "Tests", "JS"))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => join(canonicalProject, "Tests", "JS", name)).sort();
  if (!syntheticHelperPairPresent) {
    throw new Error("full JavaScript qualification omitted the exact reviewed helper operand lifecycle");
  }
  const observedFiles = [...new Set(starts.map((record) => realpathSync(normalizedFile(record))))].sort();
  if (JSON.stringify(observedFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error("full JavaScript qualification did not execute the exact source test-file set");
  }
  // Frozen to the exact reviewed aggregate topology. Any added, removed,
  // skipped, or silently truncated test changes this ledger and fails closed.
  const expectedTests = 680;
  const expectedTopLevelTests = 655;
  const expectedPassed = profile === "full-candidate" ? 634 : 633;
  if (starts.length !== expectedTests || summaries[0].counts?.passed !== expectedPassed
      || topLevelStarts !== expectedTopLevelTests
      || skippedKeys.length !== allowedSkippedKeys.length) {
    throw new Error(`full JavaScript qualification count drift: tests=${starts.length} topLevel=${topLevelStarts} passed=${summaries[0].counts?.passed} skipped=${skippedNames.length}`);
  }
}
process.stdout.write(`JavaScript event accounting passed: ${starts.length} exact tests, ${skippedNames.length} intentional skips.\n`);
