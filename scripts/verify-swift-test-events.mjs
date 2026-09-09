#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

const [eventPath, rawHostMajor, profile, planPath, fixtureProfile] = process.argv.slice(2);
const hostMajor = Number(rawHostMajor);
if (process.argv.length !== 7
    || !/^\/private\/tmp\/fulmar-swift-tests\.[A-Za-z0-9]+\/swift-events-[a-f0-9]{32}\.jsonl$/u.test(eventPath ?? "")
    || !Number.isSafeInteger(hostMajor) || hostMajor < 15 || hostMajor > 99
    || !["full", "focused"].includes(profile)
    || typeof planPath !== "string" || !planPath.endsWith("/Config/SwiftTestPlan.json")
    || !["ordinary", "release-fixtures"].includes(fixtureProfile)) {
  throw new Error("usage: verify-swift-test-events.mjs <private-event-path> <host-major> <full|focused> <plan-path> <ordinary|release-fixtures>");
}

function loadPlan(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || before.uid !== process.getuid() || (before.mode & 0o022) !== 0
        || before.size < 1 || before.size > 16 * 1024) {
      throw new Error("Swift test plan has unsafe metadata");
    }
    const planBytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < planBytes.length) {
      const count = readSync(descriptor, planBytes, offset, planBytes.length - offset, offset);
      if (count < 1) throw new Error("Swift test plan was truncated while reading");
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || after.uid !== before.uid || after.mode !== before.mode || after.nlink !== before.nlink) {
      throw new Error("Swift test plan changed while reading");
    }
    let value;
    try { value = JSON.parse(planBytes.toString("utf8")); }
    catch { throw new Error("Swift test plan is not valid JSON"); }
    if (!value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).sort().join(",") !== "functionCount,schemaVersion,sortedSpecifierSHA256"
        || value.schemaVersion !== 1
        || !Number.isSafeInteger(value.functionCount) || value.functionCount < 1 || value.functionCount > 10_000
        || !/^[a-f0-9]{64}$/u.test(value.sortedSpecifierSHA256 ?? "")) {
      throw new Error("Swift test plan has an invalid schema");
    }
    return value;
  } finally { closeSync(descriptor); }
}
const fullPlan = loadPlan(planPath);

const descriptor = openSync(eventPath, constants.O_RDONLY | constants.O_NOFOLLOW);
let bytes;
try {
  const before = fstatSync(descriptor);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== process.getuid() || (before.mode & 0o777) !== 0o600
      || before.size < 1 || before.size > 64 * 1024 * 1024) {
    throw new Error("Swift event stream has unsafe metadata");
  }
  bytes = Buffer.alloc(before.size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count < 1) throw new Error("Swift event stream was truncated while reading");
    offset += count;
  }
  const after = fstatSync(descriptor);
  if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) {
    throw new Error("Swift event stream changed while reading");
  }
} finally { closeSync(descriptor); }
if (bytes.at(-1) !== 0x0a) throw new Error("Swift event stream is unterminated");

const lines = bytes.toString("utf8").split("\n").slice(0, -1);
if (lines.length < 4 || lines.length > 100_000) throw new Error("Swift event stream has an invalid record count");
const records = lines.map((line, index) => {
  if (line.length < 2 || line.length > 1024 * 1024) throw new Error(`invalid Swift event line ${index + 1}`);
  let value;
  try { value = JSON.parse(line); } catch { throw new Error(`malformed Swift event JSON on line ${index + 1}`); }
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 0
      || !["test", "event"].includes(value.kind) || !value.payload || typeof value.payload !== "object") {
    throw new Error(`invalid Swift event record on line ${index + 1}`);
  }
  return value;
});

const discovered = new Map();
const discoveredFunctions = new Map();
const discoveredSuites = new Map();
for (const [recordIndex, record] of records.entries()) {
  if (record.kind !== "test") continue;
  const { id, kind, name, isParameterized, _testCases } = record.payload;
  if (typeof id !== "string" || id.length < 3 || id.length > 4096
      || typeof name !== "string" || name.length < 3 || name.length > 1024
      || !["function", "suite"].includes(kind) || discovered.has(id)) {
    throw new Error("Swift event stream contains malformed or duplicate test discovery");
  }
  const testCases = new Map();
  if (kind === "function" && isParameterized === true) {
    if (!Array.isArray(_testCases) || _testCases.length < 1 || _testCases.length > 10_000) {
      throw new Error("Swift parameterized test discovery has no bounded case plan");
    }
    for (const testCase of _testCases) {
      if (!testCase || typeof testCase !== "object" || Array.isArray(testCase)
          || typeof testCase.id !== "string" || testCase.id.length < 1 || testCase.id.length > 524_288
          || typeof testCase.displayName !== "string" || testCase.displayName.length > 524_288
          || testCases.has(testCase.id)) {
        throw new Error("Swift parameterized test discovery has malformed or duplicate cases");
      }
      testCases.set(testCase.id, testCase.displayName);
    }
  } else if (_testCases !== undefined && (!Array.isArray(_testCases) || _testCases.length !== 0)) {
    throw new Error("Swift non-parameterized discovery unexpectedly declares test cases");
  }
  const entry = { kind, name, recordIndex, isParameterized: isParameterized === true, testCases };
  discovered.set(id, entry);
  (kind === "function" ? discoveredFunctions : discoveredSuites).set(id, entry);
}
if (discoveredFunctions.size < 1) throw new Error("Swift event stream discovered no selected function tests");
if (profile === "full" && discoveredFunctions.size !== fullPlan.functionCount) {
  throw new Error("Swift full-suite event stream does not match the frozen function count");
}

const eventRecords = records.filter((record) => record.kind === "event");
const allowedEventKinds = new Set([
  "runStarted", "testStarted", "testCaseStarted", "issueRecorded", "valueAttached",
  "testCaseEnded", "testCaseCancelled", "testEnded", "testSkipped", "runEnded"
]);
for (const record of eventRecords) {
  if (!allowedEventKinds.has(record.payload.kind)) {
    throw new Error(`Swift event stream contains an unknown event kind: ${record.payload.kind}`);
  }
}
const runStarts = eventRecords.filter((record) => record.payload.kind === "runStarted");
const runEnds = eventRecords.filter((record) => record.payload.kind === "runEnded");
const runStartIndex = eventRecords.indexOf(runStarts[0]);
const runEndIndex = eventRecords.indexOf(runEnds[0]);
if (runStarts.length !== 1 || runEnds.length !== 1
    || runStartIndex !== 0 || runEndIndex !== eventRecords.length - 1
    || runStartIndex >= runEndIndex) {
  throw new Error("Swift event stream does not contain one ordered completed run");
}
const runStartRecordIndex = records.indexOf(runStarts[0]);
if ([...discovered.values()].some(({ recordIndex }) => recordIndex >= runStartRecordIndex)) {
  throw new Error("Swift event stream contains discovery outside its pre-run plan");
}
const symbols = (event) => Array.isArray(event.payload.messages)
  ? event.payload.messages.map((message) => message?.symbol).filter((value) => typeof value === "string")
  : [];
if (!symbols(runEnds[0]).includes("pass")) throw new Error("Swift test run did not end with pass");

const allowedConditionalSkips = new Set([
  "renderedMacOS26ToolbarSemanticTypeScalesRemainVisuallyLevel()",
  "renderedMacOS26ToolbarStatusAndModelTextAreVisuallyLevelAcrossReleaseMatrix()",
  "renderedMacOS26ToolbarMetricRejectsLegacyFullHeightStatusLabel()"
]);
const allowedEnvironmentSkips = new Set([
  "appOwnedOllamaLaunchPlanPropagatesAValidatedExplicitExternalModelStore()",
  "installedOllamaResolvesToOneStrictOfficialIdentityWhenPresent()",
  "appOwnedOllamaPlanLaunchesOneAttestedSandboxedListenerWhenInstalled()",
  "harnessControllerUsesAttestedSandboxPlanAndReapsItWhenInstalled()"
]);
const allowedReleaseFixtureSkips = new Set([
  "atomicInstallValidatesRealPrivateStableFixtureAndRejectsCertMismatchAndTamper()",
  "extractedCandidateSchedulerHelperPassesStrictNestedAttestationWhenProvided()",
  "privateInstallCoordinatorHashesRealPrivateStableFixtureDeterministically()",
  "updateArchiveReleaseArtifactPassesTheSameNativePreflightWhenProvided()"
]);
const starts = new Map();
const terminals = new Map();
const caseStarts = new Map();
const caseTerminals = new Map();
for (const [eventIndex, record] of eventRecords.entries()) {
  const { kind, testID } = record.payload;
  if (kind === "issueRecorded" || kind === "testCaseCancelled"
      || symbols(record).some((symbol) => ["fail", "error", "warning"].includes(symbol))) {
    throw new Error(`Swift event stream recorded a test issue or failure (${kind})`);
  }
  if (testID !== undefined
      && (typeof testID !== "string" || !discovered.has(testID))) {
    throw new Error(`Swift event references an undiscovered test: ${testID}`);
  }
  if (["testCaseStarted", "testCaseEnded", "testCaseCancelled"].includes(kind)) {
    const functionEntry = discoveredFunctions.get(testID);
    const testCase = record.payload._testCase;
    if (!functionEntry?.isParameterized || !testCase || typeof testCase !== "object"
        || Array.isArray(testCase) || typeof testCase.id !== "string"
        || typeof testCase.displayName !== "string"
        || functionEntry.testCases.get(testCase.id) !== testCase.displayName) {
      throw new Error(`Swift event references an undiscovered parameterized test case: ${testID}`);
    }
    const startsForFunction = caseStarts.get(testID) ?? new Map();
    const terminalsForFunction = caseTerminals.get(testID) ?? new Map();
    caseStarts.set(testID, startsForFunction);
    caseTerminals.set(testID, terminalsForFunction);
    if (kind === "testCaseStarted") {
      if (startsForFunction.has(testCase.id) || terminalsForFunction.has(testCase.id)) {
        throw new Error(`Swift parameterized test has duplicate case lifecycle events: ${functionEntry.name}`);
      }
      startsForFunction.set(testCase.id, eventIndex);
    } else if (kind === "testCaseEnded") {
      const startIndex = startsForFunction.get(testCase.id);
      if (!Number.isSafeInteger(startIndex) || terminalsForFunction.has(testCase.id)
          || eventIndex <= startIndex) {
        throw new Error(`Swift parameterized test has an orphaned or duplicate case terminal: ${functionEntry.name}`);
      }
      terminalsForFunction.set(testCase.id, eventIndex);
    }
  }
  if (!["testStarted", "testEnded", "testSkipped"].includes(kind)) continue;
  if (typeof testID !== "string") {
    throw new Error(`Swift test lifecycle event has no discovered identity (${kind})`);
  }
  if (eventIndex <= runStartIndex || eventIndex >= runEndIndex) {
    throw new Error(`Swift test lifecycle event is outside its run boundary: ${testID}`);
  }
  if (kind === "testStarted") {
    const prior = starts.get(testID);
    starts.set(testID, { count: (prior?.count ?? 0) + 1, index: eventIndex });
    continue;
  }
  if (terminals.has(testID)) throw new Error(`Swift test has duplicate terminal events: ${testID}`);
  const eventSymbols = symbols(record);
  terminals.set(testID, {
    result: eventSymbols.includes("skip") || kind === "testSkipped" ? "skip"
      : eventSymbols.includes("pass") ? "pass" : "invalid",
    index: eventIndex
  });
}

let skipped = 0;
for (const [id, { kind, name }] of discovered) {
  const terminal = terminals.get(id);
  const started = starts.get(id);
  if (terminal?.result === "skip") {
    skipped += 1;
    const allowedSkip = allowedEnvironmentSkips.has(name)
      || (fixtureProfile === "ordinary" && allowedReleaseFixtureSkips.has(name))
      || (hostMajor < 26 && allowedConditionalSkips.has(name));
    if (kind !== "function" || !allowedSkip
        || (started?.count ?? 0) > 1
        || (started && terminal.index <= started.index)) {
      throw new Error(`unexpected skipped Swift test: ${name}`);
    }
    continue;
  }
  if (started?.count !== 1 || terminal?.result !== "pass" || terminal.index <= started.index) {
    throw new Error(`Swift test did not start and terminally pass exactly once: ${name}`);
  }
}
if (starts.size > discovered.size || terminals.size !== discovered.size) {
  throw new Error("Swift event stream has incomplete or unexpected test lifecycle accounting");
}

for (const [functionID, entry] of discoveredFunctions) {
  const startsForFunction = caseStarts.get(functionID) ?? new Map();
  const terminalsForFunction = caseTerminals.get(functionID) ?? new Map();
  if (!entry.isParameterized) {
    if (startsForFunction.size !== 0 || terminalsForFunction.size !== 0) {
      throw new Error(`Swift non-parameterized test emitted case events: ${entry.name}`);
    }
    continue;
  }
  const functionStart = starts.get(functionID)?.index;
  const functionEnd = terminals.get(functionID)?.index;
  if (startsForFunction.size !== entry.testCases.size
      || terminalsForFunction.size !== entry.testCases.size) {
    throw new Error(`Swift parameterized test has incomplete case accounting: ${entry.name}`);
  }
  for (const testCaseID of entry.testCases.keys()) {
    const caseStart = startsForFunction.get(testCaseID);
    const caseEnd = terminalsForFunction.get(testCaseID);
    if (!Number.isSafeInteger(functionStart) || !Number.isSafeInteger(functionEnd)
        || !Number.isSafeInteger(caseStart) || !Number.isSafeInteger(caseEnd)
        || functionStart >= caseStart || caseStart >= caseEnd || caseEnd >= functionEnd) {
      throw new Error(`Swift parameterized case lifecycle is outside its function: ${entry.name}`);
    }
  }
}

// A suite ID is opaque in Swift Testing's event schema, so do not infer its
// parent from punctuation in the ID. Instead, anchor each discovered suite to
// at least one selected function lifecycle that actually occurred inside the
// suite's start/end interval. A permitted environment-bound skip legitimately
// has no testStarted event, so its single verified skip terminal is its whole
// lifecycle. This accepts real nested-suite ledgers while a suite-only or
// unrelated suite ledger cannot manufacture test coverage.
for (const [suiteID, { name }] of discoveredSuites) {
  const suiteStart = starts.get(suiteID)?.index;
  const suiteEnd = terminals.get(suiteID)?.index;
  const hasSelectedFunction = [...discoveredFunctions.keys()].some((functionID) => {
    const functionStart = starts.get(functionID)?.index;
    const functionResult = terminals.get(functionID);
    const functionTerminal = functionResult?.index;
    const isVerifiedSkip = functionResult?.result === "skip";
    return Number.isSafeInteger(suiteStart) && Number.isSafeInteger(suiteEnd)
      && Number.isSafeInteger(functionTerminal)
      && suiteStart < functionTerminal && functionTerminal < suiteEnd
      && (Number.isSafeInteger(functionStart)
        ? suiteStart < functionStart && functionStart < functionTerminal
        : isVerifiedSkip);
  });
  if (!hasSelectedFunction) {
    throw new Error(`Swift suite lifecycle is not anchored to a selected function test: ${name}`);
  }
}

process.stdout.write(
  `Swift ${profile} event accounting passed: ${discoveredFunctions.size} functions, `
  + `${discoveredSuites.size} suites, ${discovered.size - skipped} passed, `
  + `${skipped} permitted skips.\n`
);
