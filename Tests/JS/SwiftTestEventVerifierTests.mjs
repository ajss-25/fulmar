import assert from "node:assert/strict";
import test from "node:test";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const verifier = join(process.cwd(), "scripts", "verify-swift-test-events.mjs");
const releasePlan = join(process.cwd(), "Config", "SwiftTestPlan.json");
const nonce = "0123456789abcdef0123456789abcdef";

const discovery = (id, name, kind = "function", testCases = []) => ({
  kind: "test", version: 0,
  payload: {
    id, kind, name,
    ...(kind === "function" ? {
      isParameterized: testCases.length > 0,
      ...(testCases.length > 0 ? { _testCases: testCases } : {})
    } : {})
  }
});
const suite = (id, name) => discovery(id, name, "suite");
const event = (kind, testID, symbol = "default") => ({
  kind: "event", version: 0,
  payload: {
    kind,
    ...(testID ? { testID } : {}),
    messages: [{ symbol, text: kind }]
  }
});
const testCaseEvent = (kind, testID, testCase, symbol = "default") => ({
  kind: "event", version: 0,
  payload: { kind, testID, _testCase: testCase, messages: [{ symbol, text: kind }] }
});
function validRecords(entries = [["Suite.one()/One.swift:1:1", "one()"]]) {
  return [
    ...entries.map(([id, name]) => discovery(id, name)),
    event("runStarted"),
    ...entries.flatMap(([id]) => [event("testStarted", id), event("testEnded", id, "pass")]),
    event("runEnded", undefined, "pass")
  ];
}

async function fixture(records, { terminate = true } = {}) {
  const root = await mkdtemp("/private/tmp/fulmar-swift-tests.");
  const path = join(root, `swift-events-${nonce}.jsonl`);
  const body = records.map((record) => JSON.stringify(record)).join("\n") + (terminate ? "\n" : "");
  await writeFile(path, body, { mode: 0o600 });
  await chmod(path, 0o600);
  return { root, path };
}
async function planFixture(root, functionCount) {
  const directory = join(root, "Config");
  const path = join(directory, "SwiftTestPlan.json");
  await mkdir(directory, { mode: 0o700 });
  await writeFile(path, `${JSON.stringify({
    schemaVersion: 1,
    functionCount,
    sortedSpecifierSHA256: "0".repeat(64)
  })}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}
function verify(path, host = "26", profile = "focused", plan = releasePlan, fixtureProfile = "ordinary") {
  return spawnSync(process.execPath, [verifier, path, host, profile, plan, fixtureProfile], {
    encoding: "utf8", timeout: 5_000,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
}

test("Swift focused event verifier accepts complete selected ledgers", async () => {
  for (const entries of [
    [["Suite.one()/One.swift:1:1", "one()"]],
    [["Suite.one()/One.swift:1:1", "one()"], ["Suite.two()/Two.swift:2:1", "two()"]]
  ]) {
    const value = await fixture(validRecords(entries));
    try {
      const result = verify(value.path);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, new RegExp(`${entries.length} functions, 0 suites`, "u"));
    } finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift full event verifier requires the exact frozen function count", async () => {
  const entries = [
    ["Suite.one()/One.swift:1:1", "one()"],
    ["Suite.two()/Two.swift:2:1", "two()"]
  ];
  const value = await fixture(validRecords(entries));
  try {
    const exactPlan = await planFixture(value.root, 2);
    assert.equal(verify(value.path, "26", "full", exactPlan).status, 0);
    await writeFile(exactPlan, `${JSON.stringify({
      schemaVersion: 1, functionCount: 3, sortedSpecifierSHA256: "0".repeat(64)
    })}\n`, { mode: 0o600 });
    assert.notEqual(verify(value.path, "26", "full", exactPlan).status, 0);
    assert.equal(verify(value.path, "26", "focused", exactPlan).status, 0);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift event verifier accepts discovered suite containers anchored to selected functions", async () => {
  const outerID = "opaque outer suite identity";
  const innerID = "opaque inner suite identity";
  const functionID = "opaque selected function identity";
  const records = [
    suite(outerID, "OuterSuite"), suite(innerID, "InnerSuite"),
    discovery(functionID, "selectedFunction()"), event("runStarted"),
    event("testStarted", outerID), event("testStarted", innerID),
    event("testStarted", functionID), event("testEnded", functionID, "pass"),
    event("testEnded", innerID, "pass"), event("testEnded", outerID, "pass"),
    event("runEnded", undefined, "pass")
  ];
  const value = await fixture(records);
  try {
    const result = verify(value.path);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /1 functions, 2 suites/u);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift event verifier accepts a suite anchored to one permitted skipped function", async () => {
  const suiteID = "opaque live Ollama suite identity";
  const allowedName = "appOwnedOllamaPlanLaunchesOneAttestedSandboxedListenerWhenInstalled()";
  const functionID = "opaque selected installed-Ollama function identity";
  const value = await fixture([
    suite(suiteID, "LiveOllamaRuntimeSecurityTests"), discovery(functionID, allowedName),
    event("runStarted"), event("testStarted", suiteID),
    event("testSkipped", functionID, "skip"), event("testEnded", suiteID, "pass"),
    event("runEnded", undefined, "pass")
  ]);
  try {
    const result = verify(value.path);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /1 functions, 1 suites, 1 passed, 1 permitted skips/u);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift event verifier accepts exact balanced parameterized case identities", async () => {
  const suiteID = "opaque parameterized suite";
  const functionID = "opaque parameterized function";
  const cases = [
    { id: "opaque case alpha", displayName: "alpha" },
    { id: "opaque case beta", displayName: "beta" }
  ];
  const records = [
    suite(suiteID, "ParameterizedSuite"), discovery(functionID, "parameterizedFunction()", "function", cases),
    event("runStarted"), event("testStarted", suiteID), event("testStarted", functionID),
    testCaseEvent("testCaseStarted", functionID, cases[0]),
    testCaseEvent("testCaseEnded", functionID, cases[0]),
    testCaseEvent("testCaseStarted", functionID, cases[1]),
    testCaseEvent("testCaseEnded", functionID, cases[1]),
    event("testEnded", functionID, "pass"), event("testEnded", suiteID, "pass"),
    event("runEnded", undefined, "pass")
  ];
  const value = await fixture(records);
  try {
    const result = verify(value.path);
    assert.equal(result.status, 0, result.stderr);
  }
  finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift event verifier rejects truncated, malformed, and missing-run-end ledgers", async () => {
  const cases = [
    { records: validRecords(), terminate: false },
    { records: validRecords().slice(0, -1) },
    { records: [{ malformed: true }] }
  ];
  for (const entry of cases) {
    const value = await fixture(entry.records, { terminate: entry.terminate ?? true });
    try { assert.notEqual(verify(value.path).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift event verifier rejects unfinished, failed, issue-bearing, and duplicate lifecycles", async () => {
  const id = "Suite.one()/One.swift:1:1";
  const cases = [
    [discovery(id, "one()"), event("runStarted"), event("testStarted", id), event("runEnded", undefined, "pass")],
    [discovery(id, "one()"), event("runStarted"), event("testStarted", id), event("testEnded", id, "fail"), event("runEnded", undefined, "pass")],
    [discovery(id, "one()"), event("runStarted"), event("issueRecorded", id, "error"), event("testStarted", id), event("testEnded", id, "pass"), event("runEnded", undefined, "pass")],
    [discovery(id, "one()"), discovery(id, "one()"), event("runStarted"), event("testStarted", id), event("testEnded", id, "pass"), event("runEnded", undefined, "pass")],
    [discovery(id, "one()"), event("runStarted"), event("testStarted", id), event("testStarted", id), event("testEnded", id, "pass"), event("runEnded", undefined, "pass")],
    [discovery(id, "one()"), event("runStarted"), event("testStarted", id), event("testEnded", id, "pass"), event("testEnded", id, "pass"), event("runEnded", undefined, "pass")]
    , [discovery(id, "one()"), event("runStarted"), event("testEnded", id, "pass"), event("testStarted", id), event("runEnded", undefined, "pass")]
  ];
  for (const records of cases) {
    const value = await fixture(records);
    try { assert.notEqual(verify(value.path).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift event verifier rejects suite-only and unanchored suite ledgers", async () => {
  const suiteID = "opaque suite identity";
  const functionID = "opaque function identity";
  const cases = [
    [suite(suiteID, "OnlySuite"), event("runStarted"), event("testStarted", suiteID), event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [suite(suiteID, "Suite"), discovery(functionID, "function()"), event("runStarted"), event("testStarted", suiteID), event("testEnded", suiteID, "pass"), event("testStarted", functionID), event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")],
    [suite(suiteID, "Suite"), discovery(functionID, "function()"), event("runStarted"), event("testStarted", functionID), event("testStarted", suiteID), event("testEnded", functionID, "pass"), event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [suite(suiteID, "Suite"), discovery(functionID, "function()"), event("runStarted"), event("testStarted", suiteID), event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [suite(suiteID, "Suite"), discovery(functionID, "function()"), event("runStarted"), event("testStarted", functionID), event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")]
  ];
  for (const records of cases) {
    const value = await fixture(records);
    try { assert.notEqual(verify(value.path).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift event verifier rejects hostile suite discovery and lifecycle mutations", async () => {
  const suiteID = "opaque suite identity";
  const functionID = "opaque function identity";
  const unknownID = "opaque undiscovered identity";
  const baseDiscoveries = [suite(suiteID, "Suite"), discovery(functionID, "function()")];
  const completeFunction = [event("testStarted", functionID), event("testEnded", functionID, "pass")];
  const cases = [
    [suite(suiteID, "Suite"), suite(suiteID, "Suite"), discovery(functionID, "function()"), event("runStarted"), event("testStarted", suiteID), ...completeFunction, event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testStarted", unknownID), event("testEnded", unknownID, "pass"), event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testStarted", suiteID), event("testStarted", suiteID), ...completeFunction, event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testStarted", suiteID), ...completeFunction, event("testEnded", suiteID, "pass"), event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testSkipped", suiteID, "skip"), ...completeFunction, event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testStarted", suiteID), ...completeFunction, event("testEnded", suiteID, "pass"), event("mysteryEvent", functionID), event("runEnded", undefined, "pass")],
    [...baseDiscoveries, event("runStarted"), event("testStarted", suiteID), ...completeFunction, event("testEnded", suiteID, "pass"), event("runEnded", undefined, "pass"), event("valueAttached", functionID)],
    [discovery(functionID, "function()"), event("runStarted"), discovery("late function identity", "lateFunction()"), ...completeFunction, event("runEnded", undefined, "pass")]
  ];
  for (const records of cases) {
    const value = await fixture(records);
    try { assert.notEqual(verify(value.path).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift event verifier rejects hostile parameterized case mutations", async () => {
  const functionID = "opaque parameterized function";
  const first = { id: "opaque case alpha", displayName: "alpha" };
  const second = { id: "opaque case beta", displayName: "beta" };
  const unknown = { id: "opaque case unknown", displayName: "unknown" };
  const discoveryRecord = discovery(functionID, "parameterizedFunction()", "function", [first, second]);
  const prefix = [discoveryRecord, event("runStarted"), event("testStarted", functionID)];
  const suffix = [event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")];
  const completeFirst = [testCaseEvent("testCaseStarted", functionID, first), testCaseEvent("testCaseEnded", functionID, first)];
  const completeSecond = [testCaseEvent("testCaseStarted", functionID, second), testCaseEvent("testCaseEnded", functionID, second)];
  const cases = [
    [...prefix, ...completeFirst, ...suffix],
    [...prefix, ...completeFirst, testCaseEvent("testCaseEnded", functionID, second), ...suffix],
    [...prefix, testCaseEvent("testCaseStarted", functionID, first), testCaseEvent("testCaseStarted", functionID, first), testCaseEvent("testCaseEnded", functionID, first), ...completeSecond, ...suffix],
    [...prefix, ...completeFirst, ...completeSecond, testCaseEvent("testCaseEnded", functionID, second), ...suffix],
    [...prefix, ...completeFirst, testCaseEvent("testCaseStarted", functionID, unknown), testCaseEvent("testCaseEnded", functionID, unknown), ...completeSecond, ...suffix],
    [...prefix, testCaseEvent("testCaseStarted", functionID, { ...first, displayName: "mismatch" }), testCaseEvent("testCaseEnded", functionID, first), ...completeSecond, ...suffix],
    [discovery(functionID, "plainFunction()"), event("runStarted"), event("testStarted", functionID), testCaseEvent("testCaseStarted", functionID, first), testCaseEvent("testCaseEnded", functionID, first), event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")],
    [discoveryRecord, event("runStarted"), testCaseEvent("testCaseStarted", functionID, first), event("testStarted", functionID), testCaseEvent("testCaseEnded", functionID, first), ...completeSecond, ...suffix],
    [...prefix, ...completeFirst, ...completeSecond, ...suffix.slice(0, 1), testCaseEvent("testCaseEnded", functionID, first), ...suffix.slice(1)],
    [...prefix, testCaseEvent("testCaseCancelled", functionID, first), ...completeSecond, ...suffix],
    [discovery(functionID, "parameterizedFunction()", "function", [first, first]), event("runStarted"), event("testStarted", functionID), event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")]
  ];
  for (const records of cases) {
    const value = await fixture(records);
    try { assert.notEqual(verify(value.path).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
});

test("Swift event verifier never reflects parameter argument identities in failures", async () => {
  const functionID = "opaque parameterized function";
  const declared = { id: "declared case", displayName: "declared" };
  const secret = "sk-case-secret /Users/private/case-ledger";
  const hostile = { id: secret, displayName: secret };
  const records = [
    discovery(functionID, "parameterizedFunction()", "function", [declared]),
    event("runStarted"), event("testStarted", functionID),
    testCaseEvent("testCaseStarted", functionID, hostile),
    event("testEnded", functionID, "pass"), event("runEnded", undefined, "pass")
  ];
  const value = await fixture(records);
  try {
    const result = verify(value.path);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stderr, /sk-case-secret|\/Users\/private\/case-ledger/u);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift event verifier permits only the three exact pre-macOS-26 toolbar skips", async () => {
  const allowedName = "renderedMacOS26ToolbarMetricRejectsLegacyFullHeightStatusLabel()";
  const id = `Suite.${allowedName}/Toolbar.swift:1:1`;
  const allowed = [discovery(id, allowedName), event("runStarted"), event("testSkipped", id, "skip"), event("runEnded", undefined, "pass")];
  const value = await fixture(allowed);
  try {
    assert.equal(verify(value.path, "25").status, 0);
    assert.notEqual(verify(value.path, "26").status, 0);
  } finally { await rm(value.root, { recursive: true, force: true }); }

  const unexpected = await fixture([
    discovery(id, "someOtherConditionalTest()"), event("runStarted"),
    event("testSkipped", id, "skip"), event("runEnded", undefined, "pass")
  ]);
  try { assert.notEqual(verify(unexpected.path, "25").status, 0); }
  finally { await rm(unexpected.root, { recursive: true, force: true }); }
});

test("Swift event verifier permits only the exact environment-bound hardware skips", async () => {
  for (const allowedName of [
    "appOwnedOllamaLaunchPlanPropagatesAValidatedExplicitExternalModelStore()",
    "installedOllamaResolvesToOneStrictOfficialIdentityWhenPresent()",
    "appOwnedOllamaPlanLaunchesOneAttestedSandboxedListenerWhenInstalled()",
    "harnessControllerUsesAttestedSandboxPlanAndReapsItWhenInstalled()"
  ]) {
    const id = `Suite.${allowedName}/OllamaRuntimeSecurityTests.swift:1:1`;
    const value = await fixture([
      discovery(id, allowedName), event("runStarted"),
      event("testSkipped", id, "skip"), event("runEnded", undefined, "pass")
    ]);
    try {
      assert.equal(verify(value.path, "26").status, 0, allowedName);
      assert.equal(verify(value.path, "25").status, 0, allowedName);
    } finally { await rm(value.root, { recursive: true, force: true }); }
  }

  const unexpectedName = "someOtherInstalledOllamaTestWhenPresent()";
  const id = `Suite.${unexpectedName}/OllamaRuntimeSecurityTests.swift:1:1`;
  const unexpected = await fixture([
    discovery(id, unexpectedName), event("runStarted"),
    event("testSkipped", id, "skip"), event("runEnded", undefined, "pass")
  ]);
  try { assert.notEqual(verify(unexpected.path, "26").status, 0); }
  finally { await rm(unexpected.root, { recursive: true, force: true }); }
});

test("Swift event verifier requires release fixture tests when release fixtures are supplied", async () => {
  for (const allowedName of [
    "atomicInstallValidatesRealPrivateStableFixtureAndRejectsCertMismatchAndTamper()",
    "extractedCandidateSchedulerHelperPassesStrictNestedAttestationWhenProvided()",
    "privateInstallCoordinatorHashesRealPrivateStableFixtureDeterministically()",
    "updateArchiveReleaseArtifactPassesTheSameNativePreflightWhenProvided()"
  ]) {
    const id = `Suite.${allowedName}/ReleaseFixture.swift:1:1`;
    const value = await fixture([
      discovery(id, allowedName), event("runStarted"),
      event("testSkipped", id, "skip"), event("runEnded", undefined, "pass")
    ]);
    try {
      assert.equal(verify(value.path, "26", "focused", releasePlan, "ordinary").status, 0);
      assert.notEqual(
        verify(value.path, "26", "focused", releasePlan, "release-fixtures").status,
        0
      );
    } finally { await rm(value.root, { recursive: true, force: true }); }
  }
});
