import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";
import test from "node:test";

const node = process.env.LOCAL_HARNESS_TEST_NODE ?? process.execPath;
const verifier = join(process.cwd(), "scripts", "verify-js-test-events.mjs");
const fixtureFile = join(process.cwd(), "Tests", "JS", "AppIconPackagingTests.mjs");
const nonce = "0123456789abcdef0123456789abcdef";
let reporterCase = 0;

async function reportedRecords(records) {
  const url = pathToFileURL(join(process.cwd(), "scripts", "self-root-test-event-reporter.mjs"));
  const { default: reporter } = await import(`${url.href}?fixture=${++reporterCase}`);
  const chunks = [];
  reporter.on("data", (chunk) => chunks.push(chunk.toString()));
  await pipeline(Readable.from(records.map(({ type, ...data }) => ({ type, data }))), reporter);
  return chunks.join("").trimEnd().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function records(overrides = {}) {
  const start = { type: "test:start", name: "event fixture", file: fixtureFile, nesting: 0, testNumber: 1 };
  const pass = { type: "test:pass", name: "event fixture", file: fixtureFile, nesting: 0, testNumber: 1 };
  return overrides.records ?? [
    start,
    pass,
    { type: "test:plan", nesting: 0, count: 1 },
    { type: "test:summary", success: true,
      counts: { tests: 1, passed: 1, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
  ];
}

function withLedger(body, options = {}) {
  const root = mkdtempSync("/private/tmp/fulmar-js-tests.");
  const path = join(root, `events-${nonce}.jsonl`);
  try {
    const value = options.bytes ?? `${records(options).map((record) => JSON.stringify(record)).join("\n")}\n`;
    writeFileSync(path, value, { mode: 0o600 });
    chmodSync(path, options.mode ?? 0o600);
    return body(path, root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function run(path, profile = "focused") {
  return spawnSync(node, [verifier, path, profile, process.cwd()], { encoding: "utf8", timeout: 5_000 });
}

function exactFullRecords(candidate) {
  const watchdogSource = readFileSync(join(process.cwd(), "Tests", "JS", "ReleaseWatchdogTests.mjs"), "utf8");
  const evidenceSource = readFileSync(join(process.cwd(), "Tests", "JS", "ReleaseEvidenceRetentionTests.mjs"), "utf8");
  const watchdogNames = [...watchdogSource.matchAll(/^supervisorFixture\("([^"]+)"/gmu)].map((match) => match[1]);
  watchdogNames.push(
    "watchdog secret boundaries and malformed inherited markers fail closed",
    "watchdog secrets are absent from argv, environments, listings, logs, and relay parents",
    "nested inherited watchdogs relay each private descriptor exactly once",
    "external SIGTERM is forwarded to the exact child group only",
    "external SIGINT is forwarded to the exact child group only",
    "external SIGHUP is forwarded to the exact child group only"
  );
  const evidenceNames = [...evidenceSource.matchAll(/^selfRootTest\("([^"]+)"/gmu)].map((match) => match[1]);
  assert.equal(watchdogNames.length, 29);
  assert.equal(evidenceNames.length, 17);
  const descriptors = [
    ...watchdogNames.map((name) => ({ file: join(process.cwd(), "Tests", "JS", "ReleaseWatchdogTests.mjs"), name, skip: true })),
    ...evidenceNames.map((name) => ({ file: join(process.cwd(), "Tests", "JS", "ReleaseEvidenceRetentionTests.mjs"), name, skip: true }))
  ];
  if (!candidate) descriptors.push({
    file: join(process.cwd(), "Tests", "JS", "PublicDistributionScriptsTests.mjs"),
    name: "public verifier rejects the exact private candidate", skip: true
  });
  const expectedFiles = readdirSync(join(process.cwd(), "Tests", "JS"))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => join(process.cwd(), "Tests", "JS", name));
  const helperFile = join(process.cwd(), "Tests", "JS", "RootWatchdogChildProcess.mjs");
  const represented = new Set(descriptors.map((descriptor) => descriptor.file));
  for (const file of expectedFiles) {
    if (file === helperFile) {
      descriptors.push({
        name: "Tests/JS/RootWatchdogChildProcess.mjs", syntheticHelper: true
      });
    } else if (!represented.has(file)) {
      descriptors.push({ file, name: `synthetic topology ${descriptors.length}` });
    }
  }
  while (descriptors.length < 939) descriptors.push({
    file: fixtureFile, name: `synthetic exact lifecycle ${descriptors.length}`
  });
  assert.equal(descriptors.length, 939);
  for (let index = descriptors.length - 245; index < descriptors.length; index += 1) {
    descriptors[index].nesting = 1;
  }
  const events = [];
  for (const descriptor of descriptors) events.push({
    type: "test:start", name: descriptor.name,
    ...(descriptor.file ? { file: descriptor.file } : {}), nesting: descriptor.nesting ?? 0
  });
  for (const [index, descriptor] of descriptors.entries()) events.push({
    type: "test:pass", name: descriptor.name,
    ...(descriptor.file ? { file: descriptor.file } : {}), nesting: descriptor.nesting ?? 0,
    testNumber: descriptor.syntheticHelper ? 1 : index + 1,
    ...(descriptor.skip ? { skip: "intentional fixture" } : {})
  });
  const skipped = descriptors.filter((descriptor) => descriptor.skip).length;
  events.push(
    { type: "test:plan", nesting: 0, count: 694 },
    { type: "test:summary", success: true,
      counts: { tests: 939, passed: 939 - skipped, failed: 0, cancelled: 0, skipped, todo: 0 } }
  );
  return events;
}

test("JavaScript event verifier accepts one exact ordered focused ledger", async () => {
  withLedger((path) => {
    const result = run(path);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /1 exact tests, 0 intentional skips/u);
  });
  for (const [helperName, testNumber] of [
    ["Tests/JS/RootWatchdogChildProcess.mjs", 1],
    [join(process.cwd(), "Tests", "JS", "RootWatchdogChildProcess.mjs"), 302]
  ]) {
    const helperLifecycle = [
      { type: "test:start", name: helperName, nesting: 0 },
      { type: "test:pass", name: helperName, nesting: 0, testNumber },
      { type: "test:plan", nesting: 0, count: 1 },
      { type: "test:summary", success: true,
        counts: { tests: 1, passed: 1, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
    ];
    withLedger((path) => assert.equal(run(path).status, 0), { records: helperLifecycle });
  }
  const repeatedParentScopedIdentity = [
    { type: "test:start", name: "parent one", file: fixtureFile, nesting: 0 },
    { type: "test:start", name: "parent-scoped twin", file: fixtureFile, nesting: 1 },
    { type: "test:pass", name: "parent-scoped twin", file: fixtureFile, nesting: 1, testNumber: 1 },
    { type: "test:pass", name: "parent one", file: fixtureFile, nesting: 0, testNumber: 1 },
    { type: "test:start", name: "parent two", file: fixtureFile, nesting: 0 },
    { type: "test:start", name: "parent-scoped twin", file: fixtureFile, nesting: 1 },
    { type: "test:pass", name: "parent-scoped twin", file: fixtureFile, nesting: 1, testNumber: 1 },
    { type: "test:pass", name: "parent two", file: fixtureFile, nesting: 0, testNumber: 2 },
    { type: "test:plan", nesting: 0, count: 2 },
    { type: "test:summary", success: true,
      counts: { tests: 4, passed: 4, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
  ];
  withLedger((path) => {
    const result = run(path);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /4 exact tests, 0 intentional skips/u);
  }, { records: repeatedParentScopedIdentity });
  withLedger((path) => assert.notEqual(run(path).status, 0), {
    records: repeatedParentScopedIdentity.map((record) =>
      record.type === "test:plan" ? { ...record, count: 4 } : record)
  });
  const accounting = [
    ...records(),
    { type: "test:fail", name: "failure is retained", file: fixtureFile,
      nesting: 1, testNumber: 2, skip: false, todo: "pending" },
    { type: "test:plan", nesting: 1, count: 2 }
  ];
  assert.deepEqual(await reportedRecords(accounting), accounting,
    "reporting must preserve all lifecycle, nested plan, summary, skip and todo fields");
  assert.equal((await reportedRecords(Array.from({ length: 4096 }, () => records()[0]))).length, 4096);
  await assert.rejects(reportedRecords(Array.from({ length: 4097 }, () => records()[0])),
    /exceeded its bounded evidence limit/u);
  await assert.rejects(reportedRecords([{ ...records()[0], name: "x".repeat(2 * 1024 * 1024) }]),
    /exceeded its bounded evidence limit/u);

  const selfVerifier = join(process.cwd(), "scripts", "verify-self-root-test-events.mjs");
  const selfNames = [...readFileSync(selfVerifier, "utf8").matchAll(/^  "([^"]+)"/gmu)]
    .map((match) => match[1]);
  assert.equal(selfNames.length, 62);
  const selfRecords = selfNames.flatMap((name, index) => [
    { type: "test:start", name, file: fixtureFile, nesting: 0 },
    { type: "test:pass", name, file: fixtureFile, nesting: 0, testNumber: index + 1 }
  ]);
  selfRecords.push(
    { type: "test:plan", nesting: 0, count: selfNames.length },
    { type: "test:summary", success: true,
      counts: { tests: 62, passed: 62, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
  );
  const selfRoot = mkdtempSync("/private/tmp/fulmar-watchdog-self-tests.");
  try {
    const path = join(selfRoot, "events.jsonl");
    const output = await reportedRecords(selfRecords);
    writeFileSync(path, `${output.map((record) => JSON.stringify(record)).join("\n")}\n`, { mode: 0o600 });
    const accepted = spawnSync(node, [selfVerifier, path], { encoding: "utf8", timeout: 5_000 });
    assert.equal(accepted.status, 0, accepted.stderr);
  } finally { rmSync(selfRoot, { recursive: true, force: true }); }
});

test("JavaScript event verifier rejects malformed, truncated, and incomplete ledgers", () => {
  for (const options of [
    { bytes: '{"type":"test:start"}' },
    { bytes: "not-json\n" },
    { records: records().slice(0, -1) },
    { records: records().filter((record) => record.type !== "test:plan") }
  ]) {
    withLedger((path) => assert.notEqual(run(path).status, 0), options);
  }
});

test("JavaScript event verifier rejects failed, skipped, duplicate, and out-of-order lifecycles", () => {
  const base = records();
  const hostile = [
    base.map((record) => record.type === "test:pass" ? { ...record, skip: "hidden" } : record),
    [base[0], base[0], base[1], { ...base[2], count: 2 },
      { ...base[3], counts: { ...base[3].counts, tests: 2, passed: 2 } }],
    [base[1], base[0], base[2], base[3]],
    [base[0], { type: "test:fail", name: "event fixture", file: fixtureFile, nesting: 0 }, base[2],
      { ...base[3], success: false, counts: { ...base[3].counts, passed: 0, failed: 1 } }]
  ];
  for (const value of hostile) {
    withLedger((path) => assert.notEqual(run(path).status, 0), { records: value });
  }
  const helperName = "Tests/JS/RootWatchdogChildProcess.mjs";
  const helperStart = { type: "test:start", name: helperName, nesting: 0 };
  const helperPass = { type: "test:pass", name: helperName, nesting: 0, testNumber: 1 };
  const helperSummary = (tests) => [
    { type: "test:plan", nesting: 0, count: tests },
    { type: "test:summary", success: true,
      counts: { tests, passed: tests, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
  ];
  const invalidHelperLifecycles = [
    [{ ...helperStart, name: "Tests/JS/not-the-helper.mjs" },
      { ...helperPass, name: "Tests/JS/not-the-helper.mjs" }, ...helperSummary(1)],
    [{ ...helperStart, name: "Tests/JS/../JS/RootWatchdogChildProcess.mjs" },
      { ...helperPass, name: "Tests/JS/../JS/RootWatchdogChildProcess.mjs" }, ...helperSummary(1)],
    [{ ...helperStart, nesting: 1 }, { ...helperPass, nesting: 1 }, ...helperSummary(1)],
    [helperStart, { ...helperPass, testNumber: 0 }, ...helperSummary(1)],
    [helperStart, { ...helperPass, testNumber: -1 }, ...helperSummary(1)],
    [helperStart, { ...helperPass, testNumber: 1.5 }, ...helperSummary(1)],
    [helperStart, { ...helperPass, testNumber: Number.MAX_SAFE_INTEGER + 1 }, ...helperSummary(1)],
    [{ ...helperStart, testNumber: 1 }, helperPass, ...helperSummary(1)],
    [{ ...helperStart, skip: "not allowed" }, helperPass, ...helperSummary(1)],
    [{ ...helperStart, todo: "not allowed" }, helperPass, ...helperSummary(1)],
    [helperStart, { ...helperPass, skip: "not allowed" }, ...helperSummary(1)],
    [helperStart, { ...helperPass, todo: "not allowed" }, ...helperSummary(1)],
    [helperStart, helperPass, helperStart, helperPass, ...helperSummary(2)]
  ];
  for (const value of invalidHelperLifecycles) {
    withLedger((path) => assert.notEqual(run(path).status, 0), { records: value });
  }
  const negativeNestedLifecycle = [
    { type: "test:start", name: "valid parent", file: fixtureFile, nesting: 0 },
    { type: "test:start", name: "invalid child", file: fixtureFile, nesting: -1 },
    { type: "test:pass", name: "invalid child", file: fixtureFile, nesting: -1, testNumber: 1 },
    { type: "test:pass", name: "valid parent", file: fixtureFile, nesting: 0, testNumber: 1 },
    { type: "test:plan", nesting: 0, count: 1 },
    { type: "test:summary", success: true,
      counts: { tests: 2, passed: 2, failed: 0, cancelled: 0, skipped: 0, todo: 0 } }
  ];
  withLedger((path) => assert.notEqual(run(path).status, 0), {
    records: negativeNestedLifecycle
  });
});

test("JavaScript event verifier rejects unsafe metadata and a partial full-suite topology", async () => {
  withLedger((path) => assert.notEqual(run(path).status, 0), { mode: 0o644 });
  withLedger((path) => assert.notEqual(run(path, "full-source").status, 0));
  for (const [profile, candidate] of [["full-source", false], ["full-candidate", true]]) {
    const exact = exactFullRecords(candidate);
    const noisy = exact.flatMap((record) => [
      { type: "test:enqueue", name: "queued" },
      { type: "test:dequeue", name: "dequeued" },
      { type: "test:diagnostic", name: "diagnostic" },
      { type: "test:stdout", name: "stdout" },
      record
    ]);
    assert.ok(noisy.length > 4096);
    const reported = await reportedRecords(noisy);
    assert.deepEqual(reported, exact, "non-accounting traffic must not consume or truncate evidence");
    assert.equal(reported.length, 1880);
    withLedger((path) => assert.equal(run(path, profile).status, 0), { records: reported });
    withLedger((path) => assert.notEqual(run(path, profile).status, 0), { records: exactFullRecords(!candidate) });
  }
  const noSyntheticHelper = exactFullRecords(false).map((record) =>
    record.name === "Tests/JS/RootWatchdogChildProcess.mjs"
      ? { ...record, file: join(process.cwd(), "Tests", "JS", "RootWatchdogChildProcess.mjs") }
      : record);
  withLedger((path) => assert.notEqual(run(path, "full-source").status, 0), {
    records: noSyntheticHelper
  });
  const root = mkdtempSync("/private/tmp/fulmar-js-tests.");
  const target = join(root, "target");
  const path = join(root, `events-${nonce}.jsonl`);
  try {
    writeFileSync(target, `${records().map((record) => JSON.stringify(record)).join("\n")}\n`, { mode: 0o600 });
    symlinkSync(target, path);
    assert.notEqual(run(path).status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
