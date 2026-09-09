import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import { chmod, link, mkdtemp, open, readFile, readdir, realpath, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import test from "node:test";

const project = resolve(import.meta.dirname, "../..");
const node = process.env.LOCAL_HARNESS_TEST_NODE ?? process.execPath;
const migrator = join(project, "Resources/MigrateCredentials.mjs");
const helper = join(project, "Tests/Fixtures/fake-credential-helper.mjs");
const yaml = join(project, "VendorRuntime/node_modules/yaml/dist/index.js");
const leaseMarkerName = "FULMAR_CREDENTIAL_MIGRATION_LEASE_FD_V1";
const leaseDescriptor = 198;
const leaseFileName = ".fulmar-credential-migration.lock";

function migrationStdio(descriptor) {
  const stdio = ["ignore", "pipe", "pipe"];
  stdio.length = leaseDescriptor + 1;
  // Node's child_process normalizer skips sparse high-index entries. Explicit
  // nulls make every intermediate descriptor an intentional ignored slot so
  // the exact fd-198 mapping reaches the child.
  for (let index = 3; index < leaseDescriptor; index += 1) stdio[index] = null;
  stdio[leaseDescriptor] = descriptor;
  return stdio;
}

async function descriptorBoundYAMLGraph() {
  const root = dirname(yaml);
  const graph = {};
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile() && entry.name.endsWith(".js")) {
        graph[relative(root, path)] = await readFile(path, "utf8");
      } else if (!entry.isFile()) {
        throw new Error("test YAML graph contains a linked or special node");
      }
    }
  };
  await visit(root);
  return Buffer.from(JSON.stringify(graph)).toString("base64");
}

async function run(command, args, options = {}) {
  return await new Promise((resolveResult, reject) => {
    const { stdio = ["ignore", "pipe", "pipe"], ...spawnOptions } = options;
    const child = spawn(command, args, { ...spawnOptions, stdio });
    if (!child.stdout || !child.stderr) {
      reject(new Error("test child did not expose bounded output pipes"));
      return;
    }
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code, signal) => resolveResult({
      code: code ?? 1,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8")
    }));
  });
}

function canonical(value) {
  return JSON.parse(JSON.stringify(value));
}

function compactDiagnostic(value) {
  return value.replace(/data:text\/javascript;base64,[A-Za-z0-9+/=]+/gu, "data:descriptor-bound-program");
}

function fixtureYAML(refs, records) {
  const lines = ["version: 1", "refs:"];
  for (const [key, value] of Object.entries(refs)) lines.push(`  ${key}: ${JSON.stringify(value)}`);
  lines.push("records:");
  for (const [key, value] of Object.entries(records)) {
    lines.push(`  ${key}:`);
    for (const [field, fieldValue] of Object.entries(value)) lines.push(`    ${field}: ${JSON.stringify(fieldValue)}`);
  }
  return `${lines.join("\n")}\n`;
}

async function scenario({
  refs,
  records,
  initial = { refs: {}, records: {} },
  control = {},
  markerValue = String(leaseDescriptor),
  includeMarker = true,
  inheritLease = true,
  mutateLease,
  replaceLeaseDuringYAMLImport = false,
  boundProgram = false,
  boundEnvironmentTransform = () => {},
  sourceMode = 0o600,
  parentMode = 0o700,
  sourcePathTransform = (value) => value
}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "local-harness-migration-js-"));
  const source = join(root, ".credentials.yaml");
  const lease = join(root, leaseFileName);
  const state = join(root, "state.json");
  const controlPath = join(root, "control.json");
  const helperWrapper = join(root, "credential-helper");
  const helperProbeScript = join(root, "helper-boundary-probe.mjs");
  const helperProbeLog = join(root, "helper-boundary.log");
  const yamlImportLog = join(root, "yaml-import.log");
  const sourceText = fixtureYAML(refs, records);
  await writeFile(source, sourceText, { mode: sourceMode });
  await chmod(source, sourceMode);
  await writeFile(lease, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
  await chmod(lease, 0o600);
  await writeFile(state, JSON.stringify(initial), { mode: 0o600 });
  await writeFile(
    controlPath,
    JSON.stringify({ calls: 0, ...control, sourcePath: source, leasePath: lease }),
    { mode: 0o600 }
  );
  await writeFile(helperProbeScript, `
import { appendFileSync, fstatSync, lstatSync, readdirSync } from "node:fs";
const [leasePath, logPath, markerName] = process.argv.slice(2);
let violation = Object.prototype.hasOwnProperty.call(process.env, markerName) ? "marker" : "";
const leaseInfo = lstatSync(leasePath, { bigint: true });
for (const name of readdirSync("/dev/fd")) {
  if (!/^\\d+$/u.test(name)) continue;
  try {
    const info = fstatSync(Number(name), { bigint: true });
    if (info.dev === leaseInfo.dev && info.ino === leaseInfo.ino) violation ||= "inode";
  } catch {}
}
appendFileSync(logPath, violation ? \`violation:\${violation}\\n\` : "clean\\n");
if (violation) process.exit(91);
`, { mode: 0o600 });
  await writeFile(
    helperWrapper,
    `#!/bin/zsh\n${JSON.stringify(node)} ${JSON.stringify(helperProbeScript)} ${JSON.stringify(lease)} ${JSON.stringify(helperProbeLog)} ${JSON.stringify(leaseMarkerName)} || exit $?\nexec ${JSON.stringify(node)} ${JSON.stringify(helper)} "$@"\n`,
    { mode: 0o700 }
  );
  await chmod(helperWrapper, 0o700);
  const leaseHandle = await open(lease, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
  if (mutateLease) await mutateLease({ root, source, lease, leaseHandle });

  const yamlModule = join(root, "observable-yaml-module.mjs");
  await writeFile(yamlModule, `
import { appendFileSync, chmodSync, rmSync, writeFileSync } from "node:fs";
appendFileSync(${JSON.stringify(yamlImportLog)}, "imported\\n");
${replaceLeaseDuringYAMLImport ? `
rmSync(${JSON.stringify(lease)});
writeFileSync(${JSON.stringify(lease)}, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
chmodSync(${JSON.stringify(lease)}, 0o600);` : ""}
export { parseDocument } from ${JSON.stringify(pathToFileURL(yaml).href)};
`, { mode: 0o600 });
  await chmod(root, parentMode);

  const environment = {
    HOME: root,
    USER: "migration-test",
    LOGNAME: "migration-test",
    PATH: "/usr/bin:/bin",
    LOCAL_HARNESS_MIGRATION_TEST_STATE: state,
    LOCAL_HARNESS_MIGRATION_TEST_CONTROL: controlPath
  };
  if (includeMarker) environment[leaseMarkerName] = markerValue;
  let commandArguments = [migrator, sourcePathTransform(source), helperWrapper, yamlModule];
  if (boundProgram) {
    environment.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_V1 = "descriptor-pinned-base64-v1";
    environment.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_BASE64
      = (await readFile(migrator)).toString("base64");
    environment.FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_V1 = "descriptor-pinned-commonjs-v1";
    environment.FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_BASE64
      = await descriptorBoundYAMLGraph();
    boundEnvironmentTransform(environment);
    commandArguments = [
      "--input-type=module",
      "--eval",
      "await import('data:text/javascript;base64,' + process.env.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_BASE64)",
      sourcePathTransform(source),
      helperWrapper,
      "descriptor-bound-yaml-graph"
    ];
  }
  let result;
  try {
    result = await run(
      node,
      commandArguments,
      {
        env: environment,
        ...(inheritLease ? {
          stdio: migrationStdio(leaseHandle.fd)
        } : {})
      }
    );
  } finally {
    await leaseHandle.close();
  }
  const finalState = JSON.parse(await readFile(state, "utf8"));
  const finalControl = JSON.parse(await readFile(controlPath, "utf8"));
  let finalSource;
  try { finalSource = await readFile(source, "utf8"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  let helperBoundary = [];
  try {
    helperBoundary = (await readFile(helperProbeLog, "utf8"))
      .split("\n")
      .filter((value) => value.length > 0);
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  let yamlImports = 0;
  try {
    yamlImports = (await readFile(yamlImportLog, "utf8"))
      .split("\n")
      .filter((value) => value === "imported")
      .length;
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  return {
    root, source, sourceText, lease, helperWrapper, initial: canonical(initial), result,
    finalState, finalControl, finalSource, helperBoundary, yamlImports,
    cleanup: async () => {
      await chmod(root, 0o700).catch(() => {});
      await rm(root, { recursive: true, force: true });
    }
  };
}

function assertRejectedBeforeHelper(entry) {
  assert.notEqual(entry.result.code, 0);
  assert.equal(entry.finalSource, entry.sourceText);
  assert.deepEqual(entry.finalState, entry.initial);
  assert.equal(entry.finalControl.calls, 0);
  assert.deepEqual(entry.helperBoundary, []);
}

test("successful migration commits exact bytes and scrubs only the opened source inode", async () => {
  const entry = await scenario({
    refs: { Z_TOKEN: "z-value", A_TOKEN: "a-value" },
    records: { "vendor/grant": { kind: "grant", origin: "https://api.example.test:443" } },
    initial: { refs: { A_TOKEN: "old-a", UNRELATED: "keep" }, records: {} }
  });
  try {
    assert.equal(entry.result.code, 0, JSON.stringify({
      stderr: compactDiagnostic(entry.result.stderr),
      helperBoundary: entry.helperBoundary
    }));
    assert.equal(entry.finalSource, "");
    assert.deepEqual(entry.finalState, {
      refs: { A_TOKEN: "a-value", UNRELATED: "keep", Z_TOKEN: "z-value" },
      records: { "vendor/grant": JSON.stringify({ kind: "grant", origin: "https://api.example.test:443" }) }
    });
    assert.deepEqual(JSON.parse(entry.result.stdout), { references: 2, records: 1 });
  } finally { await entry.cleanup(); }
});

test("descriptor-bound program and YAML graph execute without reopening their component paths", async () => {
  const entry = await scenario({
    refs: { DESCRIPTOR_BOUND: "exact-value" },
    records: {},
    boundProgram: true
  });
  try {
    assert.equal(entry.result.code, 0, JSON.stringify({
      stderr: compactDiagnostic(entry.result.stderr),
      helperBoundary: entry.helperBoundary
    }));
    assert.equal(entry.finalSource, "");
    assert.deepEqual(entry.finalState, {
      refs: { DESCRIPTOR_BOUND: "exact-value" },
      records: {}
    });
    assert.deepEqual(entry.helperBoundary, ["clean", "clean", "clean", "clean"]);
  } finally { await entry.cleanup(); }
});

test("missing and malformed descriptor-bound program graph capabilities fail before helper access", async () => {
  const mutations = [
    (environment) => { delete environment.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_V1; },
    (environment) => { environment.FULMAR_CREDENTIAL_MIGRATION_PROGRAM_BASE64 = "%%%"; },
    (environment) => { delete environment.FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_V1; },
    (environment) => { environment.FULMAR_CREDENTIAL_MIGRATION_YAML_GRAPH_BASE64 = "%%%"; },
  ];
  for (const boundEnvironmentTransform of mutations) {
    const entry = await scenario({
      refs: { MUST_NOT_MOVE: "canary" },
      records: {},
      boundProgram: true,
      boundEnvironmentTransform
    });
    try { assertRejectedBeforeHelper(entry); }
    finally { await entry.cleanup(); }
  }
});

test("every injected helper failure preserves source and restores pre-migration state", async () => {
  const refs = { ALPHA: "one", BRAVO: "two" };
  const records = { "vendor/key": { kind: "api-key", key: "three" } };
  const initial = { refs: { ALPHA: "previous", UNRELATED: "keep" }, records: { "other/grant": "{\"kind\":\"grant\"}" } };
  // Three snapshots, three set/readback pairs, and three final reads. Inject at
  // every forward-path helper boundary; the single failure is consumed before
  // rollback starts, so rollback itself can be verified deterministically.
  for (let failAt = 1; failAt <= 12; failAt += 1) {
    const entry = await scenario({ refs, records, initial, control: { failAt } });
    try {
      assert.notEqual(entry.result.code, 0, `failure ${failAt} unexpectedly committed`);
      assert.equal(entry.finalSource, entry.sourceText, `failure ${failAt} removed or changed source`);
      assert.deepEqual(entry.finalState, initial, `failure ${failAt} did not restore Keychain state`);
      assert.match(entry.result.stderr, /plaintext source was preserved|Keychain helper rejected an entry/);
      assert.doesNotMatch(entry.result.stderr, /one|two|three|previous/);
    } finally { await entry.cleanup(); }
  }
});

test("readback corruption rolls back and preserves source", async () => {
  // call 1 snapshots the entry, call 2 writes it, call 3 is its readback.
  const initial = { refs: { TOKEN: "prior" }, records: {} };
  const entry = await scenario({ refs: { TOKEN: "next" }, records: {}, initial, control: { corruptAt: 3 } });
  try {
    assert.notEqual(entry.result.code, 0);
    assert.equal(entry.finalSource, entry.sourceText);
    assert.deepEqual(entry.finalState, initial);
  } finally { await entry.cleanup(); }
});

test("source mutation before deletion aborts, rolls back, and preserves mutated source", async () => {
  // call 1 snapshot, 2 set, 3 readback, 4 final read (which mutates source).
  const initial = { refs: { TOKEN: "prior" }, records: {} };
  const entry = await scenario({ refs: { TOKEN: "next" }, records: {}, initial, control: { mutateSourceAt: 4 } });
  try {
    assert.notEqual(entry.result.code, 0);
    assert.match(entry.finalSource, /MUTATED/);
    assert.deepEqual(entry.finalState, initial);
  } finally { await entry.cleanup(); }
});

test("a replacement installed after final validation is never unlinked or scrubbed", async () => {
  const initial = { refs: { TOKEN: "prior" }, records: {} };
  const entry = await scenario({
    refs: { TOKEN: "next" },
    records: {},
    initial,
    control: { replaceSourceBeforeScrub: true }
  });
  try {
    assert.notEqual(entry.result.code, 0);
    assert.equal(entry.finalSource, "version: 1\nrefs:\n  REPLACEMENT: preserved\n");
    assert.deepEqual(entry.finalState, initial);
    assert.match(entry.result.stderr, /plaintext source was preserved|rollback was incomplete/u);
  } finally { await entry.cleanup(); }
});

test("deterministic randomized fixtures commit exact reference and record sets", async () => {
  let state = 0x1a2b3c4d;
  const random = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let fixture = 0; fixture < 16; fixture += 1) {
    const refs = {};
    const records = {};
    const refCount = 1 + (random() % 4);
    const recordCount = 1 + (random() % 3);
    for (let index = 0; index < refCount; index += 1) refs[`R_${fixture}_${index}`] = `value-${random().toString(16)}-✓`;
    for (let index = 0; index < recordCount; index += 1) {
      records[`provider-${fixture}/key-${index}`] = { kind: index % 2 === 0 ? "api-key" : "grant", value: `record-${random().toString(16)}` };
    }
    const initial = { refs: { UNRELATED: `u-${fixture}` }, records: {} };
    const entry = await scenario({ refs, records, initial });
    try {
      assert.equal(entry.result.code, 0, entry.result.stderr);
      assert.equal(entry.finalSource, "");
      assert.equal(entry.finalState.refs.UNRELATED, `u-${fixture}`);
      for (const [key, value] of Object.entries(refs)) assert.equal(entry.finalState.refs[key], value);
      for (const [key, value] of Object.entries(records)) assert.equal(entry.finalState.records[key], JSON.stringify(value));
    } finally { await entry.cleanup(); }
  }
});

test("unsafe source permissions fail before the helper is called", async () => {
  const entry = await scenario({
    refs: { TOKEN: "secret" },
    records: {},
    sourceMode: 0o644
  });
  try {
    assertRejectedBeforeHelper(entry);
    assert.equal(entry.yamlImports, 0);
    assert.equal((await stat(entry.source)).mode & 0o777, 0o644);
  } finally { await entry.cleanup(); }
});

test("missing malformed and closed lease capabilities fail before YAML or helper access", async () => {
  const cases = [
    { includeMarker: false, inheritLease: true },
    { markerValue: "0198", inheritLease: true },
    { markerValue: "198 ", inheritLease: true },
    { markerValue: "197", inheritLease: true },
    { markerValue: String(leaseDescriptor), inheritLease: false }
  ];
  for (const leaseCase of cases) {
    const entry = await scenario({
      refs: { TOKEN: "secret" },
      records: {},
      ...leaseCase
    });
    try {
      assertRejectedBeforeHelper(entry);
      assert.equal(entry.yamlImports, 0);
    }
    finally { await entry.cleanup(); }
  }
});

test("symlink hardlink mode size and replaced lease paths fail before the helper", async () => {
  const mutations = {
    symlink: async ({ root, lease }) => {
      const outside = join(root, "outside-lease");
      await writeFile(outside, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
      await unlink(lease);
      await symlink(outside, lease);
    },
    hardlink: async ({ root, lease }) => {
      await link(lease, join(root, "lease-hardlink"));
    },
    mode: async ({ lease }) => { await chmod(lease, 0o644); },
    nonempty: async ({ lease }) => { await writeFile(lease, "poison"); },
    replaced: async ({ lease }) => {
      await unlink(lease);
      await writeFile(lease, Buffer.alloc(0), { mode: 0o600, flag: "wx" });
      await chmod(lease, 0o600);
    }
  };
  for (const [name, mutateLease] of Object.entries(mutations)) {
    const entry = await scenario({
      refs: { TOKEN: `secret-${name}` },
      records: {},
      mutateLease
    });
    try {
      assertRejectedBeforeHelper(entry);
      assert.equal(entry.yamlImports, 0);
    }
    finally { await entry.cleanup(); }
  }
});

test("a lease path replaced by YAML import is rejected before the first helper", async () => {
  const entry = await scenario({
    refs: { TOKEN: "secret" },
    records: {},
    replaceLeaseDuringYAMLImport: true
  });
  try {
    assertRejectedBeforeHelper(entry);
    assert.equal(entry.yamlImports, 1);
  }
  finally { await entry.cleanup(); }
});

test("a lease replaced while a helper runs is rejected before its result is admitted", async () => {
  const initial = { refs: { TOKEN: "prior" }, records: {} };
  const entry = await scenario({
    refs: { TOKEN: "next" },
    records: {},
    initial,
    control: { replaceLeaseAt: 1 }
  });
  try {
    assert.notEqual(entry.result.code, 0);
    assert.equal(entry.finalSource, entry.sourceText);
    assert.deepEqual(entry.finalState, initial);
    assert.equal(entry.finalControl.calls, 1);
  } finally { await entry.cleanup(); }
});

test("the source parent and source path are independently canonical and private", async () => {
  const cases = [
    { parentMode: 0o770 },
    { sourcePathTransform: (source) => source.replace("/.credentials.yaml", "/./.credentials.yaml") }
  ];
  for (const sourceCase of cases) {
    const entry = await scenario({
      refs: { TOKEN: "secret" },
      records: {},
      ...sourceCase
    });
    try {
      assertRejectedBeforeHelper(entry);
      assert.equal(entry.yamlImports, 0);
    }
    finally { await entry.cleanup(); }
  }
});

test("every helper child receives neither the lease marker nor any descriptor for its inode", async () => {
  const entry = await scenario({
    refs: { TOKEN: "exact-value" },
    records: {}
  });
  try {
    assert.equal(entry.result.code, 0, entry.result.stderr);
    assert.equal(entry.yamlImports, 1);
    assert.ok(entry.finalControl.calls > 0);
    assert.equal(entry.helperBoundary.length, entry.finalControl.calls);
    assert.ok(entry.helperBoundary.every((value) => value === "clean"));
  } finally { await entry.cleanup(); }
});
