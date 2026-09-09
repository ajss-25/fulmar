import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = join(project, "scripts/verify-macho-compatibility.sh");
const bootstrapNode = join(project, "VendorRuntime/node-v22.23.1-darwin-arm64/bin/node");
const x86Fixture = join(project, "VendorRuntime/node_modules/node-pty/prebuilds/darwin-x64/pty.node");
const x86SpawnFixture = join(project, "VendorRuntime/node_modules/node-pty/prebuilds/darwin-x64/spawn-helper");
const armFixture = join(project, "VendorRuntime/node_modules/node-pty/prebuilds/darwin-arm64/pty.node");
const documentedX86Paths = [
  "dsh/node_modules/node-pty/prebuilds/darwin-x64/pty.node",
  "dsh/node_modules/node-pty/prebuilds/darwin-x64/spawn-helper"
];
const nativeProducts = [
  "LocalHarness",
  "LocalHarnessCredentialHelper",
  "LocalHarnessRuntimeLease",
  "LocalHarnessSandboxRunner",
  "LocalHarnessSchedulerHelper",
  "LocalHarnessUpdateHelper"
];

function invoke(app, signables, minimum = "15.0") {
  return spawnSync("/bin/zsh", ["-f", verifier, app, signables, minimum], {
    encoding: "utf8",
    timeout: 30_000
  });
}

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

async function writeSignables(path, paths) {
  const sorted = [...paths].sort(byteCompare);
  await writeFile(path, `${JSON.stringify({
    schemaVersion: 1,
    root: "Runtime",
    count: sorted.length,
    paths: sorted
  }, null, 2)}\n`, { mode: 0o600 });
}

async function installRuntimeBinary(runtime, relativePath, source) {
  const destination = join(runtime, ...relativePath.split("/"));
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await copyFile(source, destination);
  await chmod(destination, 0o755);
  return destination;
}

async function duplicateMacOSBuildVersion(source, destination) {
  const bytes = await readFile(source);
  assert.equal(bytes.readUInt32LE(0), 0xfeedfacf, "duplicate-load fixture requires thin 64-bit Mach-O");
  const commands = bytes.readUInt32LE(16);
  const commandBytes = bytes.readUInt32LE(20);
  let offset = 32;
  let buildVersionOffset;
  let buildVersionBytes;
  for (let index = 0; index < commands; index += 1) {
    const command = bytes.readUInt32LE(offset);
    const size = bytes.readUInt32LE(offset + 4);
    assert.ok(size >= 8 && offset + size <= 32 + commandBytes, "invalid Mach-O load-command fixture");
    if (command === 0x32 && bytes.readUInt32LE(offset + 8) === 1) {
      buildVersionOffset = offset;
      buildVersionBytes = size;
    }
    offset += size;
  }
  assert.equal(offset, 32 + commandBytes, "Mach-O load commands do not match their header");
  assert.ok(buildVersionOffset !== undefined && buildVersionBytes !== undefined, "macOS build version is missing");
  assert.ok(offset + buildVersionBytes <= bytes.length, "Mach-O fixture has no load-command padding");
  assert.ok(bytes.subarray(offset, offset + buildVersionBytes).every((value) => value === 0),
    "Mach-O fixture has no zeroed load-command padding");
  bytes.copy(bytes, offset, buildVersionOffset, buildVersionOffset + buildVersionBytes);
  bytes.writeUInt32LE(commands + 1, 16);
  bytes.writeUInt32LE(commandBytes + buildVersionBytes, 20);
  await writeFile(destination, bytes, { mode: 0o755 });
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "fulmar-macho-compatibility."));
  const app = join(root, "Fulmar.app");
  const macOS = join(app, "Contents/MacOS");
  const migrationService = join(app, "Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS");
  const brokerService = join(app, "Contents/XPCServices/LocalHarnessCredentialBrokerService.xpc/Contents/MacOS");
  const runtime = join(app, "Contents/Resources/Runtime");
  const signables = join(root, "runtime-signables.json");
  await mkdir(macOS, { recursive: true, mode: 0o700 });
  await mkdir(migrationService, { recursive: true, mode: 0o700 });
  await mkdir(brokerService, { recursive: true, mode: 0o700 });
  await mkdir(runtime, { recursive: true, mode: 0o700 });
  for (const product of nativeProducts) {
    await copyFile(bootstrapNode, join(macOS, product));
    await chmod(join(macOS, product), 0o755);
  }
  await copyFile(bootstrapNode, join(migrationService, "LocalHarnessCredentialMigrationService"));
  await chmod(join(migrationService, "LocalHarnessCredentialMigrationService"), 0o755);
  await copyFile(bootstrapNode, join(brokerService, "LocalHarnessCredentialBrokerService"));
  await chmod(join(brokerService, "LocalHarnessCredentialBrokerService"), 0o755);
  await copyFile(bootstrapNode, join(runtime, "node"));
  await chmod(join(runtime, "node"), 0o755);
  await writeSignables(signables, ["node"]);
  return { root, app, runtime, signables };
}

async function withFixture(action) {
  const current = await fixture();
  try {
    await action(current);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
}

test("the compatibility gate is wired to exact architectures and load-command minima", async () => {
  const source = await readFile(verifier, "utf8");
  assert.match(source, /vtool -arch "\$architecture" -show/u);
  assert.match(source, /LC_BUILD_VERSION/u);
  assert.match(source, /LC_VERSION_MIN_MACOSX/u);
  assert.match(source, /lipo -archs/u);
  assert.match(source, /documented_x86_runtime/u);
  assert.match(source, /minimum_code <= declared_minimum_code/u);
});

test("the real macOS verifier accepts compatible bytes and rejects a higher embedded minimum", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, runtime, signables, root }) => {
    const accepted = invoke(app, signables);
    assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout);

    const original = join(runtime, "node");
    const raised = join(root, "node-minos-16");
    execFileSync("/usr/bin/vtool", [
      "-set-build-version", "macos", "16.0", "16.0", "-replace", "-output", raised, original
    ]);
    await chmod(raised, 0o755);
    await rename(raised, original);
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /requires macOS 16\.0, which exceeds Fulmar's declared minimum macOS 15\.0/u);
  });
});

test("the real macOS verifier rejects a wrong architecture and an extra native product", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, signables }) => {
    await copyFile(x86Fixture, join(app, "Contents/MacOS/LocalHarnessRuntimeLease"));
    await chmod(join(app, "Contents/MacOS/LocalHarnessRuntimeLease"), 0o755);
    const wrongArchitecture = invoke(app, signables);
    assert.notEqual(wrongArchitecture.status, 0);
    assert.match(wrongArchitecture.stderr, /expected arm64, found x86_64/u);
  });

  await withFixture(async ({ app, signables }) => {
    await copyFile(bootstrapNode, join(app, "Contents/MacOS/UnexpectedHelper"));
    const extra = invoke(app, signables);
    assert.notEqual(extra.status, 0);
    assert.match(extra.stderr, /does not contain exactly the six reviewed native products/u);
  });
});

test("the real macOS verifier accepts exactly the two documented x86_64 Runtime paths", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, runtime, signables }) => {
    await installRuntimeBinary(runtime, documentedX86Paths[0], x86Fixture);
    await installRuntimeBinary(runtime, documentedX86Paths[1], x86SpawnFixture);
    await writeSignables(signables, ["node", ...documentedX86Paths]);
    const accepted = invoke(app, signables);
    assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout);
    for (const path of documentedX86Paths) {
      assert.match(accepted.stdout, new RegExp(`${path.replaceAll(".", "\\.")}\\\\tx86_64\\\\tmacOS`, "u"));
    }
  });
});

test("the real macOS verifier rejects undocumented x86_64 and universal Runtime files", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, runtime, signables }) => {
    const undocumented = "dsh/node_modules/example/undocumented.node";
    await installRuntimeBinary(runtime, undocumented, x86Fixture);
    await writeSignables(signables, ["node", undocumented]);
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Unexpected Mach-O architecture.*expected arm64, found x86_64/u);
  });

  await withFixture(async ({ app, runtime, signables, root }) => {
    const universalPath = "dsh/node_modules/example/universal.node";
    const universal = join(root, "universal.node");
    execFileSync("/usr/bin/lipo", ["-create", armFixture, x86Fixture, "-output", universal]);
    await installRuntimeBinary(runtime, universalPath, universal);
    await writeSignables(signables, ["node", universalPath]);
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Unexpected Mach-O architecture.*expected arm64/u);
  });
});

test("the real macOS verifier rejects missing, duplicate, and non-macOS build metadata", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, runtime, signables, root }) => {
    const withoutMinimum = join(root, "node-without-minimum");
    execFileSync("/usr/bin/vtool", [
      "-remove-build-version", "macos", "-output", withoutMinimum, join(runtime, "node")
    ]);
    await chmod(withoutMinimum, 0o755);
    await rename(withoutMinimum, join(runtime, "node"));
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /missing, duplicate, or unsupported minimum-system metadata/u);
  });

  await withFixture(async ({ app, runtime, signables, root }) => {
    const duplicate = join(root, "node-duplicate-minimum");
    await duplicateMacOSBuildVersion(join(runtime, "node"), duplicate);
    await rename(duplicate, join(runtime, "node"));
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /missing, duplicate, or unsupported minimum-system metadata/u);
  });

  await withFixture(async ({ app, runtime, signables, root }) => {
    const wrongPlatform = join(root, "node-ios-minimum");
    execFileSync("/usr/bin/vtool", [
      "-set-build-version", "ios", "15.0", "15.0", "-replace",
      "-output", wrongPlatform, join(runtime, "node")
    ]);
    await chmod(wrongPlatform, 0o755);
    await rename(wrongPlatform, join(runtime, "node"));
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Mach-O target is not built for macOS/u);
  });
});

test("the compatibility verifier rejects hostile signables metadata before inspecting paths", {
  skip: process.platform !== "darwin"
}, async () => {
  await withFixture(async ({ app, signables }) => {
    await writeFile(signables, `${JSON.stringify({
      schemaVersion: 1,
      root: "Runtime",
      count: 1,
      paths: ["../outside"]
    }, null, 2)}\n`, { mode: 0o600 });
    const rejected = invoke(app, signables);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /signable path/u);
  });
});
