import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  captureToolchainInventory,
  compareToolchainInventories,
  toolchainInputOwnerIsAccepted,
  validateToolchainInventory,
  verifyToolchainInventory,
  writeToolchainInventory
} from "../../scripts/toolchain-inventory.mjs";

const execFileAsync = promisify(execFile);
const toolNames = [
  "clang", "codesign", "ditto", "dsymutil", "ld", "sips", "strip",
  "swift", "swift-build", "swift-frontend", "swiftc", "xcrun"
];

function descriptor(name) {
  return { path: `/usr/bin/${name}`, bytes: 1, sha256: "a".repeat(64) };
}

function inventoryFixture() {
  return {
    schemaVersion: 4,
    architecture: "arm64",
    operatingSystem: { productVersion: "26.6.2", buildVersion: "25G83" },
    developerDirectory: "/Library/Developer/CommandLineTools",
    sdk: {
      path: "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
      version: "26.5",
      buildVersion: "25F70",
      settings: descriptor("SDKSettings.json"),
      systemVersion: descriptor("SystemVersion.plist")
    },
    versions: {
      swiftc: "Swift 6.3.3",
      swiftFrontend: "Swift frontend 6.3.3",
      swiftBuild: "Swift Package Manager 6.3.3",
      clang: "Clang 21",
      ld: "ld 1234",
      dsymutil: "dsymutil 21"
    },
    tools: Object.fromEntries(toolNames.map((name) => [name, descriptor(name)])),
    build: {
      configuration: "release",
      jobs: 1,
      swiftFrontendThreads: 1,
      sourcePrefix: "/Fulmar/Sources",
      scratchPrefix: "/Fulmar/Build",
      generatedPrefix: "/Fulmar/Generated",
      linkerReproducible: true,
      canonicalSourceSnapshot: true,
      relativeDebugMapObjects: true,
      serializedDebugPrefixMappings: true,
      swiftPMDebugInfoFormat: "none",
      frontendDebugInfo: "dwarf",
      automaticDSYMGeneration: false,
      compilationDirectory: "/Fulmar/Compilation",
      dsymObjectPrependScratch: true,
      dsymObjectPrefixMaps: ["scratchToEmpty", "generatedScratchLeafToEmpty"]
    }
  };
}

function clone(value) {
  return structuredClone(value);
}

test("toolchain inventory schema rejects identity, descriptor, build-control, and extra-field mutations", () => {
  const baseline = inventoryFixture();
  assert.equal(validateToolchainInventory(baseline), baseline);
  const developerDirectory = "/Applications/Xcode_26.6.app/Contents/Developer";
  const developerTool = `${developerDirectory}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang`;
  assert.equal(toolchainInputOwnerIsAccepted("/usr/bin/xcrun", developerDirectory, 0), true);
  assert.equal(toolchainInputOwnerIsAccepted(developerTool, developerDirectory, 501), false);
  assert.equal(toolchainInputOwnerIsAccepted(developerTool, developerDirectory, 501, 501), true);
  assert.equal(toolchainInputOwnerIsAccepted(developerTool, developerDirectory, 502, 501), false);
  assert.equal(toolchainInputOwnerIsAccepted("/usr/bin/xcrun", developerDirectory, 501, 501), false);
  assert.equal(toolchainInputOwnerIsAccepted(`${developerDirectory}-other/clang`, developerDirectory, 501, 501), false);
  const mutations = [
    (value) => { value.schemaVersion = 3; },
    (value) => { value.architecture = "x86_64"; },
    (value) => { value.unreviewed = true; },
    (value) => { delete value.tools["swift-build"]; },
    (value) => { value.tools.swift.sha256 = "z".repeat(64); },
    (value) => { value.tools.swift.path = "relative/swift"; },
    (value) => { value.sdk.settings.bytes = 0; },
    (value) => { value.versions.swiftc = "bad\0version"; },
    (value) => { value.build.jobs = 2; },
    (value) => { value.build.swiftFrontendThreads = 2; },
    (value) => { value.build.swiftPMDebugInfoFormat = "dwarf"; },
    (value) => { value.build.frontendDebugInfo = "none"; },
    (value) => { value.build.automaticDSYMGeneration = true; },
    (value) => { value.build.canonicalSourceSnapshot = false; },
    (value) => { value.build.relativeDebugMapObjects = false; },
    (value) => { value.build.dsymObjectPrependScratch = false; },
    (value) => { value.build.compilationDirectory = "/private/tmp/checkout"; },
    (value) => { value.build.dsymObjectPrefixMaps = ["scratchToEmpty"]; }
  ];
  for (const mutate of mutations) {
    const candidate = clone(baseline);
    mutate(candidate);
    assert.throws(() => validateToolchainInventory(candidate));
  }
});

test("toolchain comparison detects validly shaped OS, SDK, tool, and version drift", () => {
  const baseline = inventoryFixture();
  const mutations = [
    (value) => { value.operatingSystem.buildVersion = "25G84"; },
    (value) => { value.sdk.version = "26.6"; },
    (value) => { value.tools["swift-frontend"].sha256 = "b".repeat(64); },
    (value) => { value.versions.swiftBuild = "Swift Package Manager 6.3.4"; }
  ];
  for (const mutate of mutations) {
    const candidate = clone(baseline);
    mutate(candidate);
    assert.throws(() => compareToolchainInventories(baseline, candidate), /toolchain changed/u);
  }
});

test("toolchain writer is canonical and removes its temporary file when publication fails", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-toolchain-writer-"));
  const destination = join(root, "toolchain.json");
  try {
    await writeToolchainInventory(destination, inventoryFixture());
    const encoded = await readFile(destination, "utf8");
    assert.equal(encoded, `${JSON.stringify(JSON.parse(encoded), null, 2)}\n`);
    assert.equal((await lstat(destination)).mode & 0o777, 0o644);

    const blocked = join(root, "blocked.json");
    await mkdir(blocked);
    await assert.rejects(writeToolchainInventory(blocked, inventoryFixture()));
    await assert.rejects(lstat(join(root, `.blocked.json.${process.pid}.tmp`)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("toolchain verifier rejects permissive, linked, hard-linked, and oversized files before capture", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-toolchain-file-"));
  try {
    const canonical = `${JSON.stringify(inventoryFixture(), null, 2)}\n`;
    const permissive = join(root, "permissive.json");
    await writeFile(permissive, canonical, { mode: 0o666 });
    await chmod(permissive, 0o666);
    await assert.rejects(verifyToolchainInventory(permissive), /owner-controlled/u);

    const target = join(root, "target.json");
    await writeFile(target, canonical, { mode: 0o644 });
    const symbolic = join(root, "symbolic.json");
    await symlink(target, symbolic);
    await assert.rejects(verifyToolchainInventory(symbolic), /owner-controlled/u);

    const hard = join(root, "hard.json");
    await link(target, hard);
    await assert.rejects(verifyToolchainInventory(target), /owner-controlled/u);

    const oversized = join(root, "oversized.json");
    await writeFile(oversized, Buffer.alloc(1024 * 1024 + 1), { mode: 0o644 });
    await assert.rejects(verifyToolchainInventory(oversized), /owner-controlled/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("toolchain create CLI refuses a non-release environment before inspecting tools", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-toolchain-clean-env-"));
  try {
    await assert.rejects(
      captureToolchainInventory(true, { hostedDeveloperTreeOwnerUID: 501 }),
      /clean release toolchain capture remains root-only/u
    );
    await assert.rejects(execFileAsync(process.execPath, [
      join(process.cwd(), "scripts", "toolchain-inventory.mjs"), "create", join(root, "toolchain.json")
    ], {
      env: { PATH: "/usr/bin:/bin", TMPDIR: "/private/tmp/", HOME: process.env.HOME ?? "/var/empty" }
    }), /exact clean release environment/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("real host toolchain inventory creates and verifies under the exact release environment", { timeout: 240_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-toolchain-live-"));
  try {
    const { stdout: sdkOutput } = await execFileAsync("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
    const destination = join(root, "toolchain.json");
    const cleanEnvironment = {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      TMPDIR: "/private/tmp/",
      HOME: process.env.HOME ?? "/var/empty",
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8",
      SDKROOT: sdkOutput.trim()
    };
    const script = join(process.cwd(), "scripts", "toolchain-inventory.mjs");
    await execFileAsync(process.execPath, [script, "create", destination], { env: cleanEnvironment, timeout: 180_000 });
    const verified = await execFileAsync(process.execPath, [script, "verify", destination], { env: cleanEnvironment, timeout: 180_000 });
    assert.match(verified.stdout, /Verified release toolchain/u);
    const recorded = JSON.parse(await readFile(destination, "utf8"));
    assert.deepEqual(Object.keys(recorded.tools).sort(), toolNames.sort());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
