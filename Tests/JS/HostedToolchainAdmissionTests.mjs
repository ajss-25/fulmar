import assert from "node:assert/strict";
import {
  appendFile, chmod, link, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, truncate, writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import {
  attestedToolDescriptor,
  captureToolchainInventory,
  expectedHostedRepository,
  resolveHostedToolchainAdmission,
  trackedHostedToolchainPinPath,
  verifyToolchainInventory,
  writeToolchainInventory
} from "../../scripts/toolchain-inventory.mjs";
import { canonicalPinJSON } from "../../scripts/hosted-macos-toolchain-pin.mjs";

const darwinOnly = { skip: process.platform !== "darwin" };
const uid = process.getuid();
const safePath = "/usr/bin:/bin:/usr/sbin:/sbin";

// The pin validator only accepts a full Xcode application under /Applications,
// so the synthetic hosted tree is created there under a unique fixture name and
// removed again; nothing inside it is executable by Launch Services.
async function createHostedFixture() {
  const scratch = await realpath(await mkdtemp(join(tmpdir(), "fulmar-hosted-admission.")));
  const created = await mkdtemp("/Applications/Xcode-fulmar-fixture-");
  const bundle = `${created}.app`;
  await rename(created, bundle);
  const developer = join(bundle, "Contents", "Developer");
  const toolchainBin = join(developer, "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin");
  const sdk = join(developer, "Platforms", "MacOSX.platform", "Developer", "SDKs", "MacOSX.sdk");
  for (const directory of [toolchainBin, join(sdk, "System", "Library", "CoreServices"), join(developer, "usr", "bin")]) {
    await mkdir(directory, { recursive: true, mode: 0o755 });
  }
  let cursor = bundle;
  for (const part of ["Contents", "Developer", "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin"]) {
    cursor = join(cursor, part);
    await chmod(cursor, 0o755);
  }
  await chmod(bundle, 0o755);
  const tool = async (name, seed) => {
    const path = join(toolchainBin, name);
    await writeFile(path, Buffer.alloc(3 * 1024 + seed, seed), { mode: 0o755 });
    await chmod(path, 0o755);
    return path;
  };
  const tools = {
    clang: await tool("clang", 1),
    dsymutil: await tool("dsymutil", 2),
    ld: await tool("ld", 3),
    "swift-frontend": await tool("swift-frontend", 4),
    "swift-package": await tool("swift-package", 5)
  };
  await symlink("swift-frontend", join(toolchainBin, "swift"));
  await symlink("swift-frontend", join(toolchainBin, "swiftc"));
  await symlink("swift-package", join(toolchainBin, "swift-build"));
  await writeFile(join(sdk, "SDKSettings.json"), '{"fixture":true}\n', { mode: 0o644 });
  await writeFile(join(sdk, "System", "Library", "CoreServices", "SystemVersion.plist"), "<plist/>\n", { mode: 0o644 });
  const xcodebuild = join(developer, "usr", "bin", "xcodebuild");
  await writeFile(xcodebuild, Buffer.alloc(2048, 9), { mode: 0o755 });
  const versions = {
    [`${tools["swift-frontend"]} --version`]: "Apple Swift version 6.3.3 (fixture)\nTarget: arm64-apple-macosx26.0",
    [`${tools["swift-package"]} --version`]: "Swift Package Manager - Swift 6.3.3 (fixture)",
    [`${tools.clang} --version`]: "Apple clang version 21.0.0 (fixture)",
    [`${tools.ld} -v`]: "@(#)PROGRAM:ld PROJECT:ld-fixture",
    [`${tools.dsymutil} --version`]: "Apple dsymutil version 21.0.0 (fixture)"
  };
  const table = {
    "/usr/bin/xcrun --sdk macosx --show-sdk-path": sdk,
    "/usr/bin/xcode-select -p": developer,
    "/usr/bin/xcrun -f clang": tools.clang,
    "/usr/bin/xcrun -f dsymutil": tools.dsymutil,
    "/usr/bin/xcrun -f ld": tools.ld,
    "/usr/bin/xcrun -f swift": join(toolchainBin, "swift"),
    "/usr/bin/xcrun -f swift-build": join(toolchainBin, "swift-build"),
    "/usr/bin/xcrun -f swift-frontend": tools["swift-frontend"],
    "/usr/bin/xcrun -f swiftc": join(toolchainBin, "swiftc"),
    "/usr/bin/xcrun --sdk macosx --show-sdk-version": "26.5",
    "/usr/bin/xcrun --sdk macosx --show-sdk-build-version": "25F70",
    "/usr/bin/uname -m": "arm64",
    "/usr/bin/sw_vers -productVersion": "26.5.2",
    "/usr/bin/sw_vers -buildVersion": "25F84",
    ...versions
  };
  const pinPath = join(scratch, "HostedMacOSToolchainPin.json");
  const probes = {
    command: async (path, arguments_) => {
      const key = `${path} ${arguments_.join(" ")}`;
      if (!Object.hasOwn(table, key)) throw new Error(`unexpected fixture command: ${key}`);
      return table[key];
    },
    effectiveUID: () => uid,
    trackedPinPath: () => pinPath
  };
  return {
    scratch, bundle, developer, toolchainBin, sdk, tools, xcodebuild, table, probes, pinPath,
    async remove() {
      await rm(bundle, { recursive: true, force: true });
      await rm(scratch, { recursive: true, force: true });
    }
  };
}

function pinDocument(fixture, inventory, xcodeDescriptor, mutate = () => undefined) {
  const document = {
    schemaVersion: 2,
    pinStatus: "active",
    runnerContract: {
      provider: "github-hosted", requestedLabel: "macos-26", operatingSystem: "macOS", architecture: "ARM64"
    },
    hostedDiscovery: {
      github: { repository: expectedHostedRepository, commitSHA: "a".repeat(40), runID: "1", runAttempt: "1", job: "macos" },
      image: { imageOS: "macos26", imageVersion: "20260728.0273.1" },
      runner: { effectiveUID: uid },
      xcode: { version: "Xcode 26.6\nBuild version 17F113", executable: xcodeDescriptor },
      toolchain: structuredClone(inventory)
    }
  };
  mutate(document);
  return document;
}

async function writePin(path, document, { canonical = true } = {}) {
  const encoded = canonical ? canonicalPinJSON(document) : `${JSON.stringify(document, null, 2)}\n`;
  await rm(path, { force: true });
  await writeFile(path, encoded, { mode: 0o644 });
  await chmod(path, 0o644);
}

// Emulate the exact clean release environment around one capture so the
// clean-capture code path (not only the discovery path) is exercised.
async function inCleanEnvironment(sdk, operation) {
  const saved = { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, SDKROOT: process.env.SDKROOT, DEVELOPER_DIR: process.env.DEVELOPER_DIR };
  process.env.PATH = safePath;
  process.env.TMPDIR = "/private/tmp/";
  process.env.SDKROOT = sdk;
  delete process.env.DEVELOPER_DIR;
  try {
    return await operation();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}

async function activeFixture() {
  const fixture = await createHostedFixture();
  const inventory = await captureToolchainInventory(false, { hostedDeveloperTreeOwnerUID: uid }, fixture.probes);
  const xcode = await attestedToolDescriptor(fixture.xcodebuild, fixture.developer, uid);
  await writePin(fixture.pinPath, pinDocument(fixture, inventory, xcode));
  return { fixture, inventory, xcode };
}

const cleanCapture = (fixture) => inCleanEnvironment(fixture.sdk, () => captureToolchainInventory(
  true, { hostedToolchainPin: fixture.pinPath }, fixture.probes
));

test("an exact active pin admits the pinned hosted tree into a clean capture, and nothing else does", darwinOnly, async () => {
  const { fixture, inventory } = await activeFixture();
  try {
    assert.equal(inventory.developerDirectory, fixture.developer);
    assert.equal(inventory.tools.swiftc.path, fixture.tools["swift-frontend"]);
    assert.equal(inventory.tools["swift-build"].path, fixture.tools["swift-package"]);
    assert.equal(inventory.tools.xcrun.path, "/usr/bin/xcrun");

    const admitted = await cleanCapture(fixture);
    assert.deepEqual(admitted, inventory);
    const admission = await resolveHostedToolchainAdmission({
      pinPath: fixture.pinPath, trackedPinPath: fixture.pinPath, developerDirectory: fixture.developer, effectiveUID: uid
    });
    assert.equal(admission.admitted, true);
    assert.equal(admission.effectiveUID, uid);
    const otherUID = await resolveHostedToolchainAdmission({
      pinPath: fixture.pinPath, trackedPinPath: fixture.pinPath, developerDirectory: fixture.developer, effectiveUID: uid + 1
    });
    assert.deepEqual(otherUID, { admitted: false, reason: "the effective uid is not the pinned hosted runner uid" });
    const otherTree = await resolveHostedToolchainAdmission({
      pinPath: fixture.pinPath, trackedPinPath: fixture.pinPath,
      developerDirectory: "/Library/Developer/CommandLineTools", effectiveUID: uid
    });
    assert.deepEqual(otherTree, { admitted: false, reason: "the selected developer directory is not the pinned Xcode" });

    // Without the pin option the same non-root tree is refused before hashing.
    await assert.rejects(
      inCleanEnvironment(fixture.sdk, () => captureToolchainInventory(true, {}, fixture.probes)),
      /toolchain input is not a bounded controlled regular file/u
    );
    // The raw owner-uid facility never admits a clean capture.
    await assert.rejects(
      inCleanEnvironment(fixture.sdk, () => captureToolchainInventory(true, { hostedDeveloperTreeOwnerUID: uid }, fixture.probes)),
      /clean release toolchain capture remains root-only/u
    );
    await assert.rejects(
      captureToolchainInventory(false, { hostedDeveloperTreeOwnerUID: uid, hostedToolchainPin: fixture.pinPath }, fixture.probes),
      /unexpected schema/u
    );
    // Outside the clean environment the pin still governs verify-style captures.
    assert.deepEqual(await captureToolchainInventory(false, { hostedToolchainPin: fixture.pinPath }, fixture.probes), inventory);
  } finally {
    await fixture.remove();
  }
});

test("pin status, schema, repository, runner contract, uid and developer-directory predicates all fail closed", darwinOnly, async () => {
  const { fixture, inventory, xcode } = await activeFixture();
  try {
    const cases = [
      [(pin) => { pin.pinStatus = "review-required"; }, /remains root-only: the tracked hosted pin is review-required/u, true],
      [(pin) => { pin.pinStatus = "discovery-required"; pin.hostedDiscovery = null; }, /remains root-only: the tracked hosted pin is discovery-required/u, true],
      [(pin) => { pin.schemaVersion = 3; }, /version or status is unsupported/u, false],
      [(pin) => { pin.pinStatus = "released"; }, /version or status is unsupported/u, false],
      [(pin) => { pin.hostedDiscovery.github.repository = "someone-else/fulmar"; }, /unexpected GitHub repository/u, true],
      [(pin) => { pin.runnerContract.architecture = "X64"; }, /not GitHub-hosted macOS ARM64/u, false],
      [(pin) => { pin.runnerContract.provider = "self-hosted"; }, /not GitHub-hosted macOS ARM64/u, false],
      [(pin) => { pin.hostedDiscovery.image.imageOS = ""; }, /hosted ImageOS is not one bounded safe value/u, false],
      [(pin) => { pin.hostedDiscovery.toolchain.architecture = "x86_64"; }, /not arm64|identity is unsupported/u, false],
      [(pin) => { pin.hostedDiscovery.runner.effectiveUID = uid + 1; }, /remains root-only: the effective uid is not the pinned hosted runner uid/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.developerDirectory = "/Applications/Xcode_other.app/Contents/Developer"; }, /remains root-only: the selected developer directory is not the pinned Xcode|outside the selected/u, false],
      [(pin) => { pin.hostedDiscovery.toolchain.build.jobs = 2; }, /build controls changed/u, false],
      [(pin) => { pin.hostedDiscovery.toolchain.versions.swiftc = "Apple Swift version 6.3.4 (drift)"; }, /does not equal the active pinned inventory/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.operatingSystem.buildVersion = "25G99"; }, /does not equal the active pinned inventory/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.sdk.path = `${fixture.sdk}-other`; }, /outside the selected|SDK path does not match/u, false],
      [(pin) => { pin.hostedDiscovery.toolchain.tools.clang.path = join(fixture.toolchainBin, "clang-other"); }, /tool clang path does not match/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.tools.clang.bytes += 1; }, /tool clang does not match the active hosted toolchain pin/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.tools.clang.sha256 = "b".repeat(64); }, /tool clang does not match the active hosted toolchain pin/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.tools.xcrun.sha256 = "c".repeat(64); }, /system tool xcrun does not match/u, true],
      [(pin) => { pin.hostedDiscovery.toolchain.sdk.settings.sha256 = "d".repeat(64); }, /SDK settings does not match/u, true]
    ];
    for (const [mutate, expected, canonical] of cases) {
      await writePin(fixture.pinPath, pinDocument(fixture, inventory, xcode, mutate), { canonical });
      await assert.rejects(cleanCapture(fixture), expected, `mutation ${mutate.toString()}`);
    }
  } finally {
    await fixture.remove();
  }
});

test("the pin must be the literal tracked canonical single-link owner-controlled document", darwinOnly, async () => {
  const { fixture, inventory, xcode } = await activeFixture();
  try {
    const elsewhere = join(fixture.scratch, "Elsewhere.json");
    await writePin(elsewhere, pinDocument(fixture, inventory, xcode));
    await assert.rejects(
      inCleanEnvironment(fixture.sdk, () => captureToolchainInventory(true, { hostedToolchainPin: elsewhere }, fixture.probes)),
      /accepts only the literal tracked Config\/HostedMacOSToolchainPin\.json/u
    );
    await assert.rejects(
      resolveHostedToolchainAdmission({ pinPath: elsewhere, developerDirectory: fixture.developer, effectiveUID: uid }),
      /accepts only the literal tracked/u
    );
    assert.equal(basename(trackedHostedToolchainPinPath), "HostedMacOSToolchainPin.json");

    await rm(fixture.pinPath);
    await symlink(elsewhere, fixture.pinPath);
    await assert.rejects(cleanCapture(fixture), /linked or non-canonical|owner-controlled regular file/u);
    await rm(fixture.pinPath);
    await link(elsewhere, fixture.pinPath);
    await assert.rejects(cleanCapture(fixture), /owner-controlled regular file/u);
    await rm(fixture.pinPath);

    await writePin(fixture.pinPath, pinDocument(fixture, inventory, xcode));
    await writeFile(fixture.pinPath, `${JSON.stringify(pinDocument(fixture, inventory, xcode))}\n`, { mode: 0o644 });
    await assert.rejects(cleanCapture(fixture), /not canonical JSON/u);
    await writePin(fixture.pinPath, pinDocument(fixture, inventory, xcode));
    await chmod(fixture.pinPath, 0o664);
    await assert.rejects(cleanCapture(fixture), /owner-controlled regular file/u);
    await chmod(fixture.pinPath, 0o644);
    assert.deepEqual(await cleanCapture(fixture), inventory);
  } finally {
    await fixture.remove();
  }
});

test("persistent mutation of the pinned tree fails: symlink substitution, replacement, inode change, truncation, growth, modes", darwinOnly, async () => {
  const { fixture, inventory } = await activeFixture();
  try {
    const clang = fixture.tools.clang;
    const original = await readFile(clang);
    const restore = async () => {
      await rm(clang, { force: true });
      await writeFile(clang, original, { mode: 0o755 });
      await chmod(clang, 0o755);
      assert.deepEqual(await cleanCapture(fixture), inventory);
    };

    await rm(clang);
    await symlink(fixture.tools.ld, clang);
    await assert.rejects(cleanCapture(fixture), /tool clang path does not match/u);
    await restore();

    await writeFile(join(fixture.toolchainBin, "clang.new"), Buffer.alloc(original.length, 7), { mode: 0o755 });
    await rename(join(fixture.toolchainBin, "clang.new"), clang);
    await assert.rejects(cleanCapture(fixture), /tool clang does not match the active hosted toolchain pin/u);
    await restore();

    await rm(clang);
    await writeFile(clang, original, { mode: 0o755 });
    await chmod(clang, 0o755);
    assert.deepEqual(await cleanCapture(fixture), inventory, "an identical replacement inode is indistinguishable and accepted");

    await truncate(clang, original.length - 1);
    await assert.rejects(cleanCapture(fixture), /tool clang does not match the active hosted toolchain pin/u);
    await restore();

    await appendFile(clang, Buffer.from([0]));
    await assert.rejects(cleanCapture(fixture), /tool clang does not match the active hosted toolchain pin/u);
    await restore();

    await chmod(clang, 0o775);
    await assert.rejects(cleanCapture(fixture), /toolchain input is not a bounded controlled regular file/u);
    await restore();

    await chmod(fixture.toolchainBin, 0o775);
    await assert.rejects(cleanCapture(fixture), /group- or world-writable/u);
    await chmod(fixture.toolchainBin, 0o755);
    assert.deepEqual(await cleanCapture(fixture), inventory);

    const settings = join(fixture.sdk, "SDKSettings.json");
    await appendFile(settings, "\n");
    await assert.rejects(cleanCapture(fixture), /SDK settings does not match/u);
  } finally {
    await fixture.remove();
  }
});

test("a toolchain inventory created under the pin is rejected by verify after any tree mutation", darwinOnly, async () => {
  const { fixture, inventory } = await activeFixture();
  try {
    const recorded = join(fixture.scratch, "toolchain-inventory.json");
    await writeToolchainInventory(recorded, await cleanCapture(fixture));
    await verifyToolchainInventory(recorded, { hostedToolchainPin: fixture.pinPath }, fixture.probes);
    await appendFile(fixture.tools.dsymutil, Buffer.from([1]));
    await assert.rejects(
      verifyToolchainInventory(recorded, { hostedToolchainPin: fixture.pinPath }, fixture.probes),
      /tool dsymutil does not match the active hosted toolchain pin/u
    );
    fixture.table[`${fixture.tools.ld} -v`] = "@(#)PROGRAM:ld PROJECT:ld-drifted";
    await rm(fixture.tools.dsymutil);
    await writeFile(fixture.tools.dsymutil, Buffer.alloc(3 * 1024 + 2, 2), { mode: 0o755 });
    await chmod(fixture.tools.dsymutil, 0o755);
    await assert.rejects(
      verifyToolchainInventory(recorded, { hostedToolchainPin: fixture.pinPath }, fixture.probes),
      /does not equal the active pinned inventory/u
    );
    assert.deepEqual(JSON.parse(await readFile(recorded, "utf8")), inventory);
  } finally {
    await fixture.remove();
  }
});

test("release scripts bind every toolchain capture to the literal tracked pin without environment or privilege workarounds", async () => {
  const build = await readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8");
  const inventoryTool = await readFile(join(process.cwd(), "scripts", "toolchain-inventory.mjs"), "utf8");
  const pinTool = await readFile(join(process.cwd(), "scripts", "hosted-macos-toolchain-pin.mjs"), "utf8");
  const workflow = await readFile(join(process.cwd(), ".github", "workflows", "verify-source.yml"), "utf8");
  assert.match(build, /^HOSTED_TOOLCHAIN_PIN="\$PROJECT_DIR\/Config\/HostedMacOSToolchainPin\.json"$/mu);
  assert.equal(build.match(/"\$TOOLCHAIN_TOOL" create "\$TOOLCHAIN_INVENTORY" "\$HOSTED_TOOLCHAIN_PIN"/gu)?.length, 1);
  assert.equal(build.match(/"\$TOOLCHAIN_TOOL" verify "\$TOOLCHAIN_INVENTORY" "\$HOSTED_TOOLCHAIN_PIN"/gu)?.length, 3);
  assert.equal(build.match(/"\$TOOLCHAIN_TOOL" (?:create|verify) "\$TOOLCHAIN_INVENTORY"(?!\s+"\$HOSTED_TOOLCHAIN_PIN")/gu), null);
  assert.doesNotMatch(inventoryTool, /process\.env\.[A-Za-z_]*(?:PIN|HOSTED|UID|OWNER)/u);
  assert.doesNotMatch(inventoryTool, /createReadStream|\bstat\(/u);
  assert.match(inventoryTool, /sha256AttestedRegularFile\(path, \{[\s\S]*?requireCanonicalPath: true/u);
  assert.match(inventoryTool, /clean release toolchain capture remains root-only/u);
  assert.match(inventoryTool, /resolve\(pinPath\) !== trackedPinPath/u);
  assert.doesNotMatch(pinTool, /createReadStream/u);
  assert.doesNotMatch(workflow, /\b(?:sudo|chown)\b/u);
});
