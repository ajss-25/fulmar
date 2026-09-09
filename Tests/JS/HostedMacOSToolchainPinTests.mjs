import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  activeHostedMacOSToolchainPins,
  canonicalPinJSON,
  compareHostedMacOSToolchainIdentity,
  discoverHostedMacOSToolchainIdentity,
  hostedGitHubRunnerMetadata,
  readHostedMacOSToolchainPin,
  validateHostedMacOSToolchainPin,
  verifyHostedMacOSToolchainPin,
  writeHostedMacOSToolchainProposal
} from "../../scripts/hosted-macos-toolchain-pin.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const script = join(project, "scripts", "hosted-macos-toolchain-pin.mjs");
const sourcePin = join(project, "Config", "HostedMacOSToolchainPin.json");
const descriptor = (path, marker = "a") => ({
  path,
  bytes: 64,
  sha256: marker.repeat(64)
});

function toolchainFixture() {
  const developer = "/Applications/Xcode_26.0.app/Contents/Developer";
  const toolRoot = `${developer}/Toolchains/XcodeDefault.xctoolchain/usr/bin`;
  const sdk = `${developer}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk`;
  return {
    schemaVersion: 6,
    architecture: "arm64",
    operatingSystem: { productVersion: "26.0", buildVersion: "25A123" },
    developerDirectory: developer,
    sdk: {
      path: sdk,
      version: "26.0",
      buildVersion: "25A123",
      settings: descriptor(`${sdk}/SDKSettings.json`, "b"),
      systemVersion: descriptor(`${sdk}/System/Library/CoreServices/SystemVersion.plist`, "c")
    },
    tools: {
      clang: descriptor(`${toolRoot}/clang`, "d"),
      codesign: descriptor("/usr/bin/codesign", "e"),
      ditto: descriptor("/usr/bin/ditto", "f"),
      dsymutil: descriptor(`${toolRoot}/dsymutil`, "1"),
      ld: descriptor(`${toolRoot}/ld`, "2"),
      sips: descriptor("/usr/bin/sips", "3"),
      strip: descriptor("/usr/bin/strip", "4"),
      swift: descriptor(`${toolRoot}/swift-frontend`, "5"),
      "swift-build": descriptor(`${developer}/usr/bin/swift-package`, "6"),
      "swift-frontend": descriptor(`${toolRoot}/swift-frontend`, "7"),
      swiftc: descriptor(`${toolRoot}/swift-frontend`, "8"),
      xcrun: descriptor("/usr/bin/xcrun", "9")
    },
    versions: {
      swiftc: "Swift version 6.2",
      swiftFrontend: "Swift version 6.2",
      swiftBuild: "Swift Package Manager 6.2",
      clang: "Apple clang version 17.0.0",
      ld: "@(#)PROGRAM:ld PROJECT:ld-1200",
      dsymutil: "LLVM version 17.0.0"
    },
    build: {
      configuration: "release",
      jobs: 1,
      swiftFrontendThreads: 1,
      dsymutilThreads: 1,
      sourcePrefix: "/Fulmar/Sources",
      scratchPrefix: "/Fulmar/Build",
      generatedPrefix: "/Fulmar/Generated",
      linkerReproducible: true,
      canonicalSourceSnapshot: true,
      relativeDebugMapObjects: true,
      serializedDebugPrefixMappings: true,
      swiftPMDebugInfoFormat: "none",
      frontendDebugInfo: "dwarf",
      clangModuleBreadcrumbs: false,
      automaticDSYMGeneration: false,
      compilationDirectory: "/Fulmar/Compilation",
      dsymObjectPrependScratch: true,
      dsymObjectPrefixMaps: ["scratchToEmpty", "generatedScratchLeafToEmpty"]
    }
  };
}

function hostedEnvironment(overrides = {}) {
  return {
    GITHUB_ACTIONS: "true",
    CI: "true",
    RUNNER_OS: "macOS",
    RUNNER_ARCH: "ARM64",
    GITHUB_REPOSITORY: "ajss-25/fulmar",
    GITHUB_SHA: "a".repeat(40),
    GITHUB_RUN_ID: "123456789",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_JOB: "macos",
    ImageOS: "macos26",
    ImageVersion: "20260901.1",
    ...overrides
  };
}

function proposalFixture(pinStatus = "review-required") {
  const toolchain = toolchainFixture();
  return {
    schemaVersion: 2,
    pinStatus,
    runnerContract: {
      provider: "github-hosted",
      requestedLabel: "macos-26",
      operatingSystem: "macOS",
      architecture: "ARM64"
    },
    hostedDiscovery: {
      github: {
        repository: "ajss-25/fulmar",
        commitSHA: "a".repeat(40),
        runID: "123456789",
        runAttempt: "1",
        job: "macos"
      },
      image: { imageOS: "macos26", imageVersion: "20260901.1" },
      runner: { effectiveUID: 501 },
      xcode: {
        version: "Xcode 26.0\nBuild version 17A123",
        executable: descriptor(`${toolchain.developerDirectory}/usr/bin/xcodebuild`, "0")
      },
      toolchain
    }
  };
}

function compatiblePinFixture() {
  const primary = proposalFixture("active");
  const compatible = proposalFixture("active");
  compatible.hostedDiscovery.image.imageVersion = "20260801.1";
  compatible.hostedDiscovery.github.runID = "987654321";
  compatible.hostedDiscovery.toolchain.operatingSystem = { productVersion: "26.0.1", buildVersion: "25A124" };
  compatible.hostedDiscovery.toolchain.versions.clang = "Apple clang version 17.0.0\nTarget: arm64-apple-darwin25.1.0";
  compatible.hostedDiscovery.toolchain.tools.clang.sha256 = "a".repeat(64);
  compatible.hostedDiscovery.toolchain.tools.codesign.bytes += 1;
  compatible.hostedDiscovery.toolchain.tools.codesign.sha256 = "b".repeat(64);
  return { ...primary, schemaVersion: 3, compatiblePins: [compatible] };
}

function freshProposal(pin) {
  const proposal = structuredClone(pin);
  proposal.pinStatus = "review-required";
  proposal.hostedDiscovery.github.commitSHA = "b".repeat(40);
  proposal.hostedDiscovery.github.runID = "111111111";
  return proposal;
}

test("source pin is canonical, active, and retains fail-closed unresolved behavior", async () => {
  const pin = await readHostedMacOSToolchainPin(sourcePin);
  assert.equal(pin.schemaVersion, 3);
  assert.equal(pin.pinStatus, "active");
  assert.notEqual(pin.hostedDiscovery, null);

  const activePins = activeHostedMacOSToolchainPins(pin);
  assert.equal(activePins.length, 2);
  for (const selected of activePins) {
    assert.equal(selected.schemaVersion, 2);
    assert.equal(Object.hasOwn(selected, "compatiblePins"), false);
    assert.deepEqual(compareHostedMacOSToolchainIdentity(pin, freshProposal(selected)), selected);
  }

  const unresolved = {
    schemaVersion: 2,
    pinStatus: "discovery-required",
    runnerContract: structuredClone(pin.runnerContract),
    hostedDiscovery: null
  };
  let captureCalled = false;
  await assert.rejects(
    verifyHostedMacOSToolchainPin("macos-26", unresolved, {
      captureToolchain: async () => { captureCalled = true; return toolchainFixture(); }
    }),
    /discovery-required; hosted discovery and review remain mandatory/u
  );
  assert.equal(captureCalled, false);
});

test("hosted metadata accepts only strict GitHub Actions macOS ARM64 identity", () => {
  assert.deepEqual(hostedGitHubRunnerMetadata(hostedEnvironment(), 501), {
    github: {
      repository: "ajss-25/fulmar",
      commitSHA: "a".repeat(40),
      runID: "123456789",
      runAttempt: "1",
      job: "macos"
    },
    image: { imageOS: "macos26", imageVersion: "20260901.1" },
    runner: { effectiveUID: 501 }
  });
  for (const environment of [
    hostedEnvironment({ GITHUB_ACTIONS: "false" }),
    hostedEnvironment({ RUNNER_OS: "Linux" }),
    hostedEnvironment({ RUNNER_ARCH: "X64" })
  ]) {
    assert.throws(
      () => hostedGitHubRunnerMetadata(environment),
      /requires a GitHub Actions macOS ARM64 runner/u
    );
  }
  assert.throws(
    () => hostedGitHubRunnerMetadata(hostedEnvironment({ GITHUB_REPOSITORY: "owner/repo\nleak" })),
    /GitHub repository is not one bounded safe value/u
  );
  for (const effectiveUID of [0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => hostedGitHubRunnerMetadata(hostedEnvironment(), effectiveUID),
      /hosted runner effective UID is invalid/u
    );
  }
});

test("discovery always emits review-required evidence and validates the full hosted toolchain", async () => {
  const toolchain = toolchainFixture();
  let captureArguments;
  let descriptorArguments;
  const proposal = await discoverHostedMacOSToolchainIdentity("macos-26", {
    environment: hostedEnvironment(),
    effectiveUID: 501,
    captureToolchain: async (...arguments_) => {
      captureArguments = arguments_;
      return toolchain;
    },
    runCommand: async (path, arguments_) => {
      if (path === "/usr/bin/xcrun" && arguments_.join(" ") === "-f xcodebuild") {
        return `${toolchain.developerDirectory}/usr/bin/xcodebuild`;
      }
      if (path === "/usr/bin/xcodebuild" && arguments_.join(" ") === "-version") {
        return "Xcode 26.0\nBuild version 17A123";
      }
      throw new Error("unexpected command fixture");
    },
    describeSystemFile: async (...arguments_) => {
      descriptorArguments = arguments_;
      return descriptor(`${toolchain.developerDirectory}/usr/bin/xcodebuild`, "0");
    }
  });
  assert.equal(proposal.pinStatus, "review-required");
  assert.equal(proposal.schemaVersion, 2);
  assert.equal(Object.hasOwn(proposal, "compatiblePins"), false);
  assert.deepEqual(captureArguments, [false, { hostedDeveloperTreeOwnerUID: 501 }]);
  assert.deepEqual(descriptorArguments, [
    `${toolchain.developerDirectory}/usr/bin/xcodebuild`,
    toolchain.developerDirectory,
    501
  ]);
  assert.deepEqual(proposal.hostedDiscovery.runner, { effectiveUID: 501 });
  assert.equal(proposal.hostedDiscovery.toolchain, toolchain);
  validateHostedMacOSToolchainPin(proposal);
  assert.equal(canonicalPinJSON(proposal), `${JSON.stringify(proposal, null, 2)}\n`);
});

test("schema and path validation reject invented evidence and unsafe tool identities", () => {
  const unresolved = {
    schemaVersion: 2,
    pinStatus: "discovery-required",
    runnerContract: proposalFixture().runnerContract,
    hostedDiscovery: proposalFixture().hostedDiscovery
  };
  assert.throws(
    () => validateHostedMacOSToolchainPin(unresolved),
    /must not contain invented hosted evidence/u
  );

  const missingEvidence = proposalFixture();
  missingEvidence.hostedDiscovery = null;
  assert.throws(
    () => validateHostedMacOSToolchainPin(missingEvidence),
    /requires hosted discovery evidence/u
  );

  const extraKey = proposalFixture();
  extraKey.unreviewed = true;
  assert.throws(() => validateHostedMacOSToolchainPin(extraKey), /unexpected schema/u);

  for (const effectiveUID of [0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
    const invalidOwner = proposalFixture();
    invalidOwner.hostedDiscovery.runner.effectiveUID = effectiveUID;
    assert.throws(
      () => validateHostedMacOSToolchainPin(invalidOwner),
      /hosted runner effective UID is invalid/u
    );
  }

  const homeTool = proposalFixture();
  homeTool.hostedDiscovery.toolchain.tools.clang.path = "/Users/runner/tool/clang";
  assert.throws(() => validateHostedMacOSToolchainPin(homeTool), /reviewed system tool roots/u);

  const traversal = proposalFixture();
  traversal.hostedDiscovery.toolchain.sdk.path = "/Applications/Xcode_26.0.app/Contents/Developer/../SDK.sdk";
  assert.throws(() => validateHostedMacOSToolchainPin(traversal), /canonical absolute system path/u);

  const commandLineTools = proposalFixture();
  commandLineTools.hostedDiscovery.toolchain.developerDirectory = "/Library/Developer/CommandLineTools";
  assert.throws(
    () => validateHostedMacOSToolchainPin(commandLineTools),
    /requires one selected full Xcode application/u
  );

  const compatible = compatiblePinFixture();
  validateHostedMacOSToolchainPin(compatible);
  const [primary, secondary] = activeHostedMacOSToolchainPins(compatible);
  assert.equal(primary.schemaVersion, 2);
  assert.equal(Object.hasOwn(primary, "compatiblePins"), false);
  assert.deepEqual(secondary, compatible.compatiblePins[0]);
  assert.deepEqual(activeHostedMacOSToolchainPins(proposalFixture("active")), [proposalFixture("active")]);

  for (const mutate of [
    (value) => { value.pinStatus = "review-required"; },
    (value) => { value.pinStatus = "discovery-required"; },
    (value) => { value.compatiblePins = []; },
    (value) => { value.compatiblePins = null; },
    (value) => { value.compatiblePins.push(structuredClone(value.compatiblePins[0])); },
    (value) => { delete value.compatiblePins; },
    (value) => { value.compatiblePins[0].pinStatus = "review-required"; },
    (value) => { value.compatiblePins[0].schemaVersion = 3; value.compatiblePins[0].compatiblePins = []; },
    (value) => { value.compatiblePins[0].hostedDiscovery.github.repository = "other/fulmar"; },
    (value) => { value.compatiblePins[0].runnerContract.requestedLabel = "macos-26-large"; },
    (value) => { value.compatiblePins[0].hostedDiscovery.toolchain.operatingSystem = structuredClone(value.hostedDiscovery.toolchain.operatingSystem); },
    (value) => { value.compatiblePins[0].hostedDiscovery.toolchain.tools.clang.sha256 = "not-a-digest"; }
  ]) {
    const rejected = compatiblePinFixture();
    mutate(rejected);
    assert.throws(() => validateHostedMacOSToolchainPin(rejected), undefined, `invalid compatibility record: ${mutate}`);
    assert.throws(() => activeHostedMacOSToolchainPins(rejected), undefined, `invalid record must not yield any active pins: ${mutate}`);
  }
  assert.throws(() => activeHostedMacOSToolchainPins(proposalFixture()), /review-required/u);
});

test("active comparison is exact and fails closed for image, Xcode, or tool drift", async () => {
  const active = proposalFixture("active");
  const current = proposalFixture();
  compareHostedMacOSToolchainIdentity(active, current);

  for (const mutate of [
    (value) => { value.hostedDiscovery.image.imageVersion = "20260902.1"; },
    (value) => { value.hostedDiscovery.runner.effectiveUID = 502; },
    (value) => { value.hostedDiscovery.xcode.version = "Xcode 26.0\nBuild version 17A124"; },
    (value) => { value.hostedDiscovery.toolchain.tools.ld.sha256 = "f".repeat(64); }
  ]) {
    const drifted = proposalFixture();
    mutate(drifted);
    assert.throws(
      () => compareHostedMacOSToolchainIdentity(active, drifted),
      /identity drifted from the active source pin/u
    );
  }
  assert.throws(
    () => compareHostedMacOSToolchainIdentity(proposalFixture(), current),
    /review-required; hosted discovery and review remain mandatory/u
  );

  const compatible = compatiblePinFixture();
  const [primary, secondary] = activeHostedMacOSToolchainPins(compatible);
  for (const selected of [primary, secondary]) {
    assert.deepEqual(compareHostedMacOSToolchainIdentity(compatible, freshProposal(selected)), selected);
    const identity = selected.hostedDiscovery;
    const verified = await verifyHostedMacOSToolchainPin("macos-26", compatible, {
      environment: hostedEnvironment({ ImageVersion: identity.image.imageVersion }),
      effectiveUID: identity.runner.effectiveUID,
      captureToolchain: async () => structuredClone(identity.toolchain),
      runCommand: async (path, arguments_) => {
        if (path === "/usr/bin/xcrun" && arguments_.join(" ") === "-f xcodebuild") return identity.xcode.executable.path;
        if (path === "/usr/bin/xcodebuild" && arguments_.join(" ") === "-version") return identity.xcode.version;
        throw new Error("unexpected compatibility verification command");
      },
      describeSystemFile: async () => structuredClone(identity.xcode.executable)
    });
    assert.equal(verified.schemaVersion, 2);
    assert.equal(verified.pinStatus, "review-required");
    assert.deepEqual(compareHostedMacOSToolchainIdentity(compatible, verified), selected);
  }
  for (const mutate of [
    (value) => { value.hostedDiscovery.image = structuredClone(primary.hostedDiscovery.image); },
    (value) => { value.hostedDiscovery.toolchain.tools.clang = structuredClone(primary.hostedDiscovery.toolchain.tools.clang); },
    (value) => { value.hostedDiscovery.toolchain.tools.codesign = structuredClone(primary.hostedDiscovery.toolchain.tools.codesign); },
    (value) => { value.hostedDiscovery.toolchain.operatingSystem = structuredClone(primary.hostedDiscovery.toolchain.operatingSystem); },
    (value) => { value.hostedDiscovery.toolchain.versions.clang = primary.hostedDiscovery.toolchain.versions.clang; },
    (value) => { value.hostedDiscovery.image.imageVersion = "20260999.1"; }
  ]) {
    const mixed = freshProposal(secondary);
    mutate(mixed);
    assert.throws(
      () => compareHostedMacOSToolchainIdentity(compatible, mixed),
      /identity drifted from the active source pin/u,
      `complete identity matching must not combine independently accepted fields: ${mutate}`
    );
  }
  assert.throws(
    () => compareHostedMacOSToolchainIdentity(compatible, compatible),
    /fresh review-required discovery/u
  );
});

test("pin reader rejects non-canonical, linked, hard-linked, and writable documents", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-hosted-pin-reader.")));
  try {
    const canonical = join(root, "canonical.json");
    await writeFile(canonical, canonicalPinJSON(proposalFixture()), { mode: 0o600 });
    assert.equal((await readHostedMacOSToolchainPin(canonical)).pinStatus, "review-required");

    const bounded = join(root, "compatible.json");
    await writeFile(bounded, canonicalPinJSON(compatiblePinFixture()), { mode: 0o600 });
    assert.deepEqual(await readHostedMacOSToolchainPin(bounded), compatiblePinFixture());

    const noncanonical = join(root, "noncanonical.json");
    await writeFile(noncanonical, JSON.stringify(proposalFixture()), { mode: 0o600 });
    await assert.rejects(readHostedMacOSToolchainPin(noncanonical), /not canonical JSON/u);

    const symbolic = join(root, "symbolic.json");
    await symlink(canonical, symbolic);
    await assert.rejects(readHostedMacOSToolchainPin(symbolic), /linked or non-canonical/u);

    const writable = join(root, "writable.json");
    await writeFile(writable, canonicalPinJSON(proposalFixture()), { mode: 0o600 });
    await chmod(writable, 0o666);
    await assert.rejects(readHostedMacOSToolchainPin(writable), /owner-controlled regular file/u);

    const hard = join(root, "hard.json");
    await link(canonical, hard);
    await assert.rejects(readHostedMacOSToolchainPin(canonical), /owner-controlled regular file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("proposal writer is canonical, exclusive, and refuses a linked parent", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-hosted-pin-writer.")));
  try {
    const parent = join(root, "evidence");
    await mkdir(parent, { mode: 0o700 });
    const output = join(parent, "proposal.json");
    await writeHostedMacOSToolchainProposal(output, proposalFixture());
    assert.equal(await readFile(output, "utf8"), canonicalPinJSON(proposalFixture()));
    await assert.rejects(
      writeHostedMacOSToolchainProposal(output, proposalFixture()),
      /destination already exists/u
    );

    const linkedParent = join(root, "linked-evidence");
    await symlink(parent, linkedParent);
    await assert.rejects(
      writeHostedMacOSToolchainProposal(join(linkedParent, "second.json"), proposalFixture()),
      /parent is linked or non-canonical/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI discovery and active verification both refuse a local runner impersonation", () => {
  const baseEnvironment = {
    HOME: process.env.HOME,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "en_US.UTF-8",
    LC_CTYPE: "UTF-8"
  };
  const discovery = spawnSync(process.execPath, [script, "discover", "macos-26", "/tmp/must-not-write.json"], {
    cwd: project,
    env: baseEnvironment,
    encoding: "utf8"
  });
  assert.notEqual(discovery.status, 0);
  assert.match(discovery.stderr, /requires a GitHub Actions macOS ARM64 runner/u);

  const verification = spawnSync(process.execPath, [script, "verify", "macos-26", sourcePin], {
    cwd: project,
    env: baseEnvironment,
    encoding: "utf8"
  });
  assert.notEqual(verification.status, 0);
  assert.match(verification.stderr, /requires a GitHub Actions macOS ARM64 runner/u);
});

test("hosted macOS CI retains fresh discovery before enforcing the exact reviewed source pin", async () => {
  const workflow = await readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8");
  const macStart = workflow.indexOf("  macos:\n");
  const consumerStart = workflow.indexOf("  minimum-macos-candidate:\n");
  assert.ok(macStart >= 0 && consumerStart > macStart, "macOS producer job is missing");
  const macJob = workflow.slice(macStart, consumerStart);
  const bootstrap = macJob.indexOf("scripts/bootstrap-source-checkout.sh");
  const discover = macJob.indexOf("hosted-macos-toolchain-pin.mjs discover");
  const upload = macJob.indexOf("name: hosted-macos-toolchain-proposal-${{ github.run_id }}-${{ github.run_attempt }}");
  const verify = macJob.indexOf("hosted-macos-toolchain-pin.mjs verify");
  const build = macJob.indexOf("make private-release");
  assert.ok(bootstrap >= 0 && bootstrap < discover && discover < upload && upload < verify && verify < build);
  assert.match(macJob, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7\.0\.1/u);
  assert.match(macJob, /path: \$\{\{ runner\.temp \}\}\/hosted-macos-toolchain-proposal\.json[\s\S]*archive: false[\s\S]*retention-days: 90/u);
  assert.equal((macJob.match(/hosted-macos-toolchain-pin\.mjs discover/gu) ?? []).length, 1);
  assert.equal((macJob.match(/hosted-macos-toolchain-pin\.mjs verify/gu) ?? []).length, 1);
  assert.match(macJob, /VendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node[\s\S]*discover/u);
  assert.match(macJob, /verify[\s\S]*Config\/HostedMacOSToolchainPin\.json/u);
});
