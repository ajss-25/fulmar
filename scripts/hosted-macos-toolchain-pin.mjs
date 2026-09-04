import { constants } from "node:fs";
import { execFile } from "node:child_process";
import { link, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  attestedToolDescriptor,
  captureToolchainInventory,
  validateToolchainInventory
} from "./toolchain-inventory.mjs";
import { readAttestedRegularFile, withAttestedDirectory } from "./attested-regular-file.mjs";

const execFileAsync = promisify(execFile);
const safePath = "/usr/bin:/bin:/usr/sbin:/sbin";
const maximumDocumentBytes = 2 * 1024 * 1024;
const maximumSystemFileBytes = 1024 * 1024 * 1024;
const allowedPinStatuses = new Set(["discovery-required", "review-required", "active"]);
const systemToolPaths = new Set([
  "/usr/bin/codesign",
  "/usr/bin/ditto",
  "/usr/bin/sips",
  "/usr/bin/strip",
  "/usr/bin/xcrun"
]);

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be one plain object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} has an unexpected schema`);
  }
}

function safeToken(value, pattern, label, maximumLength = 128) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximumLength
      || /[\u0000-\u001f\u007f]/u.test(value) || !pattern.test(value)) {
    throw new Error(`${label} is not one bounded safe value`);
  }
  return value;
}

function safeRequestedLabel(value) {
  return safeToken(
    value,
    /^macos-[0-9]{2}(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,31})?$/u,
    "requested runner label",
    64
  );
}

function safeAbsoluteSystemPath(value, label) {
  if (typeof value !== "string" || value.length < 2 || value.length > 2_048
      || !value.startsWith("/") || value.includes("\\")
      || /[\u0000-\u001f\u007f]/u.test(value)
      || value.split("/").some((part, index) => index > 0 && (!part || part === "." || part === ".."))) {
    throw new Error(`${label} is not one canonical absolute system path`);
  }
  if (!(value.startsWith("/Applications/")
      || value.startsWith("/Library/Developer/")
      || value.startsWith("/usr/bin/"))) {
    throw new Error(`${label} escapes the reviewed system tool roots`);
  }
  return value;
}

function pathIsWithin(path, root) {
  return path === root || path.startsWith(`${root}/`);
}

function validateRunnerContract(value) {
  exactKeys(
    value,
    ["provider", "requestedLabel", "operatingSystem", "architecture"],
    "hosted runner contract"
  );
  if (value.provider !== "github-hosted" || value.operatingSystem !== "macOS"
      || value.architecture !== "ARM64") {
    throw new Error("hosted runner contract is not GitHub-hosted macOS ARM64");
  }
  safeRequestedLabel(value.requestedLabel);
  return value;
}

function validateGitHubSource(value) {
  exactKeys(value, ["repository", "commitSHA", "runID", "runAttempt", "job"], "GitHub discovery source");
  safeToken(
    value.repository,
    /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/u,
    "GitHub repository",
    201
  );
  safeToken(value.commitSHA, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u, "GitHub commit SHA", 64);
  safeToken(value.runID, /^[1-9][0-9]{0,19}$/u, "GitHub run ID", 20);
  safeToken(value.runAttempt, /^[1-9][0-9]{0,5}$/u, "GitHub run attempt", 6);
  safeToken(value.job, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/u, "GitHub job", 100);
  return value;
}

function validateRunnerImage(value) {
  exactKeys(value, ["imageOS", "imageVersion"], "hosted runner image");
  safeToken(value.imageOS, /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u, "hosted ImageOS", 64);
  safeToken(value.imageVersion, /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u, "hosted ImageVersion", 64);
  return value;
}

function validateRunnerIdentity(value) {
  exactKeys(value, ["effectiveUID"], "hosted runner identity");
  if (!Number.isSafeInteger(value.effectiveUID) || value.effectiveUID <= 0
      || value.effectiveUID > 2_147_483_647) {
    throw new Error("hosted runner effective UID is invalid");
  }
  return value;
}

function validateDescriptor(value, label) {
  exactKeys(value, ["path", "bytes", "sha256"], label);
  safeAbsoluteSystemPath(value.path, `${label}.path`);
  if (!Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > maximumSystemFileBytes) {
    throw new Error(`${label}.bytes is outside the reviewed range`);
  }
  if (typeof value.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(value.sha256)) {
    throw new Error(`${label}.sha256 is invalid`);
  }
  return value;
}

function validateXcode(value, developerDirectory) {
  exactKeys(value, ["version", "executable"], "hosted Xcode identity");
  if (typeof value.version !== "string" || value.version.length < 8 || value.version.length > 4_096
      || /[\u0000\r\u007f]/u.test(value.version)
      || !/^Xcode [^\n]+\nBuild version [^\n]+$/u.test(value.version)) {
    throw new Error("hosted Xcode version output is not one bounded two-line identity");
  }
  validateDescriptor(value.executable, "hosted Xcode executable");
  if (!pathIsWithin(value.executable.path, developerDirectory)) {
    throw new Error("hosted Xcode executable is outside the selected developer directory");
  }
  return value;
}

function validateHostedToolchain(value, requestedLabel) {
  validateToolchainInventory(value);
  if (value.architecture !== "arm64") {
    throw new Error("hosted toolchain is not arm64");
  }
  const expectedMajor = requestedLabel.match(/^macos-([0-9]{2})(?:-|$)/u)?.[1];
  if (!expectedMajor || value.operatingSystem.productVersion.split(".")[0] !== expectedMajor) {
    throw new Error("hosted operating-system major does not match the requested runner label");
  }
  const developerDirectory = safeAbsoluteSystemPath(
    value.developerDirectory,
    "selected developer directory"
  );
  if (!/^\/Applications\/Xcode[A-Za-z0-9._-]*\.app\/Contents\/Developer$/u.test(developerDirectory)) {
    throw new Error("hosted discovery requires one selected full Xcode application");
  }
  const sdkPath = safeAbsoluteSystemPath(value.sdk.path, "selected SDK path");
  const expectedSDKRoot = `${developerDirectory}/Platforms/MacOSX.platform/Developer/SDKs`;
  if (!pathIsWithin(sdkPath, expectedSDKRoot)
      || !/^MacOSX[A-Za-z0-9._-]*\.sdk$/u.test(basename(sdkPath))) {
    throw new Error("selected SDK is outside the selected Xcode application");
  }
  for (const [name, descriptor] of Object.entries(value.tools)) {
    safeAbsoluteSystemPath(descriptor.path, `hosted tool ${name}`);
    if (!pathIsWithin(descriptor.path, developerDirectory)
        && !systemToolPaths.has(descriptor.path)) {
      throw new Error(`hosted tool ${name} is outside the selected Xcode or exact system tool paths`);
    }
  }
  for (const [name, descriptor] of [
    ["SDK settings", value.sdk.settings],
    ["SDK system version", value.sdk.systemVersion]
  ]) {
    safeAbsoluteSystemPath(descriptor.path, name);
    if (!pathIsWithin(descriptor.path, sdkPath)) {
      throw new Error(`${name} is outside the selected SDK`);
    }
  }
  return value;
}

function validateHostedDiscovery(value, runnerContract) {
  exactKeys(value, ["github", "image", "runner", "xcode", "toolchain"], "hosted discovery");
  validateGitHubSource(value.github);
  validateRunnerImage(value.image);
  validateRunnerIdentity(value.runner);
  validateHostedToolchain(value.toolchain, runnerContract.requestedLabel);
  validateXcode(value.xcode, value.toolchain.developerDirectory);
  return value;
}

export function validateHostedMacOSToolchainPin(value) {
  exactKeys(
    value,
    ["schemaVersion", "pinStatus", "runnerContract", "hostedDiscovery"],
    "hosted macOS toolchain pin"
  );
  if (value.schemaVersion !== 2 || !allowedPinStatuses.has(value.pinStatus)) {
    throw new Error("hosted macOS toolchain pin version or status is unsupported");
  }
  validateRunnerContract(value.runnerContract);
  if (value.pinStatus === "discovery-required") {
    if (value.hostedDiscovery !== null) {
      throw new Error("a discovery-required pin must not contain invented hosted evidence");
    }
    return value;
  }
  if (value.hostedDiscovery === null) {
    throw new Error("a review-required or active pin requires hosted discovery evidence");
  }
  validateHostedDiscovery(value.hostedDiscovery, value.runnerContract);
  return value;
}

export function canonicalPinJSON(value) {
  return `${JSON.stringify(validateHostedMacOSToolchainPin(value), null, 2)}\n`;
}

function assertSafePathArgument(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4_096
      || value.includes("\\") || /[\u0000-\u001f\u007f]/u.test(value)
      || value.split("/").some((part) => part === "..")) {
    throw new Error(`${label} is not one bounded non-traversing path`);
  }
}

export async function readHostedMacOSToolchainPin(pathArgument) {
  assertSafePathArgument(pathArgument, "pin path");
  const path = resolve(pathArgument);
  const canonicalPath = await realpath(path);
  if (canonicalPath !== path) {
    throw new Error("hosted macOS toolchain pin path is linked or non-canonical");
  }
  let input;
  try {
    input = await readAttestedRegularFile(path, {
      label: "hosted macOS toolchain pin",
      minimumBytes: 2,
      maximumBytes: maximumDocumentBytes
    });
  } catch (error) {
    throw new Error(
      "hosted macOS toolchain pin is not one bounded owner-controlled regular file",
      { cause: error }
    );
  }
  if ((input.metadata.mode & 0o022n) !== 0n) {
    throw new Error("hosted macOS toolchain pin is not one bounded owner-controlled regular file");
  }
  const encoded = input.bytes.toString("utf8");
  const value = validateHostedMacOSToolchainPin(JSON.parse(encoded));
  if (encoded !== canonicalPinJSON(value)) {
    throw new Error("hosted macOS toolchain pin is not canonical JSON");
  }
  return value;
}

export function hostedGitHubRunnerMetadata(
  environment = process.env,
  effectiveUID = process.geteuid?.() ?? process.getuid?.()
) {
  if (environment.GITHUB_ACTIONS !== "true" || environment.CI !== "true"
      || environment.RUNNER_OS !== "macOS" || environment.RUNNER_ARCH !== "ARM64") {
    throw new Error("hosted discovery requires a GitHub Actions macOS ARM64 runner");
  }
  const metadata = {
    github: {
      repository: environment.GITHUB_REPOSITORY,
      commitSHA: environment.GITHUB_SHA,
      runID: environment.GITHUB_RUN_ID,
      runAttempt: environment.GITHUB_RUN_ATTEMPT,
      job: environment.GITHUB_JOB
    },
    image: {
      imageOS: environment.ImageOS,
      imageVersion: environment.ImageVersion
    },
    runner: { effectiveUID }
  };
  validateGitHubSource(metadata.github);
  validateRunnerImage(metadata.image);
  validateRunnerIdentity(metadata.runner);
  return metadata;
}

async function command(path, arguments_) {
  const { stdout, stderr } = await execFileAsync(path, arguments_, {
    env: {
      PATH: safePath,
      HOME: process.env.HOME ?? "/var/empty",
      TMPDIR: "/private/tmp/",
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8"
    },
    encoding: "utf8",
    maxBuffer: 1024 * 1024
  });
  const output = `${stdout}${stderr}`.trim();
  if (!output || /[\u0000\r\u007f]/u.test(output)) {
    throw new Error(`invalid identity output from ${path}`);
  }
  return output;
}

async function systemFileDescriptor(pathArgument, developerDirectory, hostedDeveloperTreeOwnerUID) {
  const path = await realpath(pathArgument);
  safeAbsoluteSystemPath(path, "hosted system executable");
  // Descriptor-attested, no-follow hashing with the same owner rule as the
  // toolchain capture (root anywhere, the hosted uid only inside the tree).
  try {
    return await attestedToolDescriptor(path, developerDirectory, hostedDeveloperTreeOwnerUID);
  } catch (error) {
    throw new Error("hosted system executable is not one bounded controlled regular file", { cause: error });
  }
}

export async function discoverHostedMacOSToolchainIdentity(
  requestedLabel,
  {
    environment = process.env,
    effectiveUID = process.geteuid?.() ?? process.getuid?.(),
    captureToolchain = captureToolchainInventory,
    runCommand = command,
    describeSystemFile = systemFileDescriptor
  } = {}
) {
  safeRequestedLabel(requestedLabel);
  const metadata = hostedGitHubRunnerMetadata(environment, effectiveUID);
  const toolchain = await captureToolchain(false, {
    hostedDeveloperTreeOwnerUID: metadata.runner.effectiveUID
  });
  validateHostedToolchain(toolchain, requestedLabel);
  const selectedXcodebuild = await runCommand("/usr/bin/xcrun", ["-f", "xcodebuild"]);
  const xcode = {
    version: await runCommand("/usr/bin/xcodebuild", ["-version"]),
    executable: await describeSystemFile(
      selectedXcodebuild,
      toolchain.developerDirectory,
      metadata.runner.effectiveUID
    )
  };
  const proposal = {
    schemaVersion: 2,
    pinStatus: "review-required",
    runnerContract: {
      provider: "github-hosted",
      requestedLabel,
      operatingSystem: "macOS",
      architecture: "ARM64"
    },
    hostedDiscovery: {
      github: metadata.github,
      image: metadata.image,
      runner: metadata.runner,
      xcode,
      toolchain
    }
  };
  validateHostedMacOSToolchainPin(proposal);
  return proposal;
}

function comparableIdentity(document) {
  return {
    repository: document.hostedDiscovery.github.repository,
    image: document.hostedDiscovery.image,
    runner: document.hostedDiscovery.runner,
    xcode: document.hostedDiscovery.xcode,
    toolchain: document.hostedDiscovery.toolchain
  };
}

export function compareHostedMacOSToolchainIdentity(activePin, currentProposal) {
  validateHostedMacOSToolchainPin(activePin);
  validateHostedMacOSToolchainPin(currentProposal);
  if (activePin.pinStatus !== "active") {
    throw new Error(`hosted macOS toolchain pin is ${activePin.pinStatus}; hosted discovery and review remain mandatory`);
  }
  if (currentProposal.pinStatus !== "review-required") {
    throw new Error("current hosted identity must be one fresh review-required discovery");
  }
  if (JSON.stringify(activePin.runnerContract) !== JSON.stringify(currentProposal.runnerContract)
      || JSON.stringify(comparableIdentity(activePin)) !== JSON.stringify(comparableIdentity(currentProposal))) {
    throw new Error("hosted macOS image, Xcode, SDK, compiler, linker, or tool identity drifted from the active source pin");
  }
}

export async function verifyHostedMacOSToolchainPin(
  requestedLabel,
  pin,
  discoveryOptions = {}
) {
  safeRequestedLabel(requestedLabel);
  validateHostedMacOSToolchainPin(pin);
  if (pin.pinStatus !== "active") {
    throw new Error(`hosted macOS toolchain pin is ${pin.pinStatus}; hosted discovery and review remain mandatory`);
  }
  if (pin.runnerContract.requestedLabel !== requestedLabel) {
    throw new Error("requested runner label does not match the active source pin");
  }
  const current = await discoverHostedMacOSToolchainIdentity(requestedLabel, discoveryOptions);
  compareHostedMacOSToolchainIdentity(pin, current);
  return current;
}

export async function writeHostedMacOSToolchainProposal(pathArgument, value) {
  assertSafePathArgument(pathArgument, "proposal path");
  const destination = resolve(pathArgument);
  const leaf = basename(destination);
  safeToken(leaf, /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u, "proposal filename", 128);
  const parent = dirname(destination);
  const payload = canonicalPinJSON(value);
  const temporary = join(parent, `.${leaf}.${process.pid}.tmp`);
  // The complete create/write/sync/publish sequence runs inside one already-open,
  // no-follow, canonical, owner-controlled directory descriptor, which also
  // performs the final directory fsync; no checked path is reopened. The
  // destination is published with link(2), whose EEXIST is the non-racy
  // "must not already exist" check.
  let publishing = false;
  try {
    await withAttestedDirectory(parent, {
      label: "hosted discovery proposal parent",
      allowContentMutation: true,
      requireCurrentUser: true,
      requireOwnerControlledMode: true,
      requireCanonicalPath: true
    }, async ({ handle: directory }) => {
      publishing = true;
      let handle;
      try {
        // O_EXCL makes the descriptor creation itself the non-racy existence check.
        handle = await open(
          temporary,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600
        );
        await handle.writeFile(payload, "utf8");
        await handle.sync();
        await handle.chmod(0o644);
        await handle.close();
        handle = undefined;
        try {
          await link(temporary, destination);
        } catch (error) {
          if (error?.code === "EEXIST") throw new Error("hosted discovery proposal destination already exists");
          throw error;
        }
        await directory.sync();
      } finally {
        await handle?.close().catch(() => {});
        await unlink(temporary).catch(() => {});
      }
    });
  } catch (error) {
    if (publishing) throw error;
    if (/not owned by the current user|group- or world-writable/u.test(error?.message ?? "")) {
      throw new Error("hosted discovery proposal parent is not owner-controlled", { cause: error });
    }
    throw new Error("hosted discovery proposal parent is linked or non-canonical", { cause: error });
  }
}

async function main() {
  const [operation, requestedLabel, path] = process.argv.slice(2);
  if (!new Set(["discover", "verify"]).has(operation) || !requestedLabel || !path
      || process.argv.length !== 5) {
    throw new Error("usage: hosted-macos-toolchain-pin.mjs <discover|verify> <macos-runner-label> <pin-or-proposal.json>");
  }
  if (operation === "discover") {
    const proposal = await discoverHostedMacOSToolchainIdentity(requestedLabel);
    await writeHostedMacOSToolchainProposal(path, proposal);
    process.stdout.write(`Wrote review-required hosted macOS identity proposal to ${basename(path)}.\n`);
    return;
  }
  const pin = await readHostedMacOSToolchainPin(path);
  await verifyHostedMacOSToolchainPin(requestedLabel, pin);
  process.stdout.write(`Verified exact active hosted macOS toolchain pin for ${requestedLabel}.\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`Hosted macOS toolchain identity failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
