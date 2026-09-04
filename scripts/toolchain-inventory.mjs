import { execFile } from "node:child_process";
import { open, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  readAttestedRegularFile,
  sha256AttestedRegularFile,
  withAttestedDirectory
} from "./attested-regular-file.mjs";

const execFileAsync = promisify(execFile);
const safePath = "/usr/bin:/bin:/usr/sbin:/sbin";
const maximumInventoryBytes = 1024 * 1024;
const maximumToolBytes = 1024 * 1024 * 1024;
// Developer-tree tools are single binaries (symbolic aliases resolve first);
// SIP-protected /usr/bin shims are legitimately multi-linked, so their bound
// is generous but still finite.
const maximumDeveloperToolLinks = 16;
const maximumSystemToolLinks = 4096;
const toolNames = [
  "clang", "codesign", "ditto", "dsymutil", "ld", "sips", "strip",
  "swift", "swift-build", "swift-frontend", "swiftc", "xcrun"
];
const developerToolNames = ["clang", "dsymutil", "ld", "swift", "swift-build", "swift-frontend", "swiftc"];
const systemToolPaths = Object.freeze({
  codesign: "/usr/bin/codesign",
  ditto: "/usr/bin/ditto",
  sips: "/usr/bin/sips",
  strip: "/usr/bin/strip",
  xcrun: "/usr/bin/xcrun"
});

/**
 * The only file that can admit a non-root-owned toolchain into a clean release
 * capture. It is resolved from this script's own repository, never from an
 * environment variable or an arbitrary argument.
 */
export const trackedHostedToolchainPinPath = resolve(
  dirname(fileURLToPath(import.meta.url)), "..", "Config", "HostedMacOSToolchainPin.json"
);
/** The exact GitHub repository whose hosted discovery an active pin may record. */
export const expectedHostedRepository = "ajss-25/fulmar";

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} must be one plain object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new Error(`${label} has an unexpected schema`);
}

function boundedString(value, label, { absolute = false, multiline = false } = {}) {
  if (typeof value !== "string" || value.length < 1 || value.length > 65536
      || value.includes("\0") || value.includes("\r") || (!multiline && value.includes("\n"))
      || (absolute && !value.startsWith("/"))) throw new Error(`${label} is not a bounded canonical string`);
}

function pathIsWithin(path, root) {
  return path === root || path.startsWith(`${root}/`);
}

export function toolchainInputOwnerIsAccepted(
  path,
  developerDirectory,
  ownerUID,
  hostedDeveloperTreeOwnerUID = null
) {
  if (ownerUID === 0) return true;
  return Number.isSafeInteger(hostedDeveloperTreeOwnerUID)
    && hostedDeveloperTreeOwnerUID > 0
    && ownerUID === hostedDeveloperTreeOwnerUID
    && pathIsWithin(path, developerDirectory);
}

function validateOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)
      || Object.getPrototypeOf(options) !== Object.prototype) {
    throw new Error("toolchain capture options must be one plain object");
  }
  const keys = Object.keys(options);
  if (keys.some((key) => key !== "hostedDeveloperTreeOwnerUID" && key !== "hostedToolchainPin")
      || keys.length > 1) {
    throw new Error("toolchain capture options have an unexpected schema");
  }
}

// The raw owner-uid facility exists only for hosted discovery, which runs in
// the workflow environment before any pin exists. A clean release capture can
// never take an owner uid from its caller; it admits a non-root tree solely
// through the tracked active pin (see resolveHostedToolchainAdmission).
function hostedDeveloperTreeOwner(options, requireCleanEnvironment) {
  if (!Object.hasOwn(options, "hostedDeveloperTreeOwnerUID")) return null;
  const ownerUID = options.hostedDeveloperTreeOwnerUID;
  if (!Number.isSafeInteger(ownerUID) || ownerUID <= 0 || ownerUID > 2_147_483_647) {
    throw new Error("hosted developer-tree owner identity is invalid");
  }
  if (requireCleanEnvironment) {
    throw new Error("clean release toolchain capture remains root-only");
  }
  return ownerUID;
}

function validateDescriptor(value, label) {
  exactKeys(value, ["bytes", "path", "sha256"], label);
  boundedString(value.path, `${label}.path`, { absolute: true });
  if (!Number.isSafeInteger(value.bytes) || value.bytes <= 0 || value.bytes > maximumToolBytes) {
    throw new Error(`${label}.bytes is outside the accepted range`);
  }
  if (typeof value.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(value.sha256)) {
    throw new Error(`${label}.sha256 is invalid`);
  }
}

const expectedBuildControls = Object.freeze({
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
  dsymObjectPrefixMaps: Object.freeze(["scratchToEmpty", "generatedScratchLeafToEmpty"])
});

function buildControls() {
  return JSON.parse(JSON.stringify(expectedBuildControls));
}

export function validateToolchainInventory(value) {
  exactKeys(value, ["architecture", "build", "developerDirectory", "operatingSystem", "schemaVersion", "sdk", "tools", "versions"], "toolchain inventory");
  if (value.schemaVersion !== 6 || value.architecture !== "arm64") throw new Error("toolchain inventory identity is unsupported");
  boundedString(value.developerDirectory, "developerDirectory", { absolute: true });
  exactKeys(value.operatingSystem, ["buildVersion", "productVersion"], "operatingSystem");
  boundedString(value.operatingSystem.productVersion, "operatingSystem.productVersion");
  boundedString(value.operatingSystem.buildVersion, "operatingSystem.buildVersion");
  exactKeys(value.sdk, ["buildVersion", "path", "settings", "systemVersion", "version"], "sdk");
  boundedString(value.sdk.path, "sdk.path", { absolute: true });
  boundedString(value.sdk.version, "sdk.version");
  boundedString(value.sdk.buildVersion, "sdk.buildVersion");
  validateDescriptor(value.sdk.settings, "sdk.settings");
  validateDescriptor(value.sdk.systemVersion, "sdk.systemVersion");
  exactKeys(value.tools, toolNames, "tools");
  for (const name of toolNames) validateDescriptor(value.tools[name], `tools.${name}`);
  exactKeys(value.versions, ["clang", "dsymutil", "ld", "swiftBuild", "swiftFrontend", "swiftc"], "versions");
  for (const [name, version] of Object.entries(value.versions)) {
    boundedString(version, `versions.${name}`, { multiline: true });
  }
  exactKeys(value.build, Object.keys(expectedBuildControls), "build");
  if (JSON.stringify(value.build) !== JSON.stringify(expectedBuildControls)) throw new Error("toolchain build controls changed");
  return value;
}

export function compareToolchainInventories(recorded, current) {
  validateToolchainInventory(recorded);
  validateToolchainInventory(current);
  if (JSON.stringify(recorded) !== JSON.stringify(current)) throw new Error("toolchain changed after candidate compilation");
}

async function command(path, arguments_) {
  const { stdout, stderr } = await execFileAsync(path, arguments_, {
    env: {
      PATH: safePath,
      SDKROOT: process.env.SDKROOT ?? "",
      HOME: process.env.HOME ?? "/var/empty",
      TMPDIR: "/private/tmp/",
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8"
    },
    encoding: "utf8",
    maxBuffer: 1024 * 1024
  });
  const output = `${stdout}${stderr}`.trim();
  if (!output || /[\u0000\r]/u.test(output)) throw new Error(`invalid output from ${path}`);
  return output;
}

/**
 * Probes are function values used only by deterministic unit tests to stand
 * in for the live host (commands, effective uid, the tracked pin location).
 * A release subprocess can never supply them: the CLI always uses the live
 * defaults, and no environment variable is consulted.
 */
const defaultProbes = Object.freeze({
  command,
  effectiveUID: () => process.geteuid?.() ?? process.getuid?.() ?? -1,
  trackedPinPath: () => trackedHostedToolchainPinPath
});

/**
 * Pin-bound hosted admission for a clean release capture.
 *
 * What this proves: the reviewed, tracked, active hosted pin describes exactly
 * this runner tree (effective uid, developer directory, SDK, every tool's
 * canonical path, byte count and SHA-256, OS, versions and build controls),
 * and nothing under the pinned developer directory has been persistently
 * replaced since the pin was reviewed. It is exact reviewed-image provenance
 * with persistent-mutation detection. It is not a sandbox: same-uid or
 * passwordless-sudo workflow code running on the same runner is outside its
 * threat model, and the live GitHub Actions / runner-image environment
 * variables are bound by the preceding workflow `verify` step, not by this
 * environment-free capture.
 */
export async function resolveHostedToolchainAdmission({
  pinPath,
  trackedPinPath = trackedHostedToolchainPinPath,
  developerDirectory,
  effectiveUID
}) {
  if (typeof pinPath !== "string" || resolve(pinPath) !== trackedPinPath) {
    throw new Error("hosted toolchain admission accepts only the literal tracked Config/HostedMacOSToolchainPin.json");
  }
  const { readHostedMacOSToolchainPin } = await import("./hosted-macos-toolchain-pin.mjs");
  const pin = await readHostedMacOSToolchainPin(trackedPinPath);
  if (pin.pinStatus !== "active") {
    return Object.freeze({ admitted: false, reason: `the tracked hosted pin is ${pin.pinStatus}` });
  }
  const contract = pin.runnerContract;
  if (contract.provider !== "github-hosted" || contract.operatingSystem !== "macOS"
      || contract.architecture !== "ARM64") {
    throw new Error("the tracked hosted pin is not a GitHub-hosted macOS ARM64 runner contract");
  }
  if (pin.hostedDiscovery.github.repository !== expectedHostedRepository) {
    throw new Error("the tracked hosted pin was discovered in an unexpected GitHub repository");
  }
  const runnerUID = pin.hostedDiscovery.runner.effectiveUID;
  if (!Number.isSafeInteger(effectiveUID) || effectiveUID !== runnerUID) {
    return Object.freeze({ admitted: false, reason: "the effective uid is not the pinned hosted runner uid" });
  }
  const toolchain = pin.hostedDiscovery.toolchain;
  if (developerDirectory !== toolchain.developerDirectory) {
    return Object.freeze({ admitted: false, reason: "the selected developer directory is not the pinned Xcode" });
  }
  return Object.freeze({ admitted: true, effectiveUID: runnerUID, toolchain, pin });
}

function ownerSetFor(path, developerDirectory, admittedUID) {
  return Number.isSafeInteger(admittedUID) && admittedUID > 0 && pathIsWithin(path, developerDirectory)
    ? [0, admittedUID]
    : [0];
}

/**
 * Describe one toolchain input through a no-follow descriptor: the pathname
 * is canonical, the descriptor's own metadata is the reviewed shape (regular,
 * bounded, owner root or the admitted hosted uid inside the developer tree,
 * no group/world write, bounded link count), and pathname identity plus
 * descriptor metadata are rechecked before and after hashing.
 */
export async function attestedToolDescriptor(pathArgument, developerDirectory, admittedUID = null) {
  const path = await realpath(pathArgument);
  let attested;
  try {
    attested = await sha256AttestedRegularFile(path, {
      label: `toolchain input ${basename(path)}`,
      minimumBytes: 1,
      maximumBytes: maximumToolBytes,
      acceptedOwnerUIDs: ownerSetFor(path, developerDirectory, admittedUID),
      requireOwnerControlledMode: true,
      requireSingleLink: false,
      maximumLinks: pathIsWithin(path, developerDirectory) ? maximumDeveloperToolLinks : maximumSystemToolLinks,
      requireCanonicalPath: true
    });
  } catch (error) {
    throw new Error(`toolchain input is not a bounded controlled regular file: ${path}`, { cause: error });
  }
  return { path, bytes: Number(attested.metadata.size), sha256: attested.sha256 };
}

async function attestDeveloperTreeDirectory(path, developerDirectory, admittedUID) {
  await withAttestedDirectory(path, {
    label: `developer tree directory ${basename(path)}`,
    requireCurrentUser: false,
    acceptedOwnerUIDs: ownerSetFor(path, developerDirectory, admittedUID),
    requireOwnerControlledMode: true,
    requireCanonicalPath: true
  }, async () => undefined);
}

// Attest the canonical developer directory and every directory from it down to
// each pinned tool's parent and the SDK, each through its own no-follow
// directory descriptor bound to its pathname.
async function attestDeveloperTreeChain(developerDirectory, leafPaths, admittedUID) {
  const directories = new Set([developerDirectory]);
  for (const leaf of leafPaths) {
    let cursor = dirname(leaf);
    while (pathIsWithin(cursor, developerDirectory)) {
      directories.add(cursor);
      if (cursor === developerDirectory) break;
      cursor = dirname(cursor);
    }
  }
  for (const directory of [...directories].sort()) {
    await attestDeveloperTreeDirectory(directory, developerDirectory, admittedUID);
  }
}

function requirePinnedDescriptor(label, actual, pinned) {
  if (!pinned || JSON.stringify(actual) !== JSON.stringify(pinned)) {
    throw new Error(`${label} does not match the active hosted toolchain pin`);
  }
}

export async function captureToolchainInventory(requireCleanEnvironment = false, options = {}, probes = defaultProbes) {
  validateOptions(options);
  const hostedDeveloperTreeOwnerUID = hostedDeveloperTreeOwner(options, requireCleanEnvironment);
  const pinPath = Object.hasOwn(options, "hostedToolchainPin") ? options.hostedToolchainPin : null;
  if (requireCleanEnvironment && (process.env.PATH !== safePath || process.env.TMPDIR !== "/private/tmp/"
      || !process.env.SDKROOT || process.env.DEVELOPER_DIR)) {
    throw new Error("toolchain capture requires the exact clean release environment");
  }
  const run = probes.command;
  const selectedSDK = await run("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
  const declaredSDK = resolve(process.env.SDKROOT || selectedSDK);
  const canonicalDeclaredSDK = await realpath(declaredSDK);
  const canonicalSelectedSDK = await realpath(selectedSDK);
  if (canonicalDeclaredSDK !== canonicalSelectedSDK) throw new Error("selected SDK changed after the compatibility probe");
  const developerDirectory = await realpath(await run("/usr/bin/xcode-select", ["-p"]));

  // Admission is decided before any toolchain file is hashed or executed, and
  // only through the tracked pin; the raw uid facility never reaches here in a
  // clean capture.
  let admission = null;
  if (pinPath !== null) {
    admission = await resolveHostedToolchainAdmission({
      pinPath,
      trackedPinPath: probes.trackedPinPath(),
      developerDirectory,
      effectiveUID: probes.effectiveUID()
    });
  }
  const admittedUID = admission?.admitted ? admission.effectiveUID : hostedDeveloperTreeOwnerUID;
  const pinned = admission?.admitted ? admission.toolchain : null;

  const describe = async (label, pathArgument, pinnedDescriptor) => {
    let described;
    try {
      described = await attestedToolDescriptor(pathArgument, developerDirectory, admittedUID);
    } catch (error) {
      if (admission && !admission.admitted && /accepted reviewed owner/u.test(error?.cause?.message ?? "")) {
        throw new Error(`clean release toolchain capture remains root-only: ${admission.reason} (${label})`, { cause: error });
      }
      throw error;
    }
    if (pinned) requirePinnedDescriptor(label, described, pinnedDescriptor);
    return described;
  };

  const toolPaths = {};
  for (const name of developerToolNames) {
    const selected = await run("/usr/bin/xcrun", ["-f", name]);
    if (!selected.startsWith("/") || selected.includes("\n")) throw new Error(`invalid ${name} path`);
    toolPaths[name] = await realpath(selected);
  }
  const sdkSettingsPath = join(canonicalDeclaredSDK, "SDKSettings.json");
  const sdkSystemVersionPath = join(canonicalDeclaredSDK, "System/Library/CoreServices/SystemVersion.plist");
  if (pinned) {
    if (canonicalDeclaredSDK !== pinned.sdk.path) throw new Error("selected SDK path does not match the active hosted toolchain pin");
    for (const name of developerToolNames) {
      if (toolPaths[name] !== pinned.tools[name].path) throw new Error(`tool ${name} path does not match the active hosted toolchain pin`);
    }
    await attestDeveloperTreeChain(
      developerDirectory,
      [...Object.values(toolPaths), sdkSettingsPath, sdkSystemVersionPath],
      admittedUID
    );
  }

  const tools = {};
  for (const name of developerToolNames) {
    tools[name] = await describe(`tool ${name}`, toolPaths[name], pinned?.tools[name]);
  }
  for (const [name, path] of Object.entries(systemToolPaths)) {
    // System tools stay exact root-owned /usr/bin paths: no admission applies
    // outside the developer tree, so the accepted owner set is root alone.
    tools[name] = await attestedToolDescriptor(path, developerDirectory, null);
    if (tools[name].path !== path) throw new Error(`system tool ${name} is not the exact /usr/bin executable`);
    if (pinned) requirePinnedDescriptor(`system tool ${name}`, tools[name], pinned.tools[name]);
  }
  const sdk = {
    path: canonicalDeclaredSDK,
    version: await run("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-version"]),
    buildVersion: await run("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-build-version"]),
    settings: await describe("SDK settings", sdkSettingsPath, pinned?.sdk.settings),
    systemVersion: await describe("SDK system version", sdkSystemVersionPath, pinned?.sdk.systemVersion)
  };
  // Every admitted executable matched its pinned bytes before it is executed
  // for its version string.
  const inventory = {
    schemaVersion: 6,
    architecture: await run("/usr/bin/uname", ["-m"]),
    operatingSystem: {
      productVersion: await run("/usr/bin/sw_vers", ["-productVersion"]),
      buildVersion: await run("/usr/bin/sw_vers", ["-buildVersion"])
    },
    developerDirectory,
    sdk,
    versions: {
      swiftc: await run(tools.swiftc.path, ["--version"]),
      swiftFrontend: await run(tools["swift-frontend"].path, ["--version"]),
      swiftBuild: await run(tools["swift-build"].path, ["--version"]),
      clang: await run(tools.clang.path, ["--version"]),
      ld: await run(tools.ld.path, ["-v"]),
      dsymutil: await run(tools.dsymutil.path, ["--version"])
    },
    tools,
    build: buildControls()
  };
  validateToolchainInventory(inventory);
  if (pinned && JSON.stringify(inventory) !== JSON.stringify(pinned)) {
    throw new Error("the freshly captured hosted toolchain inventory does not equal the active pinned inventory");
  }
  return inventory;
}

export async function writeToolchainInventory(destinationArgument, inventory) {
  validateToolchainInventory(inventory);
  const destination = resolve(destinationArgument);
  const payload = `${JSON.stringify(inventory, null, 2)}\n`;
  if (Buffer.byteLength(payload) > maximumInventoryBytes) throw new Error("toolchain inventory exceeds its byte limit");
  const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.tmp`);
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(payload, "utf8");
    await handle.sync();
    await handle.chmod(0o644);
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function verifyToolchainInventory(pathArgument, options = {}, probes = defaultProbes) {
  const path = resolve(pathArgument);
  let input;
  try {
    input = await readAttestedRegularFile(path, {
      label: "toolchain inventory",
      maximumBytes: maximumInventoryBytes
    });
  } catch (error) {
    throw new Error(
      "toolchain inventory is not one bounded owner-controlled regular file",
      { cause: error }
    );
  }
  if ((input.metadata.mode & 0o777n) !== 0o644n) {
    throw new Error("toolchain inventory is not one bounded owner-controlled regular file");
  }
  const encoded = input.bytes.toString("utf8");
  const recorded = validateToolchainInventory(JSON.parse(encoded));
  if (encoded !== `${JSON.stringify(recorded, null, 2)}\n`) throw new Error("toolchain inventory is not canonical JSON");
  const current = await captureToolchainInventory(false, options, probes);
  compareToolchainInventories(recorded, current);
  process.stdout.write(`Verified release toolchain: ${current.versions.swiftc.split("\n")[0]}; macOS ${current.operatingSystem.productVersion} (${current.operatingSystem.buildVersion}); SDK ${current.sdk.version} (${current.sdk.buildVersion}).\n`);
}

// CLI: `create <inventory.json> [pin.json]` and `verify <inventory.json> [pin.json]`.
// The optional pin argument exists so release scripts state the literal tracked
// pin explicitly; it must resolve to exactly that file, and when omitted the
// same tracked file is used. No environment variable can select a pin.
// The CLI runs as an ordinary promise rather than a top-level await so the
// pin module (which imports this module) can be loaded on demand without an
// import-cycle deadlock.
async function main() {
  const [operation, destination, pinArgument, ...extra] = process.argv.slice(2);
  const pinPath = pinArgument === undefined ? trackedHostedToolchainPinPath : resolve(pinArgument);
  if (extra.length !== 0 || !destination) {
    throw new Error("usage: toolchain-inventory.mjs <create|verify> <inventory.json> [Config/HostedMacOSToolchainPin.json]");
  }
  if (pinPath !== trackedHostedToolchainPinPath) {
    throw new Error("toolchain-inventory.mjs accepts only the literal tracked Config/HostedMacOSToolchainPin.json");
  }
  if (operation === "create") {
    await writeToolchainInventory(destination, await captureToolchainInventory(true, { hostedToolchainPin: pinPath }));
  } else if (operation === "verify") {
    await verifyToolchainInventory(destination, { hostedToolchainPin: pinPath });
  } else {
    throw new Error("usage: toolchain-inventory.mjs <create|verify> <inventory.json> [Config/HostedMacOSToolchainPin.json]");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    process.stderr.write(`${error?.stack ?? error}\n`);
    if (error?.cause) process.stderr.write(`caused by: ${error.cause?.stack ?? error.cause}\n`);
    process.exitCode = 1;
  });
}
