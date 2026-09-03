import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { createReadStream } from "node:fs";
import { chmod, lstat, open, readFile, realpath, rename, stat, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const safePath = "/usr/bin:/bin:/usr/sbin:/sbin";
const maximumInventoryBytes = 1024 * 1024;
const maximumToolBytes = 1024 * 1024 * 1024;
const toolNames = [
  "clang", "codesign", "ditto", "dsymutil", "ld", "sips", "strip",
  "swift", "swift-build", "swift-frontend", "swiftc", "xcrun"
];

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

export function validateToolchainInventory(value) {
  exactKeys(value, ["architecture", "build", "developerDirectory", "operatingSystem", "schemaVersion", "sdk", "tools", "versions"], "toolchain inventory");
  if (value.schemaVersion !== 3 || value.architecture !== "arm64") throw new Error("toolchain inventory identity is unsupported");
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
  exactKeys(value.build, ["automaticDSYMGeneration", "canonicalSourceSnapshot", "compilationDirectory", "configuration", "dsymObjectPrefixMaps", "dsymObjectPrependScratch", "frontendDebugInfo", "generatedPrefix", "jobs", "linkerReproducible", "relativeDebugMapObjects", "scratchPrefix", "serializedDebugPrefixMappings", "sourcePrefix", "swiftPMDebugInfoFormat"], "build");
  const expectedBuild = {
    configuration: "release",
    jobs: 1,
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
  };
  if (JSON.stringify(value.build) !== JSON.stringify(expectedBuild)) throw new Error("toolchain build controls changed");
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

async function descriptor(pathArgument) {
  const path = await realpath(pathArgument);
  const details = await stat(path);
  if (!details.isFile() || details.size <= 0 || details.size > maximumToolBytes
      || details.uid !== 0 || (details.mode & 0o022) !== 0) {
    throw new Error(`toolchain input is not a bounded root-owned regular file: ${path}`);
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return { path, bytes: details.size, sha256: hash.digest("hex") };
}

async function resolvedTool(name) {
  const selected = await command("/usr/bin/xcrun", ["-f", name]);
  if (!selected.startsWith("/") || selected.includes("\n")) throw new Error(`invalid ${name} path`);
  return descriptor(selected);
}

export async function captureToolchainInventory(requireCleanEnvironment = false) {
  if (requireCleanEnvironment && (process.env.PATH !== safePath || process.env.TMPDIR !== "/private/tmp/"
      || !process.env.SDKROOT || process.env.DEVELOPER_DIR)) {
    throw new Error("toolchain capture requires the exact clean release environment");
  }
  const selectedSDK = await command("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
  const declaredSDK = resolve(process.env.SDKROOT || selectedSDK);
  const canonicalDeclaredSDK = await realpath(declaredSDK);
  const canonicalSelectedSDK = await realpath(selectedSDK);
  if (canonicalDeclaredSDK !== canonicalSelectedSDK) throw new Error("selected SDK changed after the compatibility probe");
  const developerDirectory = await realpath(await command("/usr/bin/xcode-select", ["-p"]));
  const tools = {};
  for (const name of ["clang", "dsymutil", "ld", "swift", "swift-build", "swift-frontend", "swiftc"]) {
    tools[name] = await resolvedTool(name);
  }
  for (const [name, path] of Object.entries({
    codesign: "/usr/bin/codesign",
    ditto: "/usr/bin/ditto",
    sips: "/usr/bin/sips",
    strip: "/usr/bin/strip",
    xcrun: "/usr/bin/xcrun"
  })) tools[name] = await descriptor(path);
  return {
    schemaVersion: 3,
    architecture: await command("/usr/bin/uname", ["-m"]),
    operatingSystem: {
      productVersion: await command("/usr/bin/sw_vers", ["-productVersion"]),
      buildVersion: await command("/usr/bin/sw_vers", ["-buildVersion"])
    },
    developerDirectory,
    sdk: {
      path: canonicalDeclaredSDK,
      version: await command("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-version"]),
      buildVersion: await command("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-build-version"]),
      settings: await descriptor(join(canonicalDeclaredSDK, "SDKSettings.json")),
      systemVersion: await descriptor(join(canonicalDeclaredSDK, "System/Library/CoreServices/SystemVersion.plist"))
    },
    versions: {
      swiftc: await command(tools.swiftc.path, ["--version"]),
      swiftFrontend: await command(tools["swift-frontend"].path, ["--version"]),
      swiftBuild: await command(tools["swift-build"].path, ["--version"]),
      clang: await command(tools.clang.path, ["--version"]),
      ld: await command(tools.ld.path, ["-v"]),
      dsymutil: await command(tools.dsymutil.path, ["--version"])
    },
    tools,
    build: {
      configuration: "release",
      jobs: 1,
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

export async function verifyToolchainInventory(pathArgument) {
  const path = resolve(pathArgument);
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || details.size <= 0 || details.size > maximumInventoryBytes || (details.mode & 0o777) !== 0o644
      || details.uid !== process.getuid()) {
    throw new Error("toolchain inventory is not one bounded owner-controlled regular file");
  }
  const encoded = await readFile(path, "utf8");
  const recorded = validateToolchainInventory(JSON.parse(encoded));
  if (encoded !== `${JSON.stringify(recorded, null, 2)}\n`) throw new Error("toolchain inventory is not canonical JSON");
  const current = await captureToolchainInventory();
  compareToolchainInventories(recorded, current);
  process.stdout.write(`Verified release toolchain: ${current.versions.swiftc.split("\n")[0]}; macOS ${current.operatingSystem.productVersion} (${current.operatingSystem.buildVersion}); SDK ${current.sdk.version} (${current.sdk.buildVersion}).\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const [operation, destination] = process.argv.slice(2);
  if (operation === "create" && destination) {
    await writeToolchainInventory(destination, await captureToolchainInventory(true));
  } else if (operation === "verify" && destination) {
    await verifyToolchainInventory(destination);
  } else {
    throw new Error("usage: toolchain-inventory.mjs <create|verify> <inventory.json>");
  }
}
