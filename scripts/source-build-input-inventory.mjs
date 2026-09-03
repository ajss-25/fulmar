import { constants, createReadStream } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  unlink
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const buildInputRoots = Object.freeze([
  "Package.swift",
  "Makefile",
  ".gitattributes",
  ".gitignore",
  ".github",
  "LICENSE",
  "README.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "SUPPORT.md",
  "docs",
  "Config",
  "Sources",
  "Tools",
  "Tests",
  "scripts",
  "Resources",
  "VendorRuntime.inventory.json",
  "VendorRuntime/package.json",
  "VendorRuntime/package-lock.json"
]);

const limits = Object.freeze({
  maximumEntries: 20_000,
  maximumDepth: 32,
  maximumPathBytes: 4_096,
  maximumFileBytes: 64 * 1_024 * 1_024,
  maximumAggregateBytes: 512 * 1_024 * 1_024,
  maximumInventoryBytes: 32 * 1_024 * 1_024
});

function compareNames(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function normalizedIdentity(relativePath) {
  return relativePath.normalize("NFC").toLocaleLowerCase("en-US");
}

function validateRelativePath(relativePath, depth) {
  if (!relativePath || relativePath.startsWith("/") || relativePath.includes("\\")
      || relativePath.split("/").some((part) => !part || part === "." || part === "..")
      || /[\u0000-\u001f\u007f]/u.test(relativePath)
      || Buffer.byteLength(relativePath, "utf8") > limits.maximumPathBytes
      || depth > limits.maximumDepth) {
    throw new Error(`unsafe or unbounded build-input path: ${relativePath}`);
  }
}

function validateOwnerAndMode(stats, relativePath) {
  const effectiveUID = typeof process.geteuid === "function" ? process.geteuid() : stats.uid;
  if (stats.uid !== effectiveUID || (stats.mode & 0o022) !== 0) {
    throw new Error(`build input is not owner-controlled: ${relativePath}`);
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mode === right.mode
    && left.uid === right.uid && left.nlink === right.nlink;
}

async function hashRegularFile(absolutePath, relativePath, expected) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(absolutePath, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || !sameIdentity(before, expected)) {
      throw new Error(`build input changed identity before hashing: ${relativePath}`);
    }
    validateOwnerAndMode(before, relativePath);
    if (before.size < 0 || before.size > limits.maximumFileBytes) {
      throw new Error(`build input exceeds its per-file limit: ${relativePath}`);
    }
    const hash = createHash("sha256");
    let bytes = 0;
    const stream = createReadStream(absolutePath, {
      fd: handle.fd,
      autoClose: false,
      start: 0,
      highWaterMark: 64 * 1_024
    });
    for await (const chunk of stream) {
      bytes += chunk.length;
      if (bytes > limits.maximumFileBytes) {
        stream.destroy();
        throw new Error(`build input grew beyond its per-file limit: ${relativePath}`);
      }
      hash.update(chunk);
    }
    const after = await handle.stat();
    if (!sameIdentity(before, after) || bytes !== before.size) {
      throw new Error(`build input changed while hashing: ${relativePath}`);
    }
    return { bytes, sha256: hash.digest("hex") };
  } finally {
    await handle.close();
  }
}

async function enumerateEntry(projectRoot, relativePath, depth, state) {
  validateRelativePath(relativePath, depth);
  const identity = normalizedIdentity(relativePath);
  if (state.identities.has(identity)) {
    throw new Error(`case- or normalization-colliding build-input path: ${relativePath}`);
  }
  state.identities.add(identity);
  state.count += 1;
  if (state.count > limits.maximumEntries) {
    throw new Error("build-input inventory exceeds its entry limit");
  }

  const absolutePath = join(projectRoot, relativePath);
  const details = await lstat(absolutePath);
  validateOwnerAndMode(details, relativePath);
  const mode = details.mode & 0o7777;
  if (details.isSymbolicLink()) {
    throw new Error(`symbolic links are not accepted as release build inputs: ${relativePath}`);
  }
  if (details.isDirectory()) {
    state.entries.push({ path: relativePath, type: "directory", mode });
    const before = details;
    const children = (await readdir(absolutePath)).sort(compareNames);
    for (const child of children) {
      await enumerateEntry(projectRoot, `${relativePath}/${child}`, depth + 1, state);
    }
    const after = await lstat(absolutePath);
    if (!after.isDirectory() || before.dev !== after.dev || before.ino !== after.ino
        || before.mode !== after.mode || before.uid !== after.uid) {
      throw new Error(`build-input directory changed while enumerating: ${relativePath}`);
    }
    return;
  }
  if (!details.isFile() || details.nlink !== 1) {
    throw new Error(`special or hard-linked build input is not accepted: ${relativePath}`);
  }
  const descriptor = await hashRegularFile(absolutePath, relativePath, details);
  state.aggregateBytes += descriptor.bytes;
  if (state.aggregateBytes > limits.maximumAggregateBytes) {
    throw new Error("build-input inventory exceeds its aggregate-byte limit");
  }
  state.entries.push({
    path: relativePath,
    type: "file",
    mode,
    bytes: descriptor.bytes,
    sha256: descriptor.sha256
  });
}

export async function createBuildInputInventory(projectRootArgument) {
  const projectRoot = resolve(projectRootArgument);
  const rootDetails = await lstat(projectRoot);
  if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink()) {
    throw new Error("project root must be a real directory");
  }
  const state = { entries: [], identities: new Set(), count: 0, aggregateBytes: 0 };
  for (const relativePath of buildInputRoots) {
    try {
      await enumerateEntry(projectRoot, relativePath, 1, state);
    } catch (error) {
      if (relativePath === "LICENSE" && error?.code === "ENOENT") continue;
      throw error;
    }
  }
  state.entries.sort((left, right) => compareNames(left.path, right.path));
  return {
    schemaVersion: 1,
    rootLabel: "LocalHarnessBuildInputs",
    algorithm: "sha256",
    inputRoots: [...buildInputRoots],
    totals: { entries: state.entries.length, fileBytes: state.aggregateBytes },
    entries: state.entries
  };
}

async function writeInventory(destinationArgument, inventory) {
  const destination = resolve(destinationArgument);
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${Date.now()}.tmp`);
  const payload = `${JSON.stringify(inventory, null, 2)}\n`;
  if (Buffer.byteLength(payload) > limits.maximumInventoryBytes) {
    throw new Error("build-input inventory document exceeds its size limit");
  }
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(payload, "utf8");
    await handle.sync();
    await handle.chmod(0o644);
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, destination);
    const directory = await open(dirname(destination), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function loadBoundedInventory(pathArgument) {
  const path = resolve(pathArgument);
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || details.size <= 0 || details.size > limits.maximumInventoryBytes) {
    throw new Error("build-input inventory must be a bounded regular file");
  }
  return JSON.parse(await readFile(path, "utf8"));
}

export async function verifyBuildInputInventory(projectRoot, inventoryPath) {
  const [expected, actual] = await Promise.all([
    loadBoundedInventory(inventoryPath),
    createBuildInputInventory(projectRoot)
  ]);
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    throw new Error("release build inputs changed after the candidate was compiled");
  }
  return actual;
}

async function main() {
  const [command, projectRoot, inventoryPath] = process.argv.slice(2);
  if (!command || !projectRoot || !inventoryPath || !["create", "verify"].includes(command)) {
    throw new Error("usage: source-build-input-inventory.mjs <create|verify> <project-root> <inventory>");
  }
  if (command === "create") {
    const inventory = await createBuildInputInventory(projectRoot);
    await writeInventory(inventoryPath, inventory);
    process.stdout.write(`Captured ${inventory.totals.entries} release build inputs (${inventory.totals.fileBytes} bytes).\n`);
    return;
  }
  const inventory = await verifyBuildInputInventory(projectRoot, inventoryPath);
  process.stdout.write(`Verified ${inventory.totals.entries} unchanged release build inputs.\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
