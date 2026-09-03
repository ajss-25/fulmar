import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const supportedPythonDistributions = Object.freeze({
  "Darwin:arm64": Object.freeze({
    url: "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.12.3%2B20240415-aarch64-apple-darwin-install_only.tar.gz",
    bytes: 16_814_925,
    sha256: "ccc40e5af329ef2af81350db2a88bbd6c17b56676e82d62048c15d548401519e",
    archiveEntries: 2_176,
    executable: "python/bin/python3.12",
    executableSHA256: "02f1498c0eff1936ab91de7c411abf49c6f918e11628445cc6502da94d5aa15b"
  }),
  "Linux:x86_64": Object.freeze({
    url: "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.12.3%2B20240415-x86_64-unknown-linux-gnu-install_only.tar.gz",
    bytes: 67_368_051,
    sha256: "a73ba777b5d55ca89edef709e6b8521e3f3d4289581f174c8699adfb608d09d6",
    archiveEntries: 5_191,
    executable: "python/bin/python3.12",
    executableSHA256: "4933b6c4a8521fb3aa93856701e30b3ac2626d3c47ceb22965a3b0b422e85b44"
  })
});

function fail(message) {
  throw new Error(`Semgrep toolchain lock: ${message}`);
}

function plainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected, label) {
  if (!plainRecord(value)) fail(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail(`${label} has unsupported fields`);
}

function safeRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 200
    && !isAbsolute(value) && !value.includes("\\") && !value.includes("\0")
    && !/[\u0000-\u001f\u007f]/u.test(value)
    && !value.split("/").some((part) => part.length === 0 || part === "." || part === "..");
}

async function boundedRegularFile(path, maximumBytes, label) {
  const metadata = await lstat(path).catch(() => null);
  if (!metadata?.isFile() || metadata.isSymbolicLink()) fail(`${label} is missing, linked, or not regular`);
  if ((metadata.mode & 0o022) !== 0) fail(`${label} is group/world writable`);
  if (metadata.size < 1 || metadata.size > maximumBytes) fail(`${label} has an unsafe size`);
  return readFile(path);
}

function exactSHA256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) fail(`${label} is invalid`);
  return value;
}

function validatePythonDistribution(value, platform) {
  exactKeys(value, ["url", "bytes", "sha256", "archiveEntries", "executable", "executableSHA256"], `${platform} Python distribution`);
  const expected = supportedPythonDistributions[platform];
  if (!expected || value.url !== expected.url) fail(`${platform} Python distribution URL is unsupported`);
  if (!Number.isSafeInteger(value.bytes) || value.bytes < 1024 * 1024 || value.bytes > 256 * 1024 * 1024) {
    fail(`${platform} Python distribution size is unsafe`);
  }
  if (!Number.isSafeInteger(value.archiveEntries) || value.archiveEntries < 100 || value.archiveEntries > 20_000) {
    fail(`${platform} Python distribution entry count is unsafe`);
  }
  exactSHA256(value.sha256, `${platform} Python archive digest`);
  exactSHA256(value.executableSHA256, `${platform} Python executable digest`);
  if (value.executable !== "python/bin/python3.12") fail(`${platform} Python executable path is unsupported`);
  if (value.bytes !== expected.bytes || value.sha256 !== expected.sha256
      || value.archiveEntries !== expected.archiveEntries
      || value.executable !== expected.executable
      || value.executableSHA256 !== expected.executableSHA256) {
    fail(`${platform} Python distribution identity changed`);
  }
  return value;
}

function parseRequirements(source, engineVersion) {
  const logical = [];
  let pending = "";
  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    pending += `${pending.length > 0 ? " " : ""}${line.endsWith("\\") ? line.slice(0, -1).trim() : line}`;
    if (!line.endsWith("\\")) {
      logical.push(pending);
      pending = "";
    }
  }
  if (pending.length > 0) fail("requirements end in an incomplete continuation");
  if (logical.length < 2 || logical.length > 200) fail("requirements have an implausible package count");

  const names = new Set();
  let semgrepCount = 0;
  for (const line of logical) {
    if (line.includes(" @ ") || line.includes("://") || line.includes(";") || line.includes("--index")) {
      fail("requirements contain a URL, marker, or index override");
    }
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+)((?:\s+--hash=sha256:[a-f0-9]{64})+)$/.exec(line);
    if (!match) fail("every requirement must use one exact version and SHA-256 hashes only");
    const normalized = match[1].toLowerCase().replace(/[-_.]+/gu, "-");
    if (names.has(normalized)) fail(`duplicate requirement ${normalized}`);
    names.add(normalized);
    const hashes = [...match[3].matchAll(/--hash=sha256:([a-f0-9]{64})/g)].map((item) => item[1]);
    if (hashes.length === 0 || new Set(hashes).size !== hashes.length) fail(`invalid hashes for ${normalized}`);
    if (normalized === "semgrep") {
      semgrepCount += 1;
      if (match[2] !== engineVersion) fail("Semgrep requirement does not match the manifest version");
    }
  }
  if (semgrepCount !== 1) fail("requirements must contain exactly one Semgrep package");
  return logical.length;
}

async function main() {
  const [command, rootArgument, platformArgument, archiveArgument] = process.argv.slice(2);
  if (!new Set(["verify", "select", "verify-python-archive"]).has(command) || !rootArgument) {
    fail("usage: verify-semgrep-toolchain-lock.mjs <verify|select|verify-python-archive> <project-root> [Darwin:arm64|Linux:x86_64] [archive]");
  }
  const projectRoot = await realpath(resolve(rootArgument));
  const manifestPath = join(projectRoot, "Config", "SemgrepToolchain.json");
  const manifestBytes = await boundedRegularFile(manifestPath, 32 * 1024, "manifest");
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    fail("manifest is not valid JSON");
  }
  exactKeys(manifest, ["schemaVersion", "engineVersion", "pythonVersion", "pipVersion", "resolverVersion", "resolutionCutoff", "indexURL", "requirementsInput", "lockGeneration", "pythonDistributions", "locks"], "manifest");
  if (manifest.schemaVersion !== 1 || manifest.engineVersion !== "1.135.0") fail("unsupported manifest identity");
  if (manifest.pythonVersion !== "3.12.3" || manifest.pipVersion !== "24.0") fail("unsupported Python or pip version");
  if (manifest.resolverVersion !== "0.11.8" || manifest.resolutionCutoff !== "2026-09-03T00:00:00Z") fail("unsupported resolver identity or package cutoff");
  if (manifest.indexURL !== "https://pypi.org/simple") fail("only the public PyPI simple index is permitted");
  exactKeys(manifest.requirementsInput, ["path", "sha256"], "requirements input");
  if (manifest.requirementsInput.path !== "Config/SemgrepRequirements.in") fail("requirements input path is unsupported");
  exactSHA256(manifest.requirementsInput.sha256, "requirements input digest");
  const requirementsBytes = await boundedRegularFile(
    join(projectRoot, manifest.requirementsInput.path), 1024, "requirements input"
  );
  if (createHash("sha256").update(requirementsBytes).digest("hex") !== manifest.requirementsInput.sha256
      || requirementsBytes.toString("utf8") !== `semgrep==${manifest.engineVersion}\nsetuptools==80.9.0\n`) {
    fail("requirements input bytes changed");
  }
  exactKeys(manifest.lockGeneration, ["platform", "resolverExecutableSHA256", "pythonExecutableSHA256"], "lock generation");
  if (manifest.lockGeneration.platform !== "Darwin:arm64"
      || manifest.lockGeneration.resolverExecutableSHA256 !== "51f0ae3c531a124727fa39e16e8599f2e371e427822a4aa92ebf667b52548b43"
      || manifest.lockGeneration.pythonExecutableSHA256 !== supportedPythonDistributions["Darwin:arm64"].executableSHA256) {
    fail("lock generator identity changed");
  }
  exactKeys(manifest.pythonDistributions, ["Darwin:arm64", "Linux:x86_64"], "Python distributions");
  for (const platform of ["Darwin:arm64", "Linux:x86_64"]) {
    validatePythonDistribution(manifest.pythonDistributions[platform], platform);
  }
  exactKeys(manifest.locks, ["Darwin:arm64", "Linux:x86_64"], "platform locks");

  const results = new Map();
  for (const platform of ["Darwin:arm64", "Linux:x86_64"]) {
    const descriptor = manifest.locks[platform];
    exactKeys(descriptor, ["path", "sha256"], `${platform} lock`);
    if (!safeRelativePath(descriptor.path) || !descriptor.path.startsWith("Config/")) fail(`${platform} lock path is unsafe`);
    if (!/^[a-f0-9]{64}$/.test(descriptor.sha256)) fail(`${platform} lock digest is invalid`);
    const absolute = resolve(projectRoot, descriptor.path);
    const rel = relative(projectRoot, absolute);
    if (rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) fail(`${platform} lock escapes the project`);
    const bytes = await boundedRegularFile(absolute, 1024 * 1024, `${platform} requirements`);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== descriptor.sha256) fail(`${platform} requirements digest changed`);
    const packages = parseRequirements(bytes.toString("utf8"), manifest.engineVersion);
    results.set(platform, { path: descriptor.path, packages });
  }

  if (command === "select") {
    if (!results.has(platformArgument)) fail("the requested host platform is unsupported");
    const python = manifest.pythonDistributions[platformArgument];
    process.stdout.write([
      results.get(platformArgument).path,
      python.url,
      String(python.bytes),
      python.sha256,
      String(python.archiveEntries),
      python.executable,
      python.executableSHA256
    ].join("\t") + "\n");
    return;
  }
  if (command === "verify-python-archive") {
    if (!results.has(platformArgument) || !archiveArgument || process.argv.length !== 6) {
      fail("Python archive verification requires one reviewed platform and archive path");
    }
    const archive = resolve(archiveArgument);
    const bytes = await boundedRegularFile(archive, 256 * 1024 * 1024, "Python archive");
    const expected = manifest.pythonDistributions[platformArgument];
    if (bytes.length !== expected.bytes
        || createHash("sha256").update(bytes).digest("hex") !== expected.sha256) {
      fail("Python archive does not match the reviewed bytes");
    }
    process.stdout.write(`Verified exact ${platformArgument} Python ${manifest.pythonVersion} archive.\n`);
    return;
  }
  process.stdout.write(`Verified hash-locked Semgrep ${manifest.engineVersion} closures for macOS arm64 and Linux x86_64 (${results.get("Darwin:arm64").packages} packages each).\n`);
}

await main();
