import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

const [templateArgument, runtimeArgument, overridesArgument, destinationArgument] = process.argv.slice(2);
if (!templateArgument || !runtimeArgument || !overridesArgument || !destinationArgument) {
  throw new Error("usage: generate-third-party-notices.mjs <template.md> <bundled-runtime-root> <override-config.json> <output.md>");
}

const MAXIMUM_TEXT_BYTES = 8 * 1024 * 1024;
const MAXIMUM_LOCK_BYTES = 64 * 1024 * 1024;
const LICENSE_NAME = /^(?:licen[cs]e|copying|notice|copyright|patents|authors)(?:$|[._-])/iu;
const SHA256 = /^[a-f0-9]{64}$/u;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSafeRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024
      || isAbsolute(value) || value.includes("\\") || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} must be one bounded POSIX relative path`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw new Error(`${label} contains an unsafe path segment`);
  }
  return value;
}

async function boundedRegularBytes(path, maximumBytes, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) {
      throw new Error(`${label} is not one bounded, unlinked regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || BigInt(bytes.byteLength) !== after.size) {
      throw new Error(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function boundedText(path, maximumBytes, label, requireCanonicalLines = true) {
  const bytes = await boundedRegularBytes(path, maximumBytes, label);
  const text = bytes.toString("utf8");
  if (text.includes("\0") || (requireCanonicalLines && text.includes("\r"))
      || Buffer.from(text, "utf8").compare(bytes) !== 0) {
    throw new Error(`${label} is not canonical UTF-8 text`);
  }
  return { bytes, text };
}

function parseObject(text, label) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  return value;
}

async function requireCanonicalDirectory(path, label) {
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink()) throw new Error(`${label} is not a real directory`);
  if (await realpath(path) !== path) throw new Error(`${label} must not traverse aliases or symbolic links`);
}

function packageRuntimePath(lockPath) {
  return lockPath === "node_modules/@deepseek-ai/dsh" ? "dsh" : `dsh/${lockPath}`;
}

function escaped(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ").replaceAll("\r", " ");
}

function formatMaterials(materials) {
  return materials.map(({ path, sha256: digest, origin, upstreamSHA256 }) => {
    const provenance = origin === undefined
      ? ""
      : `; upstream \`${escaped(origin)}\` (raw \`sha256:${upstreamSHA256}\`; canonicalized by appending one terminal LF)`;
    return `\`${escaped(path)}\` (\`sha256:${digest}\`${provenance})`;
  }).join("<br>");
}

const runtimeRoot = resolve(runtimeArgument);
await requireCanonicalDirectory(runtimeRoot, "bundled runtime root");

const templatePath = resolve(templateArgument);
const overridesPath = resolve(overridesArgument);
const destination = resolve(destinationArgument);
await requireCanonicalDirectory(dirname(overridesPath), "licence override config directory");
const projectRoot = resolve(dirname(overridesPath), "..");
await requireCanonicalDirectory(projectRoot, "project root inferred from licence override config");
const { text: templateText } = await boundedText(templatePath, MAXIMUM_TEXT_BYTES, "notice template");
const { bytes: overridesBytes, text: overridesText } = await boundedText(overridesPath, MAXIMUM_TEXT_BYTES, "licence override config");
const overridesDocument = parseObject(overridesText, "licence override config");
if (overridesDocument.schemaVersion !== 1 || !Array.isArray(overridesDocument.overrides)) {
  throw new Error("licence override config has an unsupported schema");
}

const overrides = new Map();
for (const entry of overridesDocument.overrides) {
  const packagePath = assertSafeRelativePath(entry?.packagePath, "override packagePath");
  if (!packagePath.startsWith("node_modules/") || overrides.has(packagePath)) {
    throw new Error(`licence override has a duplicate or non-package path: ${packagePath}`);
  }
  if (typeof entry.reason !== "string" || entry.reason.trim() !== entry.reason
      || entry.reason.length < 16 || entry.reason.length > 512 || /[\0\r\n]/u.test(entry.reason)) {
    throw new Error(`licence override has an invalid reason: ${packagePath}`);
  }
  if (!Array.isArray(entry.materials) || entry.materials.length === 0 || entry.materials.length > 8) {
    throw new Error(`licence override must name one to eight materials: ${packagePath}`);
  }
  const seenMaterials = new Set();
  const materials = entry.materials.map((material) => {
    const hasRuntimePath = material?.path !== undefined;
    const hasSourcePath = material?.sourcePath !== undefined;
    if (hasRuntimePath === hasSourcePath) {
      throw new Error(`licence override material must name exactly one runtime path or tracked source path: ${packagePath}`);
    }
    const path = assertSafeRelativePath(
      hasRuntimePath ? material.path : material.sourcePath,
      `override material for ${packagePath}`
    );
    if (hasSourcePath && !path.startsWith("Resources/ThirdPartyLicenses/")) {
      throw new Error(`tracked licence material must remain under Resources/ThirdPartyLicenses: ${packagePath}`);
    }
    let origin;
    if (hasSourcePath) {
      if (typeof material.origin !== "string" || material.origin.length < 16 || material.origin.length > 1024
          || /[\0\r\n]/u.test(material.origin)) {
        throw new Error(`tracked licence material has invalid upstream provenance: ${packagePath}`);
      }
      let parsedOrigin;
      try { parsedOrigin = new URL(material.origin); }
      catch { throw new Error(`tracked licence material has invalid upstream provenance: ${packagePath}`); }
      if (parsedOrigin.protocol !== "https:" || parsedOrigin.username || parsedOrigin.password
          || parsedOrigin.search || parsedOrigin.hash) {
        throw new Error(`tracked licence material requires one clean HTTPS upstream provenance URL: ${packagePath}`);
      }
      origin = parsedOrigin.href;
    } else if (material.origin !== undefined || material.sourcePath !== undefined) {
      throw new Error(`runtime licence material cannot declare source provenance fields: ${packagePath}`);
    }
    let upstreamSHA256;
    let normalization;
    if (hasSourcePath) {
      upstreamSHA256 = material.upstreamSHA256;
      normalization = material.normalization;
      if (!SHA256.test(upstreamSHA256 ?? "") || normalization !== "append-terminal-lf-v1") {
        throw new Error(`tracked licence material requires its exact raw upstream SHA-256 and reviewed normalization: ${packagePath}`);
      }
    } else if (material.upstreamSHA256 !== undefined || material.normalization !== undefined) {
      throw new Error(`runtime licence material cannot declare source normalization fields: ${packagePath}`);
    }
    const identity = `${hasSourcePath ? "source" : "runtime"}:${path}`;
    if (!SHA256.test(material?.sha256 ?? "") || seenMaterials.has(identity)) {
      throw new Error(`licence override has a duplicate material or invalid SHA-256: ${packagePath}`);
    }
    seenMaterials.add(identity);
    return {
      kind: hasSourcePath ? "source" : "runtime",
      path,
      origin,
      upstreamSHA256,
      normalization,
      sha256: material.sha256
    };
  });
  overrides.set(packagePath, { reason: entry.reason, materials });
}

const lockPath = join(runtimeRoot, "package-lock.json");
const { bytes: lockBytes, text: lockText } = await boundedText(lockPath, MAXIMUM_LOCK_BYTES, "bundled package lock");
const lock = parseObject(lockText, "bundled package lock");
if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
  throw new Error("bundled package lock has an unsupported schema");
}

const rows = [];
const usedOverrides = new Set();
const trackedSourceMaterials = new Map();
let omittedOptionalPackages = 0;
let materialCount = 0;

for (const [lockPackagePath, locked] of Object.entries(lock.packages).sort(([left], [right]) => left.localeCompare(right))) {
  if (!lockPackagePath) continue;
  assertSafeRelativePath(lockPackagePath, "lockfile package path");
  if (!lockPackagePath.startsWith("node_modules/") || !locked || typeof locked !== "object" || Array.isArray(locked)
      || typeof locked.version !== "string" || locked.version.length === 0 || typeof locked.license !== "string"
      || locked.license.length === 0) {
    throw new Error(`dependency has incomplete notice metadata: ${lockPackagePath}`);
  }

  const runtimeRelative = packageRuntimePath(lockPackagePath);
  const packageDirectory = join(runtimeRoot, ...runtimeRelative.split("/"));
  let directoryDetails;
  try {
    directoryDetails = await lstat(packageDirectory);
  } catch (error) {
    if (error?.code === "ENOENT" && locked.optional === true) {
      omittedOptionalPackages += 1;
      continue;
    }
    throw new Error(`required bundled package is missing: ${lockPackagePath}`);
  }
  if (!directoryDetails.isDirectory() || directoryDetails.isSymbolicLink() || await realpath(packageDirectory) !== packageDirectory) {
    throw new Error(`bundled package is not a real canonical directory: ${lockPackagePath}`);
  }

  const packageJSONPath = join(packageDirectory, "package.json");
  const { text: packageText } = await boundedText(
    packageJSONPath,
    MAXIMUM_TEXT_BYTES,
    `package metadata for ${lockPackagePath}`,
    false
  );
  const installed = parseObject(packageText, `package metadata for ${lockPackagePath}`);
  if (typeof installed.name !== "string" || installed.name.length === 0
      || installed.version !== locked.version || installed.license !== locked.license) {
    throw new Error(`installed package identity or licence drifted from the lockfile: ${lockPackagePath}`);
  }

  const firstListing = (await readdir(packageDirectory, { withFileTypes: true }))
    .filter((entry) => LICENSE_NAME.test(entry.name))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));
  let materials = [];
  if (firstListing.length > 0) {
    if (overrides.has(lockPackagePath)) throw new Error(`stale licence override is no longer required: ${lockPackagePath}`);
    for (const name of firstListing) {
      const materialPath = join(packageDirectory, name);
      const bytes = await boundedRegularBytes(materialPath, MAXIMUM_TEXT_BYTES, `licence material for ${lockPackagePath}`);
      materials.push({ path: `${runtimeRelative}/${name}`, sha256: sha256(bytes) });
    }
    const secondListing = (await readdir(packageDirectory, { withFileTypes: true }))
      .filter((entry) => LICENSE_NAME.test(entry.name))
      .map((entry) => entry.name)
      .sort((left, right) => left.localeCompare(right));
    if (firstListing.join("\0") !== secondListing.join("\0")) {
      throw new Error(`licence material topology changed while it was being inventoried: ${lockPackagePath}`);
    }
  } else {
    const override = overrides.get(lockPackagePath);
    if (!override) throw new Error(`bundled package has no adjacent licence material or reviewed override: ${lockPackagePath}`);
    usedOverrides.add(lockPackagePath);
    materials = [];
    for (const material of override.materials) {
      const root = material.kind === "source" ? projectRoot : runtimeRoot;
      const absolute = join(root, ...material.path.split("/"));
      if (material.kind === "source" && await realpath(absolute) !== absolute) {
        throw new Error(`tracked licence material must not traverse aliases or symbolic links: ${lockPackagePath} -> ${material.path}`);
      }
      const { bytes, text } = material.kind === "source"
        ? await boundedText(absolute, MAXIMUM_TEXT_BYTES, `tracked licence material for ${lockPackagePath}`)
        : { bytes: await boundedRegularBytes(absolute, MAXIMUM_TEXT_BYTES, `override material for ${lockPackagePath}`) };
      const digest = sha256(bytes);
      if (digest !== material.sha256) throw new Error(`override material SHA-256 drifted: ${lockPackagePath} -> ${material.path}`);
      if (material.kind === "source") {
        if (bytes.byteLength < 2 || bytes[bytes.byteLength - 1] !== 0x0a
            || sha256(bytes.subarray(0, bytes.byteLength - 1)) !== material.upstreamSHA256) {
          throw new Error(`tracked licence material no longer equals the exact upstream bytes plus one terminal LF: ${lockPackagePath} -> ${material.path}`);
        }
      }
      const displayPath = material.kind === "source" ? `source:${material.path}` : material.path;
      materials.push({
        path: displayPath,
        sha256: digest,
        origin: material.origin,
        upstreamSHA256: material.upstreamSHA256
      });
      if (material.kind === "source") {
        const existing = trackedSourceMaterials.get(material.path);
        if (existing !== undefined && (existing.sha256 !== digest || existing.origin !== material.origin
            || existing.upstreamSHA256 !== material.upstreamSHA256)) {
          throw new Error(`tracked licence material has conflicting provenance: ${material.path}`);
        }
        trackedSourceMaterials.set(material.path, {
          path: material.path,
          sha256: digest,
          origin: material.origin,
          upstreamSHA256: material.upstreamSHA256,
          text
        });
      }
    }
  }
  materialCount += materials.length;
  const reason = overrides.get(lockPackagePath)?.reason;
  rows.push(`| \`${escaped(runtimeRelative)}\` | \`${escaped(lockPackagePath)}\` | \`${escaped(installed.name)}\` | \`${escaped(installed.version)}\` | ${escaped(installed.license)} | ${formatMaterials(materials)} | ${reason ? escaped(reason) : "Adjacent upstream material"} |`);
}

for (const packagePath of overrides.keys()) {
  if (!usedOverrides.has(packagePath)) throw new Error(`licence override is stale or refers to an unshipped package: ${packagePath}`);
}

const nodeLicense = await boundedRegularBytes(join(runtimeRoot, "NODE_LICENSE"), MAXIMUM_TEXT_BYTES, "bundled Node licence");
const trackedLicenceText = [...trackedSourceMaterials.values()]
  .sort((left, right) => left.path.localeCompare(right.path))
  .flatMap((material) => [
    `### \`${material.path}\``,
    "",
    `Upstream: ${material.origin}`,
    `Exact raw upstream SHA-256: \`${material.upstreamSHA256}\``,
    `Exact tracked SHA-256: \`${material.sha256}\``,
    "Repository normalization: one terminal LF appended; all upstream text bytes are otherwise identical.",
    "",
    material.text.trimEnd(),
    ""
  ]);
const inventory = [
  "",
  "## Complete bundled npm dependency inventory",
  "",
  `This artifact-aware inventory contains ${rows.length} package paths actually present in the bundled runtime; ${omittedOptionalPackages} lockfile-only optional package paths are absent and intentionally omitted.`,
  `Pinned production lockfile SHA-256: \`${sha256(lockBytes)}\`. Reviewed override-config SHA-256: \`${sha256(overridesBytes)}\`.`,
  `It binds ${materialCount} npm licence/notice payloads by exact Runtime-relative path and SHA-256. The bundled Node.js consolidated licence is \`NODE_LICENSE\` (\`sha256:${sha256(nodeLicense)}\`).`,
  "",
  "> This is an auditable material inventory, not legal clearance. In particular, the bundled libvips payload declares LGPL components; source-offer, replacement/relinking, signing, and other distribution obligations require independent legal review before publication.",
  "",
  "| Runtime path | Lockfile path | Package | Version | Declared licence | Licence/notice material and SHA-256 | Basis |",
  "| --- | --- | --- | --- | --- | --- | --- |",
  ...rows,
  ...(trackedLicenceText.length === 0 ? [] : [
    "",
    "## Exact tracked upstream licence texts",
    "",
    "These terms are embedded from the digest-bound tracked source material named by the package row above.",
    "",
    ...trackedLicenceText
  ]),
  ""
].join("\n");

const output = `${templateText.trimEnd()}${inventory}`;
const destinationParent = dirname(destination);
await requireCanonicalDirectory(destinationParent, "notice destination directory");
try {
  const existing = await lstat(destination);
  if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1) {
    throw new Error("notice destination already exists with unsafe topology");
  }
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

const temporary = join(destinationParent, `.${basename(destination)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
let temporaryHandle;
try {
  temporaryHandle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
  await temporaryHandle.writeFile(output, "utf8");
  await temporaryHandle.sync();
  await temporaryHandle.close();
  temporaryHandle = undefined;
  await rename(temporary, destination);
} catch (error) {
  await temporaryHandle?.close();
  await unlink(temporary).catch(() => {});
  throw error;
}
