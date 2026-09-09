import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { loadManifest as loadMaterialsManifest, renderBoundNoticeMaterials, verifyMaterials } from "./prepare-libvips-source-materials.mjs";

const USAGE = "usage: generate-third-party-notices.mjs <template.md> <bundled-runtime-root> <override-config.json> <output.md> [--rust-crate-materials <verified-crate-materials-directory>]";

// Explicit operands only: the verified Rust crate materials directory is named
// on the command line when the provenance record declares that binding, and is
// never inferred from the environment.
const positionalArguments = [];
const optionArguments = {};
const rawArguments = process.argv.slice(2);
for (let index = 0; index < rawArguments.length; index += 1) {
  const argument = rawArguments[index];
  if (argument === "--rust-crate-materials") {
    const value = rawArguments[index + 1];
    if (optionArguments.rustCrateMaterials !== undefined || value === undefined || value.length === 0 || value.startsWith("--")) throw new Error(USAGE);
    optionArguments.rustCrateMaterials = value;
    index += 1;
  } else if (argument.startsWith("--")) {
    throw new Error(USAGE);
  } else {
    positionalArguments.push(argument);
  }
}
const [templateArgument, runtimeArgument, overridesArgument, destinationArgument] = positionalArguments;
if (positionalArguments.length !== 4 || !templateArgument || !runtimeArgument || !overridesArgument || !destinationArgument) {
  throw new Error(USAGE);
}

const MAXIMUM_TEXT_BYTES = 8 * 1024 * 1024;
const MAXIMUM_LOCK_BYTES = 64 * 1024 * 1024;
const LICENSE_NAME = /^(?:licen[cs]e|copying|notice|copyright|patents|authors)(?:$|[._-])/iu;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const COMPONENT_NAME = /^[a-z0-9][a-z0-9._+-]{0,63}$/u;
const MAXIMUM_COMPONENT_NOTICES = 128;
const MAXIMUM_MATERIALS_PER_COMPONENT = 8;
const TRACKED_LICENCE_PREFIX = "Resources/ThirdPartyLicenses/";
const NORMALIZATION = "append-terminal-lf-v1";

function byCodePoint(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedString(value, minimum, maximum, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length < minimum || value.length > maximum
      || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} must be one bounded single-line string`);
  }
  return value;
}

function cleanHTTPSOrigin(value, label) {
  if (typeof value !== "string" || value.length < 16 || value.length > 1024 || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} has invalid upstream provenance`);
  }
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error(`${label} has invalid upstream provenance`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${label} requires one clean HTTPS upstream provenance URL`);
  }
  return parsed.href;
}

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
  let componentNotices;
  if (entry.componentNotices !== undefined) {
    const reference = entry.componentNotices;
    if (!reference || typeof reference !== "object" || Array.isArray(reference)
        || Object.keys(reference).sort(byCodePoint).join("\0") !== "component\0manifest") {
      throw new Error(`licence override component-notice reference must name exactly a manifest and a component: ${packagePath}`);
    }
    const manifest = assertSafeRelativePath(reference.manifest, `component-notice manifest for ${packagePath}`);
    if (!/^Config\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u.test(manifest)) {
      throw new Error(`component-notice manifest must be one tracked JSON document under Config: ${packagePath}`);
    }
    if (typeof reference.component !== "string" || !COMPONENT_NAME.test(reference.component)) {
      throw new Error(`component-notice reference names an invalid component: ${packagePath}`);
    }
    componentNotices = { manifest, component: reference.component };
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
  overrides.set(packagePath, { reason: entry.reason, materials, componentNotices });
}

// Reads one tracked source licence text and proves it equals the exact
// upstream bytes plus one terminal LF. Shared by package-level override
// materials and per-component binary notices so both obey one contract.
async function boundTrackedSourceText(material, label) {
  const absolute = join(projectRoot, ...material.path.split("/"));
  if (await realpath(absolute) !== absolute) {
    throw new Error(`tracked licence material must not traverse aliases or symbolic links: ${label} -> ${material.path}`);
  }
  const { bytes, text } = await boundedText(absolute, MAXIMUM_TEXT_BYTES, `tracked licence material for ${label}`);
  const digest = sha256(bytes);
  if (digest !== material.sha256) throw new Error(`override material SHA-256 drifted: ${label} -> ${material.path}`);
  if (bytes.byteLength < 2 || bytes[bytes.byteLength - 1] !== 0x0a
      || sha256(bytes.subarray(0, bytes.byteLength - 1)) !== material.upstreamSHA256) {
    throw new Error(`tracked licence material no longer equals the exact upstream bytes plus one terminal LF: ${label} -> ${material.path}`);
  }
  return { bytes, text, digest };
}

function recordTrackedSourceMaterial(registry, material, digest, text) {
  const existing = registry.get(material.path);
  if (existing !== undefined && (existing.sha256 !== digest || existing.origin !== material.origin
      || existing.upstreamSHA256 !== material.upstreamSHA256)) {
    throw new Error(`tracked licence material has conflicting provenance: ${material.path}`);
  }
  registry.set(material.path, {
    path: material.path,
    sha256: digest,
    origin: material.origin,
    upstreamSHA256: material.upstreamSHA256,
    text
  });
}

// Binds the exact per-component copyright/licence notices of one redistributed
// combined binary from a tracked provenance manifest. Every component named by
// the upstream licence manifest must be present exactly once, every versioned
// component must map to the exact pinned version, and every notice text must be
// a tracked file proven equal to the immutable upstream bytes plus one LF.
async function bindComponentNotices(lockPackagePath, reference, registry) {
  const manifestPath = join(projectRoot, ...reference.manifest.split("/"));
  if (await realpath(manifestPath) !== manifestPath) {
    throw new Error(`component-notice manifest must not traverse aliases or symbolic links: ${lockPackagePath}`);
  }
  const { bytes: manifestBytes, text: manifestText } = await boundedText(manifestPath, MAXIMUM_TEXT_BYTES, `component-notice manifest for ${lockPackagePath}`);
  const manifest = parseObject(manifestText, `component-notice manifest for ${lockPackagePath}`);
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.components)) {
    throw new Error(`component-notice manifest has an unsupported schema: ${lockPackagePath}`);
  }
  const matching = manifest.components.filter((component) => component?.id === reference.component);
  if (matching.length !== 1) {
    throw new Error(`component-notice manifest must describe the referenced component exactly once: ${lockPackagePath} -> ${reference.component}`);
  }
  const [component] = matching;
  if (component.lockfilePath !== lockPackagePath) {
    throw new Error(`component-notice manifest component does not describe this package: ${lockPackagePath} -> ${reference.component}`);
  }
  const versions = component.componentVersions;
  if (!versions || typeof versions !== "object" || Array.isArray(versions)
      || Object.values(versions).some((version) => typeof version !== "string" || version.length === 0)) {
    throw new Error(`component-notice manifest lacks exact component versions: ${lockPackagePath}`);
  }
  if (!Array.isArray(component.manifestLibraries) || component.manifestLibraries.length === 0
      || component.manifestLibraries.length > MAXIMUM_COMPONENT_NOTICES
      || component.manifestLibraries.some((name) => typeof name !== "string" || !COMPONENT_NAME.test(name))
      || new Set(component.manifestLibraries).size !== component.manifestLibraries.length) {
    throw new Error(`component-notice manifest must list the upstream licence-manifest libraries exactly once each: ${lockPackagePath}`);
  }
  const withoutVersion = component.manifestDiscrepancy?.librariesWithoutVersionKey;
  if (!Array.isArray(withoutVersion) || typeof component.manifestDiscrepancy?.resolution !== "string"
      || component.manifestDiscrepancy.resolution.length < 40) {
    throw new Error(`component-notice manifest must resolve the library/version discrepancy explicitly: ${lockPackagePath}`);
  }
  const notices = component.componentNotices;
  if (!Array.isArray(notices) || notices.length === 0 || notices.length > MAXIMUM_COMPONENT_NOTICES) {
    throw new Error(`component-notice manifest carries no bounded per-component notices: ${lockPackagePath}`);
  }

  const seenComponents = new Set();
  const seenVersionKeys = new Set();
  const seenPaths = new Set();
  const records = [];
  for (const notice of notices) {
    if (!notice || typeof notice !== "object" || Array.isArray(notice)) {
      throw new Error(`component notice is not an object: ${lockPackagePath}`);
    }
    const name = notice.component;
    if (typeof name !== "string" || !COMPONENT_NAME.test(name) || seenComponents.has(name)) {
      throw new Error(`component notice has a duplicate or invalid component name: ${lockPackagePath} -> ${String(name)}`);
    }
    seenComponents.add(name);
    if (!component.manifestLibraries.includes(name)) {
      throw new Error(`component notice names a component absent from the upstream licence manifest: ${lockPackagePath} -> ${name}`);
    }
    if (notice.versionKey === null) {
      if (notice.version !== null || !withoutVersion.includes(name)) {
        throw new Error(`component notice without a version key must be an explicitly resolved discrepancy: ${lockPackagePath} -> ${name}`);
      }
      boundedString(notice.note, 40, 1200, `component notice note for ${name}`);
    } else {
      if (typeof notice.versionKey !== "string" || !Object.hasOwn(versions, notice.versionKey) || seenVersionKeys.has(notice.versionKey)) {
        throw new Error(`component notice has a duplicate or unknown version key: ${lockPackagePath} -> ${name}`);
      }
      if (notice.version !== versions[notice.versionKey]) {
        throw new Error(`component notice version does not equal the exact pinned component version: ${lockPackagePath} -> ${name}`);
      }
      if (withoutVersion.includes(name)) {
        throw new Error(`component notice is listed as version-less but carries a version key: ${lockPackagePath} -> ${name}`);
      }
      seenVersionKeys.add(notice.versionKey);
      if (notice.note !== undefined) boundedString(notice.note, 40, 1200, `component notice note for ${name}`);
    }
    const manifestLicense = boundedString(notice.manifestLicense, 3, 200, `component notice licence declaration for ${name}`);
    const upstreamRepository = cleanHTTPSOrigin(notice.upstreamRepository, `component notice repository for ${name}`);
    if (typeof notice.upstreamRevision !== "string" || !COMMIT.test(notice.upstreamRevision)) {
      throw new Error(`component notice must pin one full upstream revision: ${lockPackagePath} -> ${name}`);
    }
    boundedString(notice.revisionEvidence, 16, 400, `component notice revision evidence for ${name}`);
    if (!Array.isArray(notice.materials) || notice.materials.length === 0 || notice.materials.length > MAXIMUM_MATERIALS_PER_COMPONENT) {
      throw new Error(`component notice must bind one to ${MAXIMUM_MATERIALS_PER_COMPONENT} materials: ${lockPackagePath} -> ${name}`);
    }
    const materials = [];
    for (const raw of notice.materials) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)
          || Object.keys(raw).sort(byCodePoint).join("\0") !== "archiveMember\0archiveSHA256\0describes\0normalization\0origin\0sha256\0sourcePath\0upstreamSHA256") {
        throw new Error(`component notice material has an unexpected shape: ${lockPackagePath} -> ${name}`);
      }
      const path = assertSafeRelativePath(raw.sourcePath, `component notice material for ${name}`);
      if (!path.startsWith(TRACKED_LICENCE_PREFIX) || seenPaths.has(path)) {
        throw new Error(`component notice material must be one unique tracked file under ${TRACKED_LICENCE_PREFIX}: ${lockPackagePath} -> ${name}`);
      }
      seenPaths.add(path);
      if (!SHA256.test(raw.sha256 ?? "") || !SHA256.test(raw.upstreamSHA256 ?? "") || !SHA256.test(raw.archiveSHA256 ?? "")
          || raw.normalization !== NORMALIZATION) {
        throw new Error(`component notice material requires exact raw, tracked and archive SHA-256 values and the reviewed normalization: ${lockPackagePath} -> ${name}`);
      }
      const material = {
        path,
        describes: boundedString(raw.describes, 8, 400, `component notice description for ${name}`),
        origin: cleanHTTPSOrigin(raw.origin, `component notice material for ${name}`),
        upstreamSHA256: raw.upstreamSHA256,
        sha256: raw.sha256,
        archiveMember: assertSafeRelativePath(raw.archiveMember, `component notice archive member for ${name}`),
        archiveSHA256: raw.archiveSHA256
      };
      const { text, digest } = await boundTrackedSourceText(material, `${lockPackagePath} component ${name}`);
      recordTrackedSourceMaterial(registry, material, digest, text);
      const packageLevel = trackedSourceMaterials.get(path);
      if (packageLevel !== undefined && (packageLevel.sha256 !== digest || packageLevel.origin !== material.origin
          || packageLevel.upstreamSHA256 !== material.upstreamSHA256)) {
        throw new Error(`tracked licence material has conflicting provenance: ${path}`);
      }
      materials.push({ ...material, text });
    }
    records.push({
      component: name,
      version: notice.version,
      manifestLicense,
      upstreamRepository,
      upstreamRevision: notice.upstreamRevision,
      materials
    });
  }
  const missing = component.manifestLibraries.filter((name) => !seenComponents.has(name));
  if (missing.length > 0) {
    throw new Error(`component notices are missing for upstream licence-manifest libraries: ${lockPackagePath} -> ${missing.sort(byCodePoint).join(", ")}`);
  }
  const unversioned = Object.keys(versions).filter((key) => !seenVersionKeys.has(key));
  if (unversioned.length > 0) {
    throw new Error(`component notices are missing for pinned component versions: ${lockPackagePath} -> ${unversioned.sort(byCodePoint).join(", ")}`);
  }
  records.sort((left, right) => byCodePoint(left.component, right.component));
  const deliveryMaterials = component.deliveryMaterials === undefined
    ? undefined
    : parseDeliveryMaterials(component.deliveryMaterials, lockPackagePath, records);
  return {
    lockPackagePath,
    manifestPath: reference.manifest,
    manifestSHA256: sha256(manifestBytes),
    componentId: reference.component,
    packageName: typeof component.packageName === "string" ? component.packageName : undefined,
    version: typeof component.version === "string" ? component.version : undefined,
    buildCommit: typeof component.upstream?.buildCommit === "string" ? component.upstream.buildCommit : undefined,
    records,
    deliveryMaterials
  };
}

// ---------------------------------------------------------------------------
// Delivery material bindings declared by the provenance record: the tracked
// corresponding-source and Rust crate manifests, the version-bound external
// notice material manifest, and the accompanying-documentation statements.
// Declaring them makes the verified Rust crate materials a required, explicit
// generator input; nothing here closes an obligation or asserts clearance.

const MANIFEST_PATH = /^Config\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u;
const DOCUMENT_PATH = /^docs\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md$/u;
const DIRECTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const MAXIMUM_STATEMENTS = 8;

function requireExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort(byCodePoint).join("\0") !== keys.join("\0")) {
    throw new Error(`${label} has an unexpected shape (expected exactly: ${keys.join(", ")})`);
  }
}

function parseDeliveryMaterials(raw, lockPackagePath, records) {
  const label = `delivery materials for ${lockPackagePath}`;
  requireExactKeys(raw, ["accompanyingDocumentation", "outputDirectoryName", "purpose", "rustCrateMaterials", "rustNoticeMaterials", "sourceMaterials"], label);
  boundedString(raw.purpose, 40, 1200, `${label} purpose`);
  if (!/not legal clearance/u.test(raw.purpose)) throw new Error(`${label} purpose must state that it is not legal clearance`);
  if (typeof raw.outputDirectoryName !== "string" || !DIRECTORY_NAME.test(raw.outputDirectoryName)) throw new Error(`${label} outputDirectoryName is invalid`);
  const manifests = {};
  for (const key of ["sourceMaterials", "rustCrateMaterials", "rustNoticeMaterials"]) {
    const path = assertSafeRelativePath(raw[key], `${label} ${key}`);
    if (!MANIFEST_PATH.test(path)) throw new Error(`${label} ${key} must be one tracked JSON document under Config`);
    manifests[key] = path;
  }
  if (new Set(Object.values(manifests)).size !== 3) throw new Error(`${label} must name three distinct manifests`);
  const documentation = raw.accompanyingDocumentation;
  requireExactKeys(documentation, ["clarifications", "path", "statements"], `${label} accompanyingDocumentation`);
  const documentPath = assertSafeRelativePath(documentation.path, `${label} accompanying documentation path`);
  if (!DOCUMENT_PATH.test(documentPath)) throw new Error(`${label} accompanying documentation must be one tracked Markdown document under docs`);
  const byComponent = new Map(records.map((record) => [record.component, record]));
  const ids = new Set();
  const statements = [];
  if (!Array.isArray(documentation.statements) || documentation.statements.length === 0 || documentation.statements.length > MAXIMUM_STATEMENTS) {
    throw new Error(`${label} must declare one to ${MAXIMUM_STATEMENTS} accompanying-documentation statements`);
  }
  for (const entry of documentation.statements) {
    requireExactKeys(entry, ["basis", "component", "id", "material", "statement"], `${label} statement`);
    const id = boundedString(entry.id, 3, 64, `${label} statement id`);
    if (!COMPONENT_NAME.test(id) || ids.has(id)) throw new Error(`${label} statement has a duplicate or invalid id: ${id}`);
    ids.add(id);
    const record = byComponent.get(entry.component);
    if (record === undefined) throw new Error(`${label} statement ${id} names a component without a bound notice: ${String(entry.component)}`);
    const material = record.materials.find((candidate) => candidate.path === entry.material);
    if (material === undefined) throw new Error(`${label} statement ${id} names a material that is not bound for component ${entry.component}: ${String(entry.material)}`);
    statements.push({
      id,
      component: record.component,
      version: record.version,
      material: { path: material.path, sha256: material.sha256, describes: material.describes },
      basis: boundedString(entry.basis, 16, 600, `${label} statement ${id} basis`),
      statement: boundedString(entry.statement, 16, 600, `${label} statement ${id} text`)
    });
  }
  const clarifications = [];
  if (!Array.isArray(documentation.clarifications) || documentation.clarifications.length > MAXIMUM_STATEMENTS) {
    throw new Error(`${label} clarifications must be a bounded array`);
  }
  for (const entry of documentation.clarifications) {
    requireExactKeys(entry, ["component", "id", "retainedTexts", "statement", "upstreamLabel"], `${label} clarification`);
    const id = boundedString(entry.id, 3, 64, `${label} clarification id`);
    if (!COMPONENT_NAME.test(id) || ids.has(id)) throw new Error(`${label} clarification has a duplicate or invalid id: ${id}`);
    ids.add(id);
    const record = byComponent.get(entry.component);
    if (record === undefined) throw new Error(`${label} clarification ${id} names a component without a bound notice: ${String(entry.component)}`);
    if (entry.upstreamLabel !== record.manifestLicense) throw new Error(`${label} clarification ${id} does not quote the upstream licence declaration exactly`);
    const bound = record.materials.map((material) => material.path).sort(byCodePoint);
    if (!Array.isArray(entry.retainedTexts) || [...entry.retainedTexts].sort(byCodePoint).join("\0") !== bound.join("\0")) {
      throw new Error(`${label} clarification ${id} must name exactly the retained texts bound for component ${record.component}`);
    }
    clarifications.push({
      id,
      component: record.component,
      version: record.version,
      upstreamLabel: record.manifestLicense,
      retainedTexts: record.materials.map((material) => ({ path: material.path, sha256: material.sha256, describes: material.describes })),
      statement: boundedString(entry.statement, 16, 600, `${label} clarification ${id} text`)
    });
  }
  return {
    purpose: raw.purpose,
    outputDirectoryName: raw.outputDirectoryName,
    ...manifests,
    documentation: { path: documentPath, statements, clarifications }
  };
}

// Blockquoted statements of one Markdown document: consecutive "> " lines are
// joined with single spaces so a wrapped statement is compared as one sentence.
function blockquotedStatements(text) {
  const statements = new Set();
  let current = [];
  for (const line of [...text.split("\n"), ""]) {
    if (line.startsWith(">")) {
      current.push(line.slice(1).trim());
    } else if (current.length > 0) {
      statements.add(current.filter((part) => part.length > 0).join(" "));
      current = [];
    }
  }
  return statements;
}

async function requireTrackedPath(relativePath, label) {
  const absolute = join(projectRoot, ...relativePath.split("/"));
  if (await realpath(absolute) !== absolute) throw new Error(`${label} must not traverse aliases or symbolic links: ${relativePath}`);
  return absolute;
}

async function bindDeliveryMaterials(section, directoryArgument) {
  const declared = section.deliveryMaterials;
  const label = `delivery materials for ${section.lockPackagePath}`;
  const crateManifestPath = await requireTrackedPath(declared.rustCrateMaterials, `${label} crate manifest`);
  const noticeManifestPath = await requireTrackedPath(declared.rustNoticeMaterials, `${label} notice-materials manifest`);
  const sourceManifestPath = await requireTrackedPath(declared.sourceMaterials, `${label} corresponding-source manifest`);
  const documentPath = await requireTrackedPath(declared.documentation.path, `${label} accompanying documentation`);
  const directory = resolve(directoryArgument);
  const verified = await verifyMaterials(crateManifestPath, directory, noticeManifestPath);
  if (verified.manifest.provenanceStatuses === undefined) throw new Error(`${label} rustCrateMaterials must name a rust-crate manifest`);
  const { binary } = verified.manifest;
  if (binary.packageName !== section.packageName || binary.version !== section.version || binary.buildCommit !== section.buildCommit) {
    throw new Error(`${label}: the crate manifest does not describe this component's package, version and build commit`);
  }
  if (verified.manifest.provenanceRecord !== section.manifestPath) {
    throw new Error(`${label}: the crate manifest names ${verified.manifest.provenanceRecord} as its provenance record, not ${section.manifestPath}`);
  }
  const source = await loadMaterialsManifest(sourceManifestPath);
  if (source.manifest.provenanceStatuses !== undefined) throw new Error(`${label} sourceMaterials must name the upstream corresponding-source manifest, not a crate manifest`);
  if (JSON.stringify(source.manifest.binary) !== JSON.stringify(binary)) {
    throw new Error(`${label}: the corresponding-source manifest and the crate manifest describe different binaries`);
  }
  const { bytes: documentBytes, text: documentText } = await boundedText(documentPath, MAXIMUM_TEXT_BYTES, `${label} accompanying documentation`);
  const quoted = blockquotedStatements(documentText);
  for (const statement of declared.documentation.statements) {
    if (!quoted.has(statement.statement)) {
      throw new Error(`${label}: accompanying documentation ${declared.documentation.path} does not carry the exact statement ${statement.id}`);
    }
  }
  return {
    section,
    declared,
    verified,
    directoryName: basename(directory),
    source: {
      path: declared.sourceMaterials,
      sha256: source.manifestSHA256,
      itemCount: source.manifest.items.length,
      totalBytes: source.manifest.totalBytes,
      outputDirectoryName: source.manifest.outputDirectoryName
    },
    documentation: {
      path: declared.documentation.path,
      sha256: sha256(documentBytes),
      statements: declared.documentation.statements,
      clarifications: declared.documentation.clarifications
    }
  };
}

function renderRustCrateNotices(delivery) {
  const { verified, section } = delivery;
  const manifest = verified.manifest;
  const materials = verified.noticeMaterials;
  const crates = manifest.items.filter((item) => item.kind === "rust-crate");
  const withoutText = crates.filter((item) => item.noticeStatus === "no-licence-text-in-crate");
  const observed = crates.filter((item) => item.provenanceStatus === "compiled-per-build-log");
  const approximated = crates.filter((item) => item.provenanceStatus === "resolved-approximation");
  const statuses = manifest.provenanceStatuses;
  const log = manifest.historicalBuildLog;
  const transportNote = verified.authoritative ? "transport https (authoritative acquisition)" : `transport ${verified.transport} (NOT authoritative: an offline re-read of retained bytes whose digests equal the manifest pins)`;
  const lines = [
    "",
    "## Rust crate notices for redistributed binaries",
    "",
    "The combined binary below statically links Rust crates through librsvg. Their notice texts are read from the exact crates.io archives pinned by a tracked manifest, re-verified by size, SHA-256 and complete archive framing at generation time, and embedded once per distinct text. This is an auditable material inventory, explicitly partial where marked, not a corresponding-source offer and not legal clearance.",
    "",
    `### \`${escaped(section.lockPackagePath)}\``,
    "",
    `Crate manifest: \`${escaped(delivery.declared.rustCrateMaterials)}\` (\`sha256:${verified.manifestSHA256}\`); notice-materials manifest: \`${escaped(delivery.declared.rustNoticeMaterials)}\` (\`sha256:${materials.sha256}\`); verified crate materials directory \`${escaped(delivery.directoryName)}\` (inventory \`sha256:${verified.inventorySHA256}\`, checksum list \`sha256:${verified.sumsSHA256}\`, complete standalone notices \`RUST_CRATE_NOTICES.md\` \`sha256:${verified.rustNoticesSHA256}\`; ${transportNote}).`,
    "",
    `${crates.length} crates.io registry crates are identified for the librsvg-c static library of this binary: ${observed.length} were observed compiling in the retained historical build log${log === undefined ? "" : ` (raw \`sha256:${log.rawSHA256}\`, ${log.rawBytes} bytes, ${log.lines} lines)`} and ${approximated.length} ${approximated.length === 1 ? "is" : "are"} resolved by approximation only${approximated.length === 0 ? "" : ` (${approximated.map((item) => `\`${escaped(item.crateName)} ${escaped(item.crateVersion)}\``).join(", ")})`}. ${manifest.workspaceMembers.length === 0 ? "" : `The workspace packages ${manifest.workspaceMembers.map((member) => `\`${escaped(member)}\``).join(" and ")} are not registry crates; they are covered by the librsvg source archive and its notice bound in the per-component table above. `}Historical build provenance: compiledInHistoricalBuild=${statuses.compiledInHistoricalBuild}, incorporatedIntoShippedBinary=${statuses.incorporatedIntoShippedBinary}. Observed compilation is not a linkage map: which crate code survives fat LTO and dead-stripping into the shipped dylib is unverified, and nothing here asserts it.`,
    "",
    "| Crate | Version | Role | Licence expression (Cargo.toml) | Provenance status | Notice material in crate | .crate SHA-256 |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  for (const item of crates) {
    let members;
    if (item.noticeMembers.length === 0) {
      const record = materials.records.find((candidate) => candidate.itemId === item.id);
      members = record.status === "established" ? "none in crate; external material bound (see below)" : "none in crate; UNRESOLVED (see below)";
    } else {
      members = item.noticeMembers.map((member) => `\`${escaped(member.member.split("/")[1])}\` (\`sha256:${member.sha256}\`)`).join("<br>");
    }
    lines.push(`| \`${escaped(item.crateName)}\` | \`${escaped(item.crateVersion)}\` | ${item.role} | ${escaped(item.licenseExpression)} | ${item.provenanceStatus} | ${members} | \`${item.sha256}\` |`);
  }
  lines.push(...renderBoundNoticeMaterials(withoutText, materials, 4));
  lines.push("", "#### Licence texts carried by the crate archives", "",
    "Each distinct text is embedded once, with every crate archive member that carries it; the member digests are the values pinned in the crate manifest and verified inside the archives.");
  const embedded = new Map();
  for (const item of crates) {
    for (const member of item.noticeMembers) {
      const binding = `\`${escaped(member.member)}\` (${escaped(item.crateName)} ${escaped(item.crateVersion)}, ${member.size} bytes)`;
      if (embedded.has(member.sha256)) {
        embedded.get(member.sha256).bindings.push(binding);
      } else {
        embedded.set(member.sha256, { item, member, bindings: [binding] });
      }
    }
  }
  for (const [digest, { item, member, bindings }] of embedded) {
    lines.push("",
      `##### \`${escaped(item.crateName)}\` ${escaped(item.crateVersion)}: \`${escaped(member.member.split("/")[1])}\``,
      "",
      `Bound as: ${bindings.join("; ")}`,
      `Exact member SHA-256: \`${digest}\``,
      "",
      verified.noticeTexts.get(`${item.id}\0${member.member}`).replaceAll("\r\n", "\n").replaceAll("\r", "\n").trimEnd());
  }
  return { lines, distinctTexts: embedded.size, memberCount: crates.reduce((total, item) => total + item.noticeMembers.length, 0) };
}

function renderAccompanyingDocumentation(delivery) {
  const { documentation } = delivery;
  const lines = [
    "",
    "## Acknowledgements required in accompanying documentation",
    "",
    `Some licences bound above require a statement in the documentation that accompanies the executable, over and above the licence text itself. The exact wording below is held verbatim in \`${escaped(documentation.path)}\` (\`sha256:${documentation.sha256}\`) and is bound to the tracked notice material it derives from. Placing it in the installation guide or about text is a separate integration and owner decision; its presence here is not legal clearance.`
  ];
  for (const statement of documentation.statements) {
    lines.push("",
      `### ${escaped(statement.component)}${statement.version === null ? "" : ` ${escaped(statement.version)}`} — \`${escaped(basename(statement.material.path))}\` (\`sha256:${statement.material.sha256}\`)`,
      "",
      `Basis: ${escaped(statement.basis)}`,
      "",
      `> ${statement.statement}`);
  }
  for (const clarification of documentation.clarifications) {
    lines.push("",
      `### Clarification: ${escaped(clarification.component)}${clarification.version === null ? "" : ` ${escaped(clarification.version)}`} licence label versus retained texts`,
      "",
      `Upstream licence table label: ${escaped(clarification.upstreamLabel)}. Retained texts: ${clarification.retainedTexts.map((text) => `\`${escaped(text.path)}\` (\`sha256:${text.sha256}\`; ${escaped(text.describes)})`).join("; ")}.`,
      "",
      clarification.statement);
  }
  return lines;
}

function renderDeliveryInventory(delivery, rustSection) {
  const { verified, section, source, documentation, declared } = delivery;
  const materials = verified.noticeMaterials;
  const crates = verified.manifest.items.filter((item) => item.kind === "rust-crate");
  const row = (name, kind, digest, notes) => `| ${name} | ${kind} | ${digest} | ${notes} |`;
  const hex = (digest) => `\`${digest}\``;
  const lines = [
    "",
    `## Delivery material inventory for \`${escaped(section.lockPackagePath)}\``,
    "",
    "Every input consumed to render the Rust crate notices and accompanying acknowledgements above, and every rendered output, bound by exact SHA-256. The crate materials directory is the verified private acquisition named explicitly on the command line; no input was inferred from the environment, and an incomplete or unverifiable input fails generation rather than being omitted.",
    "",
    "| Input or output | Kind | SHA-256 | Notes |",
    "| --- | --- | --- | --- |",
    row(`\`${escaped(section.manifestPath)}\``, "tracked provenance record", hex(section.manifestSHA256), `component \`${escaped(section.componentId)}\`; declares the delivery bindings (\`${escaped(declared.outputDirectoryName)}\`)`),
    row(`\`${escaped(declared.rustCrateMaterials)}\``, "tracked crate manifest", hex(verified.manifestSHA256), `${crates.length} rust-crate items, ${verified.manifest.totalBytes} bytes; compiledInHistoricalBuild=${verified.manifest.provenanceStatuses.compiledInHistoricalBuild}, incorporatedIntoShippedBinary=${verified.manifest.provenanceStatuses.incorporatedIntoShippedBinary}`),
    row(`\`${escaped(declared.rustNoticeMaterials)}\``, "tracked notice-materials manifest", hex(materials.sha256), `established ${materials.summary.established.length}, unresolved ${materials.summary.unresolved.length}; researched ${escaped(materials.researchedOn)}`)
  ];
  for (const record of materials.records) {
    for (const material of record.materials) {
      lines.push(row(`\`${escaped(material.sourcePath)}\``, `tracked external notice material (${escaped(material.kind)})`, hex(material.sha256), `${escaped(record.identity)}; upstream \`${escaped(material.origin)}\` (raw \`sha256:${material.upstreamSHA256}\`)`));
    }
  }
  lines.push(
    row(`\`${escaped(source.path)}\``, "tracked corresponding-source manifest (referenced; its archives are not consumed by notice generation)", hex(source.sha256), `${source.itemCount} items, ${source.totalBytes} bytes; acquisition directory name \`${escaped(source.outputDirectoryName)}\``),
    row(`\`${escaped(documentation.path)}\``, "tracked accompanying documentation", hex(documentation.sha256), `${documentation.statements.length} statement${documentation.statements.length === 1 ? "" : "s"}, ${documentation.clarifications.length} clarification${documentation.clarifications.length === 1 ? "" : "s"}`),
    row(`\`${escaped(delivery.directoryName)}/INVENTORY.json\``, "verified crate materials inventory", hex(verified.inventorySHA256), `transport ${escaped(verified.transport)}${verified.authoritative ? "" : " (NOT authoritative)"}`),
    row(`\`${escaped(delivery.directoryName)}/SHA256SUMS\``, "verified crate materials checksum list", hex(verified.sumsSHA256), `${crates.length} archives plus RUST_CRATE_NOTICES.md`),
    row(`\`${escaped(delivery.directoryName)}/RUST_CRATE_NOTICES.md\``, "verified complete standalone Rust notices (re-rendered and compared at generation time)", hex(verified.rustNoticesSHA256), "rendered by scripts/prepare-libvips-source-materials.mjs with the notice-materials manifest"),
    row(`${crates.length} \`.crate\` archives in \`${escaped(delivery.directoryName)}\``, "verified opaque crates.io archives", "see the per-crate table above", `${verified.manifest.totalBytes} bytes; each verified by size, SHA-256 and complete tar framing; only the manifest-named notice members were read`),
    row("Rust crate notices section above", "rendered output", hex(sha256(rustSection.lines.join("\n"))), `${rustSection.memberCount} notice members, ${rustSection.distinctTexts} distinct texts embedded`)
  );
  return lines;
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
const componentNoticeMaterials = new Map();
const componentNoticeSections = [];
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
      let digest;
      let text;
      if (material.kind === "source") {
        ({ digest, text } = await boundTrackedSourceText(material, lockPackagePath));
      } else {
        const absolute = join(runtimeRoot, ...material.path.split("/"));
        digest = sha256(await boundedRegularBytes(absolute, MAXIMUM_TEXT_BYTES, `override material for ${lockPackagePath}`));
        if (digest !== material.sha256) throw new Error(`override material SHA-256 drifted: ${lockPackagePath} -> ${material.path}`);
      }
      const displayPath = material.kind === "source" ? `source:${material.path}` : material.path;
      materials.push({
        path: displayPath,
        sha256: digest,
        origin: material.origin,
        upstreamSHA256: material.upstreamSHA256
      });
      if (material.kind === "source") recordTrackedSourceMaterial(trackedSourceMaterials, material, digest, text);
    }
    if (override.componentNotices !== undefined) {
      componentNoticeSections.push(await bindComponentNotices(lockPackagePath, override.componentNotices, componentNoticeMaterials));
    }
  }
  materialCount += materials.length;
  const reason = overrides.get(lockPackagePath)?.reason;
  rows.push(`| \`${escaped(runtimeRelative)}\` | \`${escaped(lockPackagePath)}\` | \`${escaped(installed.name)}\` | \`${escaped(installed.version)}\` | ${escaped(installed.license)} | ${formatMaterials(materials)} | ${reason ? escaped(reason) : "Adjacent upstream material"} |`);
}

for (const packagePath of overrides.keys()) {
  if (!usedOverrides.has(packagePath)) throw new Error(`licence override is stale or refers to an unshipped package: ${packagePath}`);
}

// A component that declares delivery material bindings makes the verified
// Rust crate materials a required explicit input: without them generation
// fails closed instead of silently omitting the Rust notices, and the operand
// is refused when nothing declares a binding for it.
const deliverySections = componentNoticeSections.filter((section) => section.deliveryMaterials !== undefined);
if (deliverySections.length > 1) {
  throw new Error(`at most one bound component may declare Rust crate delivery materials: ${deliverySections.map((section) => section.lockPackagePath).join(", ")}`);
}
if (deliverySections.length === 1 && optionArguments.rustCrateMaterials === undefined) {
  const [section] = deliverySections;
  const expected = await loadMaterialsManifest(await requireTrackedPath(section.deliveryMaterials.rustCrateMaterials, `delivery materials for ${section.lockPackagePath} crate manifest`));
  throw new Error(`component ${section.componentId} (${section.lockPackagePath}) declares Rust crate delivery materials; pass --rust-crate-materials <verified ${expected.manifest.outputDirectoryName} directory> (acquired and verified by scripts/prepare-libvips-source-materials.mjs with --notice-materials ${section.deliveryMaterials.rustNoticeMaterials})`);
}
if (deliverySections.length === 0 && optionArguments.rustCrateMaterials !== undefined) {
  throw new Error("--rust-crate-materials was given but no bound component declares Rust crate delivery materials");
}
const delivery = deliverySections.length === 1 ? await bindDeliveryMaterials(deliverySections[0], optionArguments.rustCrateMaterials) : undefined;

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
// Per-component notices for redistributed combined binaries. Texts are embedded
// once per distinct tracked digest; a text already embedded above as a
// package-level tracked material is referenced rather than repeated.
function renderComponentNotices() {
  if (componentNoticeSections.length === 0) return [];
  const embeddedAbove = new Map([...trackedSourceMaterials.values()].map((material) => [material.sha256, material.path]));
  const lines = [
    "",
    "## Exact per-component notices for redistributed binaries",
    "",
    "The combined binaries below statically bundle third-party components whose upstream packages ship no standalone notice files. Each row binds the exact upstream copyright/licence file of the exact pinned component revision, tracked in this repository and proven byte-identical to the immutable upstream origin plus one terminal LF. This is an auditable material inventory, not legal clearance."
  ];
  for (const section of [...componentNoticeSections].sort((left, right) => byCodePoint(left.lockPackagePath, right.lockPackagePath))) {
    const materialCount = section.records.reduce((total, record) => total + record.materials.length, 0);
    const distinct = new Set(section.records.flatMap((record) => record.materials.map((material) => material.sha256)));
    lines.push(
      "",
      `### \`${escaped(section.lockPackagePath)}\``,
      "",
      `Component notice manifest: \`${escaped(section.manifestPath)}\` (\`sha256:${section.manifestSHA256}\`), component \`${escaped(section.componentId)}\`: ${section.records.length} components, ${materialCount} notice materials, ${distinct.size} distinct texts.`,
      "",
      "| Component | Version | Upstream licence declaration | Upstream revision | Notice material | Exact tracked SHA-256 | Upstream origin |",
      "| --- | --- | --- | --- | --- | --- | --- |"
    );
    for (const record of section.records) {
      const cell = (selector) => record.materials.map(selector).join("<br>");
      lines.push(`| \`${escaped(record.component)}\` | ${record.version === null ? "vendored (no separate version)" : `\`${escaped(record.version)}\``} | ${escaped(record.manifestLicense)} | \`${escaped(record.upstreamRepository)}\` @ \`${record.upstreamRevision}\` | ${cell((material) => `\`${escaped(material.path)}\``)} | ${cell((material) => `\`${material.sha256}\``)} | ${cell((material) => `\`${escaped(material.origin)}\``)} |`);
    }
    lines.push("", `#### Notice texts for \`${escaped(section.lockPackagePath)}\``);
    const rendered = new Set();
    for (const record of section.records) {
      for (const material of record.materials) {
        if (rendered.has(material.sha256)) continue;
        rendered.add(material.sha256);
        const sharers = section.records
          .flatMap((other) => other.materials
            .filter((candidate) => candidate.sha256 === material.sha256)
            .map((candidate) => `\`${escaped(candidate.path)}\` (${escaped(other.component)}${other.version === null ? "" : ` ${escaped(other.version)}`}: ${escaped(candidate.describes)})`));
        lines.push(
          "",
          `##### ${escaped(record.component)}${record.version === null ? "" : ` ${escaped(record.version)}`}: \`${escaped(basename(material.path))}\``,
          "",
          `Bound as: ${sharers.join("; ")}`,
          `Upstream: ${material.origin}`,
          `Exact raw upstream SHA-256: \`${material.upstreamSHA256}\``,
          `Exact tracked SHA-256: \`${material.sha256}\``,
          `Source archive member: \`${escaped(material.archiveMember)}\` of archive \`sha256:${material.archiveSHA256}\``,
          "Repository normalization: one terminal LF appended; all upstream text bytes are otherwise identical."
        );
        const above = embeddedAbove.get(material.sha256);
        if (above !== undefined) {
          lines.push("", `Text identical to \`${escaped(above)}\` embedded above; not repeated.`);
        } else {
          lines.push("", material.text.trimEnd());
        }
      }
    }
  }
  return lines;
}

const componentNoticeLines = renderComponentNotices();
const componentNoticeMaterialCount = componentNoticeSections
  .reduce((total, section) => total + section.records.reduce((inner, record) => inner + record.materials.length, 0), 0);
const rustSection = delivery === undefined ? undefined : renderRustCrateNotices(delivery);
const deliveryLines = delivery === undefined ? [] : [
  ...rustSection.lines,
  ...renderAccompanyingDocumentation(delivery),
  ...renderDeliveryInventory(delivery, rustSection)
];
const deliverySummary = delivery === undefined ? [] : [
  `It additionally binds ${rustSection.memberCount} Rust crate notice texts (${rustSection.distinctTexts} distinct) read from ${delivery.verified.manifest.items.length} verified crates.io archives, ${delivery.verified.noticeMaterials.records.reduce((total, record) => total + record.materials.length, 0)} version-bound external notice materials and ${delivery.documentation.statements.length} accompanying-documentation statements; ${delivery.verified.noticeMaterials.summary.unresolved.length} crate notices remain unresolved and are listed as such. See "Rust crate notices for redistributed binaries", "Acknowledgements required in accompanying documentation" and "Delivery material inventory" below.`
];
const inventory = [
  "",
  "## Complete bundled npm dependency inventory",
  "",
  `This artifact-aware inventory contains ${rows.length} package paths actually present in the bundled runtime; ${omittedOptionalPackages} lockfile-only optional package paths are absent and intentionally omitted.`,
  `Pinned production lockfile SHA-256: \`${sha256(lockBytes)}\`. Reviewed override-config SHA-256: \`${sha256(overridesBytes)}\`.`,
  `It binds ${materialCount} npm licence/notice payloads by exact Runtime-relative path and SHA-256. The bundled Node.js consolidated licence is \`NODE_LICENSE\` (\`sha256:${sha256(nodeLicense)}\`).`,
  ...(componentNoticeMaterialCount === 0 ? [] : [
    `It additionally binds ${componentNoticeMaterialCount} exact per-component notice texts for redistributed combined binaries; see "Exact per-component notices for redistributed binaries" below.`
  ]),
  ...deliverySummary,
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
  ...componentNoticeLines,
  ...deliveryLines,
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
