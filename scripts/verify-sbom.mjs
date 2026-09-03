import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open, readdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyBundledFirstPartyLicense } from "./first-party-license-policy.mjs";

const [sbomArgument, runtimeArgument, projectRootArgument, ...localPackagePaths] = process.argv.slice(2);
if (!sbomArgument || !runtimeArgument || !projectRootArgument || localPackagePaths.length === 0) {
  throw new Error("usage: verify-sbom.mjs <sbom> <bundled-runtime-root> <project-root> <local-package-relative-package.json ...>");
}

const runtimeRoot = resolve(runtimeArgument);
const maximumPackageJSONBytes = 1024 * 1024;
const maximumLockBytes = 32 * 1024 * 1024;
const maximumNodeBytes = 256 * 1024 * 1024;
const maximumLicenseBytes = 16 * 1024 * 1024;
const maximumLocalSourceBytes = 4 * 1024 * 1024;
const maximumSBOMBytes = 32 * 1024 * 1024;
const maximumPackageTreeFileBytes = 64 * 1024 * 1024;
const maximumPackageTreeBytes = 512 * 1024 * 1024;
const maximumPackageTreeFiles = 100_000;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const property = (component, name) => component.properties?.find((candidate) => candidate.name === name)?.value;

function expectedFirstPartyLicenses(policy) {
  return policy.state === "selected"
    ? [{ expression: policy.spdxExpression }]
    : [{ license: { name: "Fulmar unlicensed private code" } }];
}

function expectedFirstPartyProperties(policy) {
  if (policy.state === "unlicensed-private") {
    return [{ name: "local-harness:first-party-license-state", value: "unlicensed-private" }];
  }
  return [
    { name: "local-harness:first-party-license-state", value: "selected" },
    { name: "local-harness:first-party-license-file", value: "LICENSE" },
    { name: "local-harness:first-party-license-sha256", value: policy.licenseSHA256 },
    { name: "local-harness:first-party-license-spdx-expression", value: policy.spdxExpression },
    { name: "local-harness:first-party-license-display-name", value: policy.displayName }
  ];
}

function assertFirstPartyDeclaration(component, policy, label) {
  if (JSON.stringify(component.licenses ?? []) !== JSON.stringify(expectedFirstPartyLicenses(policy))) {
    throw new Error(`${label} first-party licensing declaration mismatch`);
  }
  const actualProperties = (component.properties ?? [])
    .filter((entry) => typeof entry?.name === "string" && entry.name.startsWith("local-harness:first-party-license-"));
  if (JSON.stringify(actualProperties) !== JSON.stringify(expectedFirstPartyProperties(policy))) {
    throw new Error(`${label} first-party licensing digest or metadata mismatch`);
  }
}

function validatedRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\\")
      || isAbsolute(value) || value.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`invalid ${label}`);
  }
  return value;
}

const allowedHashAlgorithms = new Set([
  "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512",
  "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3"
]);

function validatePinnedCycloneDXProfile(sbom) {
  if (sbom?.bomFormat !== "CycloneDX" || sbom?.specVersion !== "1.5" || sbom?.version !== 1
      || !Array.isArray(sbom?.components) || !Array.isArray(sbom?.dependencies)) {
    throw new Error("SBOM fails the pinned CycloneDX 1.5 release profile");
  }
  for (const component of sbom.components) {
    if (!component || !["library", "framework"].includes(component.type)
        || typeof component["bom-ref"] !== "string" || component["bom-ref"].length === 0
        || typeof component.name !== "string" || typeof component.version !== "string"
        || !["required", "optional"].includes(component.scope)) {
      throw new Error("SBOM component fails the pinned CycloneDX 1.5 release profile");
    }
    for (const hash of component.hashes ?? []) {
      if (!hash || !allowedHashAlgorithms.has(hash.alg) || typeof hash.content !== "string" || hash.content.length === 0) {
        throw new Error("SBOM hash fails the pinned CycloneDX 1.5 release profile");
      }
    }
    for (const entry of component.licenses ?? []) {
      const expression = entry?.expression;
      const id = entry?.license?.id;
      const name = entry?.license?.name;
      const alternatives = Number(typeof expression === "string")
        + Number(typeof id === "string" || typeof name === "string");
      if (alternatives !== 1 || (typeof id === "string" && /(?:^|\s)(?:AND|OR|WITH)(?:\s|$)|[()]/u.test(id))) {
        throw new Error("SBOM license fails the pinned CycloneDX 1.5 release profile");
      }
    }
  }
  for (const relationship of sbom.dependencies) {
    if (typeof relationship?.ref !== "string" || relationship.ref.length === 0
        || !Array.isArray(relationship.dependsOn)
        || relationship.dependsOn.some((ref) => typeof ref !== "string" || ref.length === 0)) {
      throw new Error("SBOM dependency fails the pinned CycloneDX 1.5 release profile");
    }
  }
}

async function readOpenedRegularFile(absolutePath, maximumBytes, label) {
  const before = await lstat(absolutePath);
  if (before.isSymbolicLink() || !before.isFile()) throw new Error(`${label} must be a regular non-symbolic file`);
  if (before.size > maximumBytes) throw new Error(`${label} exceeds its byte limit`);
  let handle;
  try {
    // O_NOFOLLOW plus descriptor fstat before/after binds every consumed byte.
    // codeql[js/file-system-race]
    handle = await open(absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > maximumBytes || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error(`${label} changed while it was being verified`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || bytes.length !== opened.size) {
      throw new Error(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function assertRuntimeRoot() {
  const stat = await lstat(runtimeRoot);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("bundled runtime root must be a regular directory");
}

async function readRuntimeFile(relativePath, maximumBytes, { optional = false, label = relativePath } = {}) {
  const safe = validatedRelativePath(relativePath, label);
  const parts = safe.split("/");
  let cursor = runtimeRoot;
  for (const part of parts.slice(0, -1)) {
    cursor = join(cursor, part);
    let stat;
    try {
      stat = await lstat(cursor);
    } catch (error) {
      if (optional && error?.code === "ENOENT") return null;
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`${label} has a symbolic or non-directory ancestor`);
  }
  const absolute = join(runtimeRoot, safe);
  try {
    return await readOpenedRegularFile(absolute, maximumBytes, label);
  } catch (error) {
    if (optional && error?.code === "ENOENT") return null;
    throw error;
  }
}

function installedPackagePath(lockPath) {
  validatedRelativePath(lockPath, "npm lock path");
  if (!lockPath.startsWith("node_modules/")) throw new Error(`unsupported npm lock path: ${lockPath}`);
  return lockPath === "node_modules/@deepseek-ai/dsh"
    ? "dsh/package.json"
    : `dsh/${lockPath}/package.json`;
}

function packageName(lockPath, value) {
  const tail = lockPath.slice(lockPath.lastIndexOf("node_modules/") + "node_modules/".length);
  const segments = tail.split("/");
  return value.name ?? (segments[0]?.startsWith("@") ? segments.slice(0, 2).join("/") : segments[0]);
}

function npmPurl(name, version) {
  if (name.startsWith("@")) {
    const separator = name.indexOf("/");
    if (separator <= 1 || separator === name.length - 1) throw new Error(`invalid scoped npm package name: ${name}`);
    return `pkg:npm/${encodeURIComponent(name.slice(0, separator))}/${encodeURIComponent(name.slice(separator + 1))}@${encodeURIComponent(version)}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function cycloneDXLicenses(value) {
  if (value === undefined) return [];
  const license = String(value);
  return /(?:^|\s)(?:AND|OR|WITH)(?:\s|$)|[()]/u.test(license)
    ? [{ expression: license }]
    : [{ license: { id: license } }];
}

async function hashPackageTree(packageJSONPath) {
  const packageRoot = dirname(packageJSONPath);
  const hasher = createHash("sha256");
  let fileCount = 0;
  let byteCount = 0;

  async function walk(directoryPath, treePrefix) {
    const entries = (await readdir(join(runtimeRoot, directoryPath), { withFileTypes: true }))
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      if (entry.name === "node_modules" && entry.isDirectory()) continue;
      const runtimePath = `${directoryPath}/${entry.name}`;
      const treePath = treePrefix ? `${treePrefix}/${entry.name}` : entry.name;
      const stat = await lstat(join(runtimeRoot, runtimePath));
      if (stat.isSymbolicLink()) throw new Error(`package tree contains a symbolic link: ${runtimePath}`);
      if (stat.isDirectory()) {
        hasher.update("directory\0", "utf8");
        hasher.update(treePath, "utf8");
        hasher.update("\0", "utf8");
        await walk(runtimePath, treePath);
        continue;
      }
      if (!stat.isFile()) throw new Error(`package tree contains a non-regular entry: ${runtimePath}`);
      if (stat.size > maximumPackageTreeFileBytes) throw new Error(`package tree file exceeds its byte limit: ${runtimePath}`);
      fileCount += 1;
      byteCount += stat.size;
      if (fileCount > maximumPackageTreeFiles || byteCount > maximumPackageTreeBytes) {
        throw new Error(`package tree exceeds its aggregate limit: ${packageRoot}`);
      }
      const bytes = await readRuntimeFile(runtimePath, maximumPackageTreeFileBytes, { label: `package tree file ${runtimePath}` });
      hasher.update("file\0", "utf8");
      hasher.update(treePath, "utf8");
      hasher.update("\0", "utf8");
      hasher.update((stat.mode & 0o777).toString(8), "utf8");
      hasher.update("\0", "utf8");
      hasher.update(sha256(bytes), "utf8");
      hasher.update("\0", "utf8");
    }
  }

  await walk(packageRoot, "");
  return { digest: hasher.digest("hex"), fileCount, byteCount };
}

function dependencyNames(value) {
  return [...new Set([
    ...Object.keys(value?.dependencies ?? {}),
    ...Object.keys(value?.optionalDependencies ?? {}),
    ...Object.keys(value?.peerDependencies ?? {})
  ])].sort();
}

function dependencyMayBeOmitted(value, name) {
  return Object.hasOwn(value?.optionalDependencies ?? {}, name)
    || value?.peerDependenciesMeta?.[name]?.optional === true;
}

function resolveDependencyPath(fromPath, dependencyName, presentPaths) {
  let base = fromPath;
  while (base) {
    const nested = `${base}/node_modules/${dependencyName}`;
    if (presentPaths.has(nested)) return nested;
    const marker = base.lastIndexOf("/node_modules/");
    if (marker < 0) break;
    base = base.slice(0, marker);
  }
  const root = `node_modules/${dependencyName}`;
  return presentPaths.has(root) ? root : null;
}

async function discoverInstalledPackageJSONPaths() {
  const discovered = new Set(["dsh/package.json"]);

  async function packageRoot(relativeRoot) {
    const packageJSONPath = `${relativeRoot}/package.json`;
    await readRuntimeFile(packageJSONPath, maximumPackageJSONBytes, { label: `discovered package ${packageJSONPath}` });
    discovered.add(packageJSONPath);
    const nested = `${relativeRoot}/node_modules`;
    try {
      const stat = await lstat(join(runtimeRoot, nested));
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`nested node_modules is not a regular directory: ${nested}`);
      await nodeModules(nested);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }

  async function nodeModules(relativeRoot) {
    const entries = (await readdir(join(runtimeRoot, relativeRoot), { withFileTypes: true }))
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      if (entry.name === ".bin" || entry.name === ".package-lock.json") continue;
      const relativeEntry = `${relativeRoot}/${entry.name}`;
      const stat = await lstat(join(runtimeRoot, relativeEntry));
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`node_modules contains a non-package entry: ${relativeEntry}`);
      if (entry.name.startsWith("@")) {
        const scoped = (await readdir(join(runtimeRoot, relativeEntry), { withFileTypes: true }))
          .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
        for (const child of scoped) {
          const childRoot = `${relativeEntry}/${child.name}`;
          const childStat = await lstat(join(runtimeRoot, childRoot));
          if (childStat.isSymbolicLink() || !childStat.isDirectory()) {
            throw new Error(`npm scope contains a non-package entry: ${childRoot}`);
          }
          await packageRoot(childRoot);
        }
      } else {
        await packageRoot(relativeEntry);
      }
    }
  }

  await nodeModules("dsh/node_modules");
  return discovered;
}

function assertInstalledIdentity(lockPath, lockValue, installed) {
  const name = packageName(lockPath, lockValue);
  if (typeof name !== "string" || installed?.name !== name || installed?.version !== lockValue.version
      || (installed?.license ?? null) !== (lockValue.license ?? null)) {
    throw new Error(`installed package metadata does not match lock path ${lockPath}`);
  }
  return name;
}

await assertRuntimeRoot();
const firstPartyLicense = await verifyBundledFirstPartyLicense(
  projectRootArgument,
  join(dirname(runtimeRoot), "LICENSE")
);
const schemaPath = fileURLToPath(new URL("./cyclonedx-1.5-fulmar.schema.json", import.meta.url));
const schemaBytes = await readOpenedRegularFile(schemaPath, 256 * 1024, "pinned CycloneDX release schema");
if (sha256(schemaBytes) !== "4163cf3e729172680ff0f34e197af50fc67ef535c46611bb656c96b1037cfdc3") {
  throw new Error("pinned CycloneDX release schema digest mismatch");
}
const sbomPath = resolve(sbomArgument);
const sbom = JSON.parse(await readOpenedRegularFile(sbomPath, maximumSBOMBytes, "SBOM"));
validatePinnedCycloneDXProfile(sbom);
const lockBytes = await readRuntimeFile("package-lock.json", maximumLockBytes, { label: "bundled package-lock.json" });
const lock = JSON.parse(lockBytes);
if (!lock?.packages || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
  throw new Error("bundled package-lock.json has no packages map");
}
if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.5" || sbom.version !== 1 || !Array.isArray(sbom.components)) {
  throw new Error("SBOM header is invalid");
}
if (sbom.metadata?.component?.type !== "application" || sbom.metadata.component.name !== "Fulmar"
    || typeof sbom.metadata.component.version !== "string" || typeof sbom.metadata.component["bom-ref"] !== "string"
    || !Array.isArray(sbom.dependencies)) {
  throw new Error("SBOM application identity is invalid");
}
if (sbom.metadata.component["bom-ref"] !== `application:Fulmar@${sbom.metadata.component.version}`) {
  throw new Error("SBOM application bom-ref is invalid");
}
assertFirstPartyDeclaration(sbom.metadata.component, firstPartyLicense, "SBOM application");
if (property(sbom.metadata, "local-harness:package-lock-sha256") !== sha256(lockBytes)) {
  throw new Error("SBOM package-lock digest does not match bundled lockfile");
}

const refs = new Set();
for (const component of sbom.components) {
  if (typeof component?.["bom-ref"] !== "string" || refs.has(component["bom-ref"])) {
    throw new Error("SBOM contains a missing or duplicate bom-ref");
  }
  refs.add(component["bom-ref"]);
  if (component.hashes?.some((hash) => hash?.alg === "SRI")) {
    throw new Error("SBOM uses the non-CycloneDX SRI hash algorithm");
  }
}

let presentPackageCount = 0;
let omittedOptionalCount = 0;
const presentLockPaths = new Set();
const installedPackageValues = new Map();
for (const [lockPath, value] of Object.entries(lock.packages)) {
  if (!lockPath) continue;
  if (typeof value?.version !== "string") throw new Error(`npm lock path has no exact version: ${lockPath}`);
  const packageJSONPath = installedPackagePath(lockPath);
  const packageBytes = await readRuntimeFile(packageJSONPath, maximumPackageJSONBytes, {
    optional: value.optional === true,
    label: `installed package.json for ${lockPath}`
  });
  const matches = sbom.components.filter((component) => property(component, "local-harness:npm-path") === lockPath);
  if (packageBytes === null) {
    omittedOptionalCount += 1;
    if (matches.length !== 0) throw new Error(`SBOM includes omitted optional lock path ${lockPath}`);
    continue;
  }
  presentPackageCount += 1;
  presentLockPaths.add(lockPath);
  if (matches.length !== 1) throw new Error(`SBOM must contain exactly one shipped component for lock path ${lockPath}`);
  const installed = JSON.parse(packageBytes);
  installedPackageValues.set(lockPath, installed);
  const name = assertInstalledIdentity(lockPath, value, installed);
  const component = matches[0];
  const expectedScope = value.optional === true ? "optional" : "required";
  const expectedPurl = npmPurl(name, value.version);
  const tree = await hashPackageTree(packageJSONPath);
  if (component["bom-ref"] !== `npm-path:${lockPath}` || component.type !== "library"
      || component.name !== name || component.version !== value.version || component.purl !== expectedPurl
      || component.scope !== expectedScope) {
    throw new Error(`SBOM identity or scope mismatch for lock path ${lockPath}`);
  }
  if (property(component, "local-harness:package-json-path") !== packageJSONPath
      || property(component, "local-harness:package-json-sha256") !== sha256(packageBytes)
      || property(component, "local-harness:package-tree-file-count") !== String(tree.fileCount)
      || property(component, "local-harness:package-tree-byte-count") !== String(tree.byteCount)
      || component.hashes?.length !== 1 || component.hashes[0]?.alg !== "SHA-256"
      || component.hashes[0]?.content !== tree.digest) {
    throw new Error(`SBOM installed package path or digest mismatch for lock path ${lockPath}`);
  }
  if ((value.integrity === undefined && property(component, "local-harness:lock-integrity") !== undefined)
      || (value.integrity !== undefined && property(component, "local-harness:lock-integrity") !== value.integrity)) {
    throw new Error(`SBOM integrity mismatch for lock path ${lockPath}`);
  }
  if (JSON.stringify(component.licenses ?? []) !== JSON.stringify(cycloneDXLicenses(value.license))) {
    throw new Error(`SBOM license mismatch for lock path ${lockPath}`);
  }
  if (lockPath === "node_modules/@deepseek-ai/dsh") {
    const patchPath = join(dirname(runtimeRoot), "LocalHarness.patch.yml");
    const patchBytes = await readOpenedRegularFile(patchPath, maximumLocalSourceBytes, "Fulmar DSH patch provenance");
    if (property(component, "local-harness:artifact-modification")
          !== "Fulmar preset sanitization and reviewed local-plugin dependency materialization"
        || property(component, "local-harness:patch-source-path") !== "../LocalHarness.patch.yml"
        || property(component, "local-harness:patch-source-sha256") !== sha256(patchBytes)) {
      throw new Error("SBOM DSH patch provenance mismatch");
    }
  }
}

if (property(sbom.metadata, "local-harness:npm-present-count") !== String(presentPackageCount)
    || property(sbom.metadata, "local-harness:npm-omitted-optional-count") !== String(omittedOptionalCount)) {
  throw new Error("SBOM present/omitted package counts do not match the bundled Runtime");
}

const nodeBytes = await readRuntimeFile("node", maximumNodeBytes, { label: "bundled Node.js executable" });
const nodeLicense = await readRuntimeFile("NODE_LICENSE", maximumLicenseBytes, { label: "bundled Node.js license" });
const nodeMatches = sbom.components.filter((component) => component["bom-ref"] === "runtime:node@22.23.1");
if (nodeMatches.length !== 1 || nodeMatches[0].type !== "framework" || nodeMatches[0].name !== "Node.js"
    || nodeMatches[0].version !== "22.23.1" || nodeMatches[0].purl !== "pkg:generic/nodejs@22.23.1"
    || nodeMatches[0].scope !== "required"
    || !nodeMatches[0].licenses?.some((entry) => entry.license?.name === "Node.js license")
    || !nodeMatches[0].hashes?.some((hash) => hash.alg === "SHA-256" && hash.content === sha256(nodeBytes))
    || property(nodeMatches[0], "local-harness:license-sha256") !== sha256(nodeLicense)) {
  throw new Error("SBOM Node.js runtime or license digest mismatch");
}

const localPackageRecords = [];
for (const packagePathValue of localPackagePaths) {
  const packagePath = validatedRelativePath(packagePathValue, "local package path");
  if (!packagePath.endsWith("/package.json")) throw new Error(`invalid bundled local package path: ${packagePath}`);
  const packageBytes = await readRuntimeFile(packagePath, maximumPackageJSONBytes, { label: `local package ${packagePath}` });
  const packageValue = JSON.parse(packageBytes);
  const matches = sbom.components.filter((component) => component["bom-ref"] === `local-package:${packageValue.name}@${packageValue.version}`);
  const expectedPurl = npmPurl(packageValue.name, packageValue.version);
  if (matches.length !== 1 || matches[0].type !== "library" || matches[0].name !== packageValue.name
      || matches[0].version !== packageValue.version || matches[0].purl !== expectedPurl
      || matches[0].scope !== "required" || property(matches[0], "local-harness:bundled-local-plugin") !== "true"
      || property(matches[0], "local-harness:package-json-path") !== packagePath) {
    throw new Error(`SBOM local-package identity mismatch for ${packageValue.name}`);
  }
  localPackageRecords.push({
    bomRef: matches[0]["bom-ref"],
    value: packageValue,
    resolutionPath: packagePath.slice("dsh/".length, -"/package.json".length)
  });
  assertFirstPartyDeclaration(matches[0], firstPartyLicense, `SBOM local package ${packageValue.name}`);
  if (property(matches[0], "local-harness:package-json-sha256") !== sha256(packageBytes)) {
    throw new Error(`SBOM package.json digest mismatch for ${packageValue.name}`);
  }
  const sourceHasher = createHash("sha256");
  const packageDirectory = dirname(packagePath);
  const entries = (await readdir(join(runtimeRoot, packageDirectory), { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    if (!entry.isFile() || !/^(?:package\.json|[a-z0-9-]+\.(?:mjs|js))$/i.test(entry.name)) {
      throw new Error(`unreviewed local-package entry: ${entry.name}`);
    }
    const bytes = await readRuntimeFile(`${packageDirectory}/${entry.name}`, maximumLocalSourceBytes, {
      label: `local package source ${packageDirectory}/${entry.name}`
    });
    sourceHasher.update(entry.name, "utf8");
    sourceHasher.update("\0");
    sourceHasher.update(sha256(bytes), "utf8");
    sourceHasher.update("\0");
  }
  if (!matches[0].hashes?.some((hash) => hash.alg === "SHA-256" && hash.content === sourceHasher.digest("hex"))) {
    throw new Error(`SBOM source digest mismatch for ${packageValue.name}`);
  }
}

const expectedCount = presentPackageCount + 1 + localPackagePaths.length;
if (sbom.components.length !== expectedCount) {
  throw new Error(`SBOM component count mismatch: expected ${expectedCount}, found ${sbom.components.length}`);
}

const expectedPackageJSONPaths = new Set([
  ...[...presentLockPaths].map(installedPackagePath),
  ...localPackagePaths.map((path) => validatedRelativePath(path, "local package path"))
]);
const discoveredPackageJSONPaths = await discoverInstalledPackageJSONPaths();
if (JSON.stringify([...discoveredPackageJSONPaths].sort()) !== JSON.stringify([...expectedPackageJSONPaths].sort())) {
  throw new Error("bundled Runtime package roots do not exactly match lockfile and reviewed local packages");
}

const localRefs = localPackageRecords.map((record) => record.bomRef).sort();
const localRefByName = new Map(localPackageRecords.map((record) => [record.value.name, record.bomRef]));
const nodeRef = "runtime:node@22.23.1";
const expectedDependencies = [];
for (const lockPath of [...presentLockPaths].sort()) {
  const dependencyRefs = [];
  const installed = installedPackageValues.get(lockPath);
  for (const name of dependencyNames(installed)) {
    const resolved = resolveDependencyPath(lockPath, name, presentLockPaths);
    if (resolved) dependencyRefs.push(`npm-path:${resolved}`);
    else if (localRefByName.has(name)) dependencyRefs.push(localRefByName.get(name));
    else if (!dependencyMayBeOmitted(installed, name)) {
      throw new Error(`required dependency ${name} is not shipped for lock path ${lockPath}`);
    }
  }
  expectedDependencies.push({ ref: `npm-path:${lockPath}`, dependsOn: [...new Set(dependencyRefs)].sort() });
}
for (const record of localPackageRecords) {
  const dependencyRefs = [];
  for (const name of dependencyNames(record.value)) {
    const resolved = resolveDependencyPath(record.resolutionPath, name, presentLockPaths);
    if (resolved) dependencyRefs.push(`npm-path:${resolved}`);
    else if (localRefByName.has(name)) dependencyRefs.push(localRefByName.get(name));
    else if (!dependencyMayBeOmitted(record.value, name)) {
      throw new Error(`required dependency ${name} is not shipped for local package ${record.value.name}`);
    }
  }
  expectedDependencies.push({ ref: record.bomRef, dependsOn: [...new Set(dependencyRefs)].sort() });
}
expectedDependencies.push({ ref: nodeRef, dependsOn: [] });
const rootDependencies = [];
for (const name of dependencyNames(lock.packages[""])) {
  const resolved = resolveDependencyPath("", name, presentLockPaths);
  if (resolved) rootDependencies.push(`npm-path:${resolved}`);
  else if (!dependencyMayBeOmitted(lock.packages[""], name)) {
    throw new Error(`required root dependency ${name} is not shipped`);
  }
}
expectedDependencies.push({
  ref: sbom.metadata.component["bom-ref"],
  dependsOn: [...new Set([nodeRef, ...rootDependencies])].sort()
});
expectedDependencies.sort((left, right) => left.ref.localeCompare(right.ref));
const actualDependencies = sbom.dependencies.map((entry) => ({
  ref: entry?.ref,
  dependsOn: Array.isArray(entry?.dependsOn) ? [...entry.dependsOn].sort() : entry?.dependsOn
})).sort((left, right) => String(left.ref).localeCompare(String(right.ref)));
if (JSON.stringify(actualDependencies) !== JSON.stringify(expectedDependencies)) {
  throw new Error("SBOM dependency relationships do not match the installed package graph");
}

process.stdout.write(`SBOM verified against ${presentPackageCount} shipped npm paths (${omittedOptionalCount} optional omitted), Node.js, and ${localPackagePaths.length} bundled local packages.\n`);
