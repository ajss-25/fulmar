import { constants } from "node:fs";
import { lstat, open, readdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { verifyBundledFirstPartyLicense } from "./first-party-license-policy.mjs";

const [runtimeArgument, destination, applicationVersion, projectRootArgument, ...localPackagePaths] = process.argv.slice(2);
if (!runtimeArgument || !destination || !projectRootArgument || localPackagePaths.length === 0
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(applicationVersion ?? "")) {
  throw new Error("usage: generate-sbom.mjs <bundled-runtime-root> <output.json> <application-version> <project-root> <local-package-relative-package.json ...>");
}

const runtimeRoot = resolve(runtimeArgument);
const maximumPackageJSONBytes = 1024 * 1024;
const maximumLockBytes = 32 * 1024 * 1024;
const maximumNodeBytes = 256 * 1024 * 1024;
const maximumLicenseBytes = 16 * 1024 * 1024;
const maximumLocalSourceBytes = 4 * 1024 * 1024;
const maximumPackageTreeFileBytes = 64 * 1024 * 1024;
const maximumPackageTreeBytes = 512 * 1024 * 1024;
const maximumPackageTreeFiles = 100_000;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function firstPartyLicenses(policy) {
  return policy.state === "selected"
    ? [{ expression: policy.spdxExpression }]
    : [{ license: { name: "Fulmar unlicensed private code" } }];
}

function firstPartyProperties(policy) {
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

function validatedRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\\")
      || isAbsolute(value) || value.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`invalid ${label}`);
  }
  return value;
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
  let before;
  try {
    before = await lstat(absolute);
  } catch (error) {
    if (optional && error?.code === "ENOENT") return null;
    throw error;
  }
  if (before.isSymbolicLink() || !before.isFile()) throw new Error(`${label} must be a regular non-symbolic file`);
  if (before.size > maximumBytes) throw new Error(`${label} exceeds its byte limit`);
  let handle;
  try {
    handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
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
  if (value === undefined) return undefined;
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
      const absolute = join(runtimeRoot, runtimePath);
      const stat = await lstat(absolute);
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
const lockData = await readRuntimeFile("package-lock.json", maximumLockBytes, { label: "bundled package-lock.json" });
const lock = JSON.parse(lockData);
if (!lock?.packages || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
  throw new Error("bundled package-lock.json has no packages map");
}

const components = [];
const presentLockPaths = new Set();
const installedPackageValues = new Map();
let presentPackageCount = 0;
let omittedOptionalCount = 0;
for (const [lockPath, value] of Object.entries(lock.packages)) {
  if (!lockPath) continue;
  if (typeof value?.version !== "string") throw new Error(`npm lock path has no exact version: ${lockPath}`);
  const packageJSONPath = installedPackagePath(lockPath);
  const packageData = await readRuntimeFile(packageJSONPath, maximumPackageJSONBytes, {
    optional: value.optional === true,
    label: `installed package.json for ${lockPath}`
  });
  if (packageData === null) {
    omittedOptionalCount += 1;
    continue;
  }
  presentPackageCount += 1;
  presentLockPaths.add(lockPath);
  const installed = JSON.parse(packageData);
  installedPackageValues.set(lockPath, installed);
  const name = assertInstalledIdentity(lockPath, value, installed);
  const tree = await hashPackageTree(packageJSONPath);
  const component = {
    type: "library",
    "bom-ref": `npm-path:${lockPath}`,
    name,
    version: value.version,
    purl: npmPurl(name, value.version),
    scope: value.optional === true ? "optional" : "required",
    hashes: [{ alg: "SHA-256", content: tree.digest }],
    properties: [
      { name: "local-harness:npm-path", value: lockPath },
      { name: "local-harness:package-json-path", value: packageJSONPath },
      { name: "local-harness:package-json-sha256", value: sha256(packageData) },
      { name: "local-harness:package-tree-file-count", value: String(tree.fileCount) },
      { name: "local-harness:package-tree-byte-count", value: String(tree.byteCount) }
    ]
  };
  const licenses = cycloneDXLicenses(value.license);
  if (licenses) component.licenses = licenses;
  if (value.integrity) component.properties.push({ name: "local-harness:lock-integrity", value: value.integrity });
  if (lockPath === "node_modules/@deepseek-ai/dsh") {
    const patchPath = join(dirname(runtimeRoot), "LocalHarness.patch.yml");
    const patchBytes = await readRuntimeFile("../LocalHarness.patch.yml", maximumLocalSourceBytes, {
      label: "Fulmar DSH patch provenance"
    }).catch(async (error) => {
      // Runtime-relative traversal is forbidden for general package paths. The
      // fixed signed sibling is read explicitly and must still be regular.
      if (!String(error?.message ?? "").startsWith("invalid ")) throw error;
      const stat = await lstat(patchPath);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > maximumLocalSourceBytes) {
        throw new Error("Fulmar DSH patch provenance must be a bounded regular file");
      }
      let handle;
      try {
        handle = await open(patchPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        return await handle.readFile();
      } finally {
        await handle?.close();
      }
    });
    component.properties.push(
      { name: "local-harness:artifact-modification", value: "Fulmar preset sanitization and reviewed local-plugin dependency materialization" },
      { name: "local-harness:patch-source-path", value: "../LocalHarness.patch.yml" },
      { name: "local-harness:patch-source-sha256", value: sha256(patchBytes) }
    );
  }
  components.push(component);
}

const nodeBinary = await readRuntimeFile("node", maximumNodeBytes, { label: "bundled Node.js executable" });
const nodeLicense = await readRuntimeFile("NODE_LICENSE", maximumLicenseBytes, { label: "bundled Node.js license" });
components.push({
  type: "framework",
  "bom-ref": "runtime:node@22.23.1",
  name: "Node.js",
  version: "22.23.1",
  purl: "pkg:generic/nodejs@22.23.1",
  scope: "required",
  hashes: [{ alg: "SHA-256", content: sha256(nodeBinary) }],
  licenses: [{ license: { name: "Node.js license" } }],
  properties: [{ name: "local-harness:license-sha256", value: sha256(nodeLicense) }]
});

const localPackageIdentities = new Set();
const localPackageRecords = [];
for (const packagePathValue of localPackagePaths) {
  const packagePath = validatedRelativePath(packagePathValue, "local package path");
  if (!packagePath.endsWith("/package.json")) throw new Error(`invalid bundled local package path: ${packagePath}`);
  const packageData = await readRuntimeFile(packagePath, maximumPackageJSONBytes, { label: `local package ${packagePath}` });
  const value = JSON.parse(packageData);
  if (typeof value?.name !== "string" || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(value.name)
      || typeof value?.version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version)) {
    throw new Error(`invalid bundled local package metadata: ${packagePath}`);
  }
  const packageDirectory = dirname(packagePath);
  const absoluteDirectory = join(runtimeRoot, packageDirectory);
  const entries = (await readdir(absoluteDirectory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
  const sourceHasher = createHash("sha256");
  for (const entry of entries) {
    if (!entry.isFile() || !/^(?:package\.json|[a-z0-9-]+\.(?:mjs|js))$/i.test(entry.name)) {
      throw new Error(`unreviewed bundled local package entry: ${entry.name}`);
    }
    const bytes = await readRuntimeFile(`${packageDirectory}/${entry.name}`, maximumLocalSourceBytes, {
      label: `local package source ${packageDirectory}/${entry.name}`
    });
    sourceHasher.update(entry.name, "utf8");
    sourceHasher.update("\0");
    sourceHasher.update(sha256(bytes), "utf8");
    sourceHasher.update("\0");
  }
  const purl = npmPurl(value.name, value.version);
  if (localPackageIdentities.has(purl) || components.some((component) => component.purl === purl)) {
    throw new Error(`bundled local package duplicates an existing SBOM identity: ${value.name}@${value.version}`);
  }
  localPackageIdentities.add(purl);
  const bomRef = `local-package:${value.name}@${value.version}`;
  localPackageRecords.push({ bomRef, value, resolutionPath: packagePath.slice("dsh/".length, -"/package.json".length) });
  components.push({
    type: "library",
    "bom-ref": bomRef,
    name: value.name,
    version: value.version,
    purl,
    scope: "required",
    licenses: firstPartyLicenses(firstPartyLicense),
    hashes: [{ alg: "SHA-256", content: sourceHasher.digest("hex") }],
    properties: [
      { name: "local-harness:bundled-local-plugin", value: "true" },
      { name: "local-harness:package-json-path", value: packagePath },
      { name: "local-harness:package-json-sha256", value: sha256(packageData) },
      ...firstPartyProperties(firstPartyLicense)
    ]
  });
}

const expectedPackageJSONPaths = new Set([
  ...[...presentLockPaths].map(installedPackagePath),
  ...localPackagePaths.map((path) => validatedRelativePath(path, "local package path"))
]);
const discoveredPackageJSONPaths = await discoverInstalledPackageJSONPaths();
if (JSON.stringify([...discoveredPackageJSONPaths].sort()) !== JSON.stringify([...expectedPackageJSONPaths].sort())) {
  throw new Error("bundled Runtime package roots do not exactly match lockfile and reviewed local packages");
}

components.sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));
const localRefs = localPackageRecords.map((record) => record.bomRef).sort();
const localRefByName = new Map(localPackageRecords.map((record) => [record.value.name, record.bomRef]));
const nodeRef = "runtime:node@22.23.1";
const applicationRef = `application:Fulmar@${applicationVersion}`;
const dependencies = [];
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
  dependencies.push({ ref: `npm-path:${lockPath}`, dependsOn: [...new Set(dependencyRefs)].sort() });
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
  dependencies.push({ ref: record.bomRef, dependsOn: [...new Set(dependencyRefs)].sort() });
}
dependencies.push({ ref: nodeRef, dependsOn: [] });
const rootDependencies = [];
for (const name of dependencyNames(lock.packages[""])) {
  const resolved = resolveDependencyPath("", name, presentLockPaths);
  if (resolved) rootDependencies.push(`npm-path:${resolved}`);
  else if (!dependencyMayBeOmitted(lock.packages[""], name)) {
    throw new Error(`required root dependency ${name} is not shipped`);
  }
}
dependencies.push({ ref: applicationRef, dependsOn: [...new Set([nodeRef, ...rootDependencies])].sort() });
dependencies.sort((left, right) => left.ref.localeCompare(right.ref));
const document = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: {
    component: {
      type: "application",
      "bom-ref": applicationRef,
      name: "Fulmar",
      version: applicationVersion,
      licenses: firstPartyLicenses(firstPartyLicense),
      properties: firstPartyProperties(firstPartyLicense)
    },
    properties: [
      { name: "local-harness:package-lock-sha256", value: sha256(lockData) },
      { name: "local-harness:npm-present-count", value: String(presentPackageCount) },
      { name: "local-harness:npm-omitted-optional-count", value: String(omittedOptionalCount) }
    ]
  },
  components,
  dependencies
};
await writeFile(destination, JSON.stringify(document, null, 2) + "\n", { mode: 0o644 });
