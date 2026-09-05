// Pure consistency tests for Config/ThirdPartyBinaryProvenance.json.
//
// These tests read only tracked repository files: the provenance manifest, the
// licence override config, the tracked licence texts, the pinned production
// lockfile and the reviewed VendorRuntime inventory. They never touch the
// reconstructed runtime, the shared build root, or any network resource, and
// they do not claim legal clearance: an obligation recorded as `open` must stay
// visibly open until a human closes it with retained evidence.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const project = process.cwd();
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;

const readJSON = async (relative) => JSON.parse(await readFile(join(project, relative), "utf8"));

test("binary provenance manifest is strict, bounded and names its open obligations", async () => {
  const manifest = await readJSON("Config/ThirdPartyBinaryProvenance.json");
  assert.deepEqual(Object.keys(manifest).sort(), ["components", "purpose", "schemaVersion"]);
  assert.equal(manifest.schemaVersion, 1);
  assert.match(manifest.purpose, /not legal clearance/u);
  assert.ok(Array.isArray(manifest.components) && manifest.components.length === 1);
  const [component] = manifest.components;
  assert.deepEqual(Object.keys(component).sort(), [
    "boundLicenseTexts", "componentVersions", "declaredLicense", "id", "integrity", "lgplComponents",
    "lockfile", "lockfilePath", "obligations", "packageName", "registryMetadata", "resolved",
    "shippedFiles", "upstream", "version"
  ]);
  assert.equal(component.id, "sharp-libvips-darwin-arm64");
  assert.equal(component.packageName, "@img/sharp-libvips-darwin-arm64");
  assert.equal(component.version, "1.3.2");
  assert.equal(component.declaredLicense, "LGPL-3.0-or-later");
  assert.match(component.resolved, /^https:\/\/registry\.npmjs\.org\/@img\/sharp-libvips-darwin-arm64\/-\/sharp-libvips-darwin-arm64-1\.3\.2\.tgz$/u);
  assert.match(component.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/u);
  assert.match(component.registryMetadata.gitHead, COMMIT);
  assert.equal(component.upstream.buildCommit, component.registryMetadata.gitHead,
    "the build tag must resolve to the npm gitHead");
  for (const key of ["buildCommit", "libvipsCommit"]) assert.match(component.upstream[key], COMMIT, key);
  for (const key of ["buildScriptsLicenseSHA256", "libvipsLicenseSHA256"]) assert.match(component.upstream[key], SHA256, key);
  for (const key of ["buildRepository", "buildScriptsLicenseURL", "componentNoticesURL", "libvipsRepository", "libvipsLicenseURL"]) {
    const url = new URL(component.upstream[key]);
    assert.equal(url.protocol, "https:", key);
    assert.equal(url.host, "github.com", key);
  }
  assert.ok(component.upstream.buildScriptsLicenseURL.includes(component.upstream.buildCommit));
  assert.ok(component.upstream.libvipsLicenseURL.includes(component.upstream.libvipsCommit));
  assert.equal(component.componentVersions.vips, "8.18.3");
  assert.equal(component.upstream.libvipsTag, `v${component.componentVersions.vips}`);
  assert.ok(component.shippedFiles.some(({ path }) => path.endsWith(`libvips-cpp.${component.componentVersions.vips}.dylib`)));
  for (const lgpl of component.lgplComponents) {
    assert.equal(typeof lgpl, "string");
  }
  assert.ok(component.lgplComponents.includes("libvips") && component.lgplComponents.includes("glib"));

  const obligationIds = component.obligations.map(({ id }) => id);
  assert.deepEqual(obligationIds, [
    "lgpl-licence-text",
    "component-licence-manifest",
    "per-component-copyright-and-permissive-notice-texts",
    "corresponding-source",
    "relinking-and-installation-information",
    "legal-clearance"
  ]);
  for (const obligation of component.obligations) {
    assert.deepEqual(Object.keys(obligation).sort(), ["detail", "id", "status"]);
    assert.ok(["material-bound", "open"].includes(obligation.status), obligation.id);
    assert.ok(obligation.detail.length >= 40 && obligation.detail.length <= 600, obligation.id);
    assert.doesNotMatch(obligation.detail, /cleared|satisfied|compliant|resolved/iu,
      `${obligation.id} must not read as a closed legal conclusion`);
  }
  const open = component.obligations.filter(({ status }) => status === "open").map(({ id }) => id);
  assert.deepEqual(open, [
    "per-component-copyright-and-permissive-notice-texts",
    "corresponding-source",
    "relinking-and-installation-information",
    "legal-clearance"
  ], "the recorded binary-material gap stays open until a human closes it with retained evidence");
});

test("binary provenance hashes match the pinned lockfile and reviewed runtime inventory", async () => {
  const manifest = await readJSON("Config/ThirdPartyBinaryProvenance.json");
  const [component] = manifest.components;
  const lock = await readJSON(component.lockfile);
  const locked = lock.packages[component.lockfilePath];
  assert.ok(locked, "the component must exist in the pinned production lockfile");
  assert.equal(locked.version, component.version);
  assert.equal(locked.license, component.declaredLicense);
  assert.equal(locked.resolved, component.resolved);
  assert.equal(locked.integrity, component.integrity);
  assert.equal(locked.optional, true, "the darwin-arm64 payload is an optional platform package");

  const inventory = await readJSON("VendorRuntime.inventory.json");
  assert.equal(inventory.schemaVersion, 1);
  const entries = new Map(inventory.entries.map((entry) => [entry.path, entry]));
  const shippedPaths = component.shippedFiles.map(({ path }) => path);
  assert.deepEqual(shippedPaths, [...new Set(shippedPaths)], "shipped files are unique");
  for (const shipped of component.shippedFiles) {
    assert.deepEqual(Object.keys(shipped).sort(), ["path", "role", "sha256", "size"]);
    assert.match(shipped.sha256, SHA256, shipped.path);
    const entry = entries.get(shipped.path);
    assert.ok(entry, `${shipped.path} must be in the reviewed VendorRuntime inventory`);
    assert.equal(entry.type, "file", shipped.path);
    assert.equal(entry.size, shipped.size, shipped.path);
    assert.equal(entry.sha256, shipped.sha256, shipped.path);
  }
  const inventoryPackageFiles = inventory.entries
    .filter((entry) => entry.type === "file" && entry.path.startsWith(`${component.lockfilePath}/`))
    .map((entry) => entry.path).sort();
  assert.deepEqual([...shippedPaths].sort(), inventoryPackageFiles,
    "every shipped file of the package is accounted for, no more and no fewer");
  assert.equal(component.registryMetadata.fileCount, component.shippedFiles.length);
});

test("binary provenance licence texts match the override config and tracked bytes", async () => {
  const manifest = await readJSON("Config/ThirdPartyBinaryProvenance.json");
  const [component] = manifest.components;
  const overrides = await readJSON("Config/ThirdPartyLicenseOverrides.json");
  const override = overrides.overrides.find(({ packagePath }) => packagePath === component.lockfilePath);
  assert.ok(override, "the package keeps a reviewed licence override");
  assert.match(override.reason, /4da6d14c0d59866adfb9d8cf52bcaa53846dc4f6/u);
  assert.match(override.reason, /Config\/ThirdPartyBinaryProvenance\.json/u);
  assert.match(override.reason, /open legal gate/u);

  const runtimeMaterials = override.materials.filter(({ path }) => path !== undefined);
  assert.deepEqual(runtimeMaterials.map(({ path }) => path), [
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/README.md",
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/versions.json"
  ]);
  for (const material of runtimeMaterials) {
    const shipped = component.shippedFiles.find(({ path }) => `dsh/${path}` === material.path);
    assert.ok(shipped, material.path);
    assert.equal(material.sha256, shipped.sha256, material.path);
  }

  const trackedMaterials = override.materials.filter(({ sourcePath }) => sourcePath !== undefined);
  assert.equal(trackedMaterials.length, component.boundLicenseTexts.length);
  for (const bound of component.boundLicenseTexts) {
    assert.deepEqual(Object.keys(bound).sort(), ["describes", "normalization", "origin", "sha256", "sourcePath", "upstreamSHA256"]);
    const material = trackedMaterials.find(({ sourcePath }) => sourcePath === bound.sourcePath);
    assert.ok(material, bound.sourcePath);
    assert.deepEqual(material, {
      sourcePath: bound.sourcePath,
      origin: bound.origin,
      upstreamSHA256: bound.upstreamSHA256,
      normalization: "append-terminal-lf-v1",
      sha256: bound.sha256
    });
    assert.ok(bound.sourcePath.startsWith("Resources/ThirdPartyLicenses/"));
    const bytes = await readFile(join(project, bound.sourcePath));
    assert.equal(digest(bytes), bound.sha256, bound.sourcePath);
    assert.equal(bytes[bytes.byteLength - 1], 0x0a, bound.sourcePath);
    assert.equal(digest(bytes.subarray(0, bytes.byteLength - 1)), bound.upstreamSHA256, bound.sourcePath);
    assert.ok(!bytes.includes(0x0d) && !bytes.includes(0x00), bound.sourcePath);
  }
  const libvips = component.boundLicenseTexts.find(({ sourcePath }) => sourcePath.endsWith("libvips-8.18.3-LICENSE"));
  assert.equal(libvips.origin, component.upstream.libvipsLicenseURL);
  assert.equal(libvips.upstreamSHA256, component.upstream.libvipsLicenseSHA256);
  const libvipsText = (await readFile(join(project, libvips.sourcePath), "utf8"));
  assert.match(libvipsText, /GNU LESSER GENERAL PUBLIC LICENSE\n\s+Version 2\.1, February 1999/u);
  const lgpl3 = component.boundLicenseTexts.find(({ sourcePath }) => sourcePath.endsWith("LGPL-3.0-only-spdx-3.28.0"));
  const lgpl3Text = await readFile(join(project, lgpl3.sourcePath), "utf8");
  assert.match(lgpl3Text, /^GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n/u);
  assert.match(lgpl3Text, /\nGNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n/u,
    "the LGPL-3.0 text must carry the GPL-3.0 text it incorporates by reference");
  assert.match(lgpl3.origin, /spdx\/license-list-data\/blob\/[a-f0-9]{40}\/text\/LGPL-3\.0-only\.txt$/u);
});
