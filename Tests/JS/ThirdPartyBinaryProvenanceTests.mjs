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
    "boundLicenseTexts", "componentNotices", "componentVersions", "declaredLicense", "deliveryMaterials", "id", "integrity", "lgplComponents",
    "lockfile", "lockfilePath", "manifestDiscrepancy", "manifestLibraries", "obligations", "packageName", "registryMetadata", "resolved",
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
    "corresponding-source",
    "relinking-and-installation-information",
    "legal-clearance"
  ], "the recorded binary-material gaps stay open until a human closes them with retained evidence");
  const notices = component.obligations.find(({ id }) => id === "per-component-copyright-and-permissive-notice-texts");
  assert.equal(notices.status, "material-bound");
  assert.match(notices.detail, /29 libraries/u);
  assert.match(notices.detail, /Rust crates .* 157 observed compiling in the retained build log/u, "the notice obligation states the observed coverage");
  assert.match(notices.detail, /incorporation into the shipped dylib is not verified/u, "and names what it does not establish");
  const source = component.obligations.find(({ id }) => id === "corresponding-source");
  assert.match(source.detail, /Config\/SharpLibvipsSourceMaterials\.json/u);
  assert.match(source.detail, /no corresponding-source offer exists yet/u);
  assert.match(source.detail, /Config\/SharpLibvipsRustProvenance\.json/u);
  assert.match(source.detail, /157 observed compiling/u);
  assert.match(source.detail, /incorporation into the dylib is unverified/u);
});

test("per-component notices cover every upstream manifest library exactly once with exact tracked upstream texts", async () => {
  const manifest = await readJSON("Config/ThirdPartyBinaryProvenance.json");
  const [component] = manifest.components;
  const sourceMaterials = await readJSON("Config/SharpLibvipsSourceMaterials.json");
  const archives = new Map(sourceMaterials.items.filter(({ kind }) => kind === "source-archive").map((item) => [item.versionKey, item]));

  assert.equal(component.manifestLibraries.length, 29, "the tarball README names 29 libraries");
  assert.deepEqual(component.manifestLibraries, [...component.manifestLibraries].sort());
  assert.deepEqual(component.manifestDiscrepancy.librariesWithoutVersionKey, ["libnsgif"]);
  assert.match(component.manifestDiscrepancy.resolution, /libvips\/foreign\/libnsgif/u);
  assert.match(component.manifestDiscrepancy.resolution, /no upstream libnsgif release or commit is recorded/u);

  const names = component.componentNotices.map(({ component: name }) => name);
  assert.deepEqual(names, [...component.manifestLibraries], "one notice record per manifest library, in sorted order");
  const versionKeys = component.componentNotices.map(({ versionKey }) => versionKey).filter((key) => key !== null);
  assert.deepEqual(versionKeys.sort(), Object.keys(component.componentVersions).sort(), "every pinned version has exactly one notice record");

  const seenPaths = new Set();
  for (const notice of component.componentNotices) {
    const label = notice.component;
    assert.ok(["component", "manifestLicense", "materials", "revisionEvidence", "upstreamRepository", "upstreamRevision", "version", "versionKey"]
      .every((key) => Object.hasOwn(notice, key)), label);
    assert.ok(Object.keys(notice).every((key) => ["component", "manifestLicense", "materials", "note", "revisionEvidence", "upstreamRepository", "upstreamRevision", "version", "versionKey"].includes(key)), label);
    if (notice.versionKey === null) {
      assert.equal(notice.version, null, label);
      assert.equal(notice.component, "libnsgif");
      assert.match(notice.note, /Last updated 22 Jan 2023/u);
      assert.doesNotMatch(notice.note, /version \d/u, "no libnsgif version may be invented");
    } else {
      assert.equal(notice.version, component.componentVersions[notice.versionKey], label);
      const archive = archives.get(notice.versionKey);
      assert.ok(archive, `${label} has a pinned source archive`);
      assert.equal(archive.upstreamRevision, notice.upstreamRevision, label);
    }
    assert.match(notice.upstreamRevision, COMMIT, label);
    assert.equal(new URL(notice.upstreamRepository).protocol, "https:", label);
    assert.ok(notice.materials.length >= 1 && notice.materials.length <= 8, label);
    for (const material of notice.materials) {
      assert.deepEqual(Object.keys(material).sort(), ["archiveMember", "archiveSHA256", "describes", "normalization", "origin", "sha256", "sourcePath", "upstreamSHA256"], label);
      assert.ok(material.sourcePath.startsWith("Resources/ThirdPartyLicenses/"), material.sourcePath);
      assert.ok(!seenPaths.has(material.sourcePath), `${material.sourcePath} is bound once`);
      seenPaths.add(material.sourcePath);
      assert.equal(material.normalization, "append-terminal-lf-v1");
      const origin = new URL(material.origin);
      assert.equal(origin.protocol, "https:", material.sourcePath);
      assert.equal(origin.search, "", material.sourcePath);
      const commitPinned = /\/(?:blob|-\/blob)\/[a-f0-9]{40}\//u.test(origin.pathname);
      const archiveOrigin = sourceMaterials.items.some((item) => item.url === material.origin && item.sha256 === material.archiveSHA256);
      assert.ok(commitPinned || archiveOrigin, `${material.sourcePath} origin is a commit-pinned file or the pinned release archive`);
      if (commitPinned) assert.ok(origin.pathname.includes(notice.upstreamRevision), `${material.sourcePath} origin is pinned to the notice revision`);
      assert.ok(sourceMaterials.items.some((item) => item.kind === "source-archive" && item.sha256 === material.archiveSHA256),
        `${material.sourcePath} archive digest is one pinned source archive`);
      const bytes = await readFile(join(project, material.sourcePath));
      assert.equal(digest(bytes), material.sha256, material.sourcePath);
      assert.equal(bytes[bytes.byteLength - 1], 0x0a, material.sourcePath);
      assert.equal(digest(bytes.subarray(0, bytes.byteLength - 1)), material.upstreamSHA256, material.sourcePath);
      assert.ok(!bytes.includes(0x0d) && !bytes.includes(0x00), material.sourcePath);
      assert.ok(/copyright|licen[cs]e|permission|patent/iu.test(bytes.toString("utf8")), `${material.sourcePath} reads as a notice`);
    }
  }
  const trackedDirectory = "Resources/ThirdPartyLicenses/sharp-libvips-1.3.2";
  const { readdir } = await import("node:fs/promises");
  const tracked = (await readdir(join(project, trackedDirectory), { withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) => `${trackedDirectory}/${entry.name}`).sort();
  const subdirectories = (await readdir(join(project, trackedDirectory), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  assert.deepEqual(subdirectories, ["rust"], "only the Rust notice-material subdirectory (bound by Config/SharpLibvipsRustNoticeMaterials.json) may exist beside the component notices");
  const bound = [...seenPaths].filter((path) => path.startsWith(`${trackedDirectory}/`)).sort();
  assert.deepEqual(tracked, bound, "every tracked component notice file is bound and nothing untracked is present");
  const libvips = component.componentNotices.find(({ component: name }) => name === "libvips");
  assert.equal(libvips.materials[0].sourcePath, "Resources/ThirdPartyLicenses/libvips-8.18.3-LICENSE", "libvips reuses the package-level tracked text");
  assert.equal(libvips.materials[0].origin, component.upstream.libvipsLicenseURL);
});

// The delivery material bindings name only tracked inputs, tie every accompanying
// statement to a bound notice material, quote the acknowledgement documentation
// verbatim, and leave every obligation state exactly as it was.
test("delivery material bindings name tracked manifests, bound materials and the exact acknowledgement wording without promoting any obligation", async () => {
  const manifest = await readJSON("Config/ThirdPartyBinaryProvenance.json");
  const [component] = manifest.components;
  const delivery = component.deliveryMaterials;
  assert.deepEqual(Object.keys(delivery).sort(), ["accompanyingDocumentation", "outputDirectoryName", "purpose", "rustCrateMaterials", "rustNoticeMaterials", "sourceMaterials"]);
  assert.match(delivery.purpose, /not legal clearance/u);
  assert.match(delivery.purpose, /do not constitute a corresponding-source offer/u);
  assert.doesNotMatch(JSON.stringify(delivery), /cleared|compliant|legally (?:sufficient|satisfied)/iu);
  assert.equal(delivery.outputDirectoryName, "sharp-libvips-1.3.2-delivery-materials");
  assert.equal(delivery.sourceMaterials, "Config/SharpLibvipsSourceMaterials.json");
  assert.equal(delivery.rustCrateMaterials, "Config/SharpLibvipsRustProvenance.json");
  assert.equal(delivery.rustNoticeMaterials, "Config/SharpLibvipsRustNoticeMaterials.json");
  const source = await readJSON(delivery.sourceMaterials);
  const crates = await readJSON(delivery.rustCrateMaterials);
  const notices = await readJSON(delivery.rustNoticeMaterials);
  assert.deepEqual(crates.binary, source.binary, "both manifests describe the same binary");
  assert.equal(crates.binary.packageName, component.packageName);
  assert.equal(crates.binary.version, component.version);
  assert.equal(crates.binary.buildCommit, component.upstream.buildCommit);
  assert.equal(crates.binary.provenanceRecord, "Config/ThirdPartyBinaryProvenance.json", "the crate manifest points back at this record");
  assert.equal(notices.crateManifest, delivery.rustCrateMaterials, "the notice-materials manifest binds the same crate manifest");
  assert.equal(source.items.length, 41);
  assert.equal(crates.items.length, 159);
  assert.deepEqual(notices.summary.unresolved, ["block 0.1.6", "malloc_buf 0.0.6", "objc-foundation 0.1.1", "objc_id 0.1.1"], "the four unresolved notices stay unresolved");

  const documentation = delivery.accompanyingDocumentation;
  assert.equal(documentation.path, "docs/THIRD_PARTY_ACKNOWLEDGEMENTS.md");
  const text = await readFile(join(project, documentation.path), "utf8");
  const quoted = new Set();
  let current = [];
  for (const line of [...text.split("\n"), ""]) {
    if (line.startsWith(">")) current.push(line.slice(1).trim());
    else if (current.length > 0) { quoted.add(current.filter((part) => part.length > 0).join(" ")); current = []; }
  }
  const byComponent = new Map(component.componentNotices.map((notice) => [notice.component, notice]));
  assert.deepEqual(documentation.statements.map(({ id }) => id), ["freetype-ftl-credit", "ijg-based-in-part"]);
  for (const statement of documentation.statements) {
    assert.deepEqual(Object.keys(statement).sort(), ["basis", "component", "id", "material", "statement"]);
    const notice = byComponent.get(statement.component);
    assert.ok(notice, `${statement.id} names a bound component`);
    assert.ok(notice.materials.some(({ sourcePath }) => sourcePath === statement.material), `${statement.id} derives from a bound material`);
    assert.ok(quoted.has(statement.statement), `${statement.id} is quoted verbatim in ${documentation.path}`);
  }
  assert.equal(documentation.statements[0].statement, "Portions of this software are copyright © 2026 The FreeType Project (https://freetype.org). All rights reserved.");
  assert.equal(documentation.statements[1].statement, "This software is based in part on the work of the Independent JPEG Group.");
  assert.deepEqual(documentation.clarifications.map(({ id }) => id), ["cairo-retained-texts"]);
  const [cairo] = documentation.clarifications;
  assert.deepEqual(Object.keys(cairo).sort(), ["component", "id", "retainedTexts", "statement", "upstreamLabel"]);
  assert.equal(cairo.upstreamLabel, byComponent.get("cairo").manifestLicense);
  assert.deepEqual([...cairo.retainedTexts].sort(), byComponent.get("cairo").materials.map(({ sourcePath }) => sourcePath).sort(),
    "the cairo clarification names exactly the retained texts");
  assert.match(cairo.statement, /LGPL 2\.1 or the Mozilla Public License 1\.1/u);
  assert.match(cairo.statement, /'Mozilla Public License 2\.0' label is not the retained text/u);
  // The bindings change no obligation: the three gates stay open and the wording is unchanged.
  assert.deepEqual(component.obligations.filter(({ status }) => status === "open").map(({ id }) => id),
    ["corresponding-source", "relinking-and-installation-information", "legal-clearance"]);
  assert.equal(component.obligations.length, 6);
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
