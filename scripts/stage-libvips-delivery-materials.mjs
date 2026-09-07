// Assembles one deterministic, private, verifiable delivery-material directory
// for the redistributed sharp-libvips combined binary from inputs that already
// passed their own manifest-bound verification, as declared by the
// deliveryMaterials block of Config/ThirdPartyBinaryProvenance.json:
//
// - the exact upstream source archives, patches and build-recipe files with
//   their INVENTORY.json/SHA256SUMS (verified against the corresponding-source
//   manifest);
// - the exact .crate archives with their INVENTORY.json/SHA256SUMS and the
//   complete RUST_CRATE_NOTICES.md rendered with the external notice material
//   (verified against the crate manifest and the notice-materials manifest);
// - the external notice texts with their bound provenance manifest, the other
//   tracked manifests and the accompanying-documentation statements;
// - a generated DELIVERY_INVENTORY.json, SHA256SUMS and a concise factual
//   DELIVERY_STATUS.md.
//
// Contract:
// - Every input is re-hashed while it is copied and the whole staged tree is
//   re-read and re-hashed before it is renamed into place; a failure removes
//   only the staging directory this invocation created and leaves the inputs
//   and any pre-existing sibling output untouched.
// - Archives stay opaque: nothing is extracted, built or executed. Only the
//   materials tool's bounded reader touches archive members, and only the
//   manifest-named notice members.
// - The destination must be a new directory under a private, canonical parent,
//   named as the provenance record requires. Symbolic links, hard links,
//   traversal, special files, unlisted extras and oversized trees fail closed.
// - `verify` re-checks a published directory against the tracked manifests
//   (not against copies inside the directory), rejects deletion, substitution,
//   extra files, a manifest that no longer matches, a truncated archive and
//   any edit to the generated files.
// - Existing local-fixture / non-authoritative acquisition flags are carried
//   forward truthfully. Nothing here publishes a source offer, adds a release
//   asset or asserts legal clearance.
import { createHash, randomBytes } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, rm } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest, verifyMaterials } from "./prepare-libvips-source-materials.mjs";

const USAGE = [
  "usage: stage-libvips-delivery-materials.mjs stage <provenance.json> <upstream-materials-directory> <rust-crate-materials-directory> <destination-directory>",
  "       stage-libvips-delivery-materials.mjs verify <provenance.json> <destination-directory>"
].join("\n");
const INVENTORY_NAME = "DELIVERY_INVENTORY.json";
const SUMS_NAME = "SHA256SUMS";
const STATUS_NAME = "DELIVERY_STATUS.md";
const MANIFESTS_DIRECTORY = "manifests";
const NOTICES_DIRECTORY = "notices";
const EXTERNAL_DIRECTORY = "notices/rust-external";
const UPSTREAM_DIRECTORY = "upstream-source";
const CRATES_DIRECTORY = "rust-crates";
const INVENTORY_TYPE = "fulmar-libvips-delivery-materials";
const MAXIMUM_FILES = 1024;
const MAXIMUM_DEPTH = 4;
const MAXIMUM_FILE_BYTES = 256 * 1024 * 1024;
const MAXIMUM_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAXIMUM_TEXT_BYTES = 8 * 1024 * 1024;
const MAXIMUM_STATEMENTS = 8;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const MANIFEST_PATH = /^Config\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u;
const DOCUMENT_PATH = /^docs\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md$/u;
const DIRECTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const IDENTIFIER = /^[a-z0-9][a-z0-9._+-]{0,63}$/u;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
  throw new Error(message);
}

function byCodePoint(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedString(value, minimum, maximum, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length < minimum || value.length > maximum || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded single-line string`);
  }
  return value;
}

function assertSafeRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || isAbsolute(value) || value.includes("\\") || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded POSIX relative path`);
  }
  if (value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) fail(`${label} contains an unsafe path segment`);
  return value;
}

function requireExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort(byCodePoint).join("\0") !== keys.join("\0")) {
    fail(`${label} has an unexpected shape (expected exactly: ${keys.join(", ")})`);
  }
}

async function boundedRegularBytes(path, maximumBytes, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) {
      fail(`${label} is not one bounded, unlinked regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.byteLength) !== after.size) {
      fail(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function boundedCanonicalText(path, maximumBytes, label) {
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
  const bytes = await boundedRegularBytes(path, maximumBytes, label);
  const text = bytes.toString("utf8");
  if (text.includes("\0") || text.includes("\r") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail(`${label} is not canonical UTF-8 text`);
  return { bytes, text };
}

async function requireCanonicalDirectory(path, label) {
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink()) fail(`${label} is not a real directory`);
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
  return details;
}

// A private destination parent: canonical, owned by this user and writable by
// nobody else. The staged tree is created 0700/0600 inside it.
async function requirePrivateDirectory(path, label) {
  const details = await requireCanonicalDirectory(path, label);
  if (typeof process.getuid === "function" && details.uid !== process.getuid()) fail(`${label} is not owned by the current user`);
  if ((details.mode & 0o022) !== 0) fail(`${label} is writable by other users; a private destination is required`);
}

// ---------------------------------------------------------------------------
// Provenance record and its delivery bindings

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

async function loadProvenance(provenanceArgument) {
  const provenancePath = resolve(provenanceArgument);
  const configDirectory = dirname(provenancePath);
  await requireCanonicalDirectory(configDirectory, "provenance record directory");
  const projectRoot = dirname(configDirectory);
  await requireCanonicalDirectory(projectRoot, "project root inferred from the provenance record");
  const relativePath = `${basename(configDirectory)}/${basename(provenancePath)}`;
  if (!MANIFEST_PATH.test(relativePath)) fail("provenance record must be one tracked JSON document under Config");
  const { bytes, text } = await boundedCanonicalText(provenancePath, MAXIMUM_TEXT_BYTES, "provenance record");
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail(`provenance record is not valid JSON: ${error.message}`); }
  if (!document || typeof document !== "object" || Array.isArray(document) || document.schemaVersion !== 1 || !Array.isArray(document.components)) {
    fail("provenance record has an unsupported schema");
  }
  boundedString(document.purpose, 40, 2000, "provenance record purpose");
  if (!/not legal clearance/u.test(document.purpose)) fail("provenance record purpose must state that it is not legal clearance");
  const declaring = document.components.filter((component) => component?.deliveryMaterials !== undefined);
  if (declaring.length !== 1) fail(`exactly one component must declare delivery materials (found ${declaring.length})`);
  const [component] = declaring;
  if (typeof component.id !== "string" || !IDENTIFIER.test(component.id)) fail("declaring component has an invalid id");
  boundedString(component.packageName, 3, 200, "declaring component packageName");
  boundedString(component.version, 1, 64, "declaring component version");
  assertSafeRelativePath(component.lockfilePath, "declaring component lockfilePath");
  if (!COMMIT.test(component.upstream?.buildCommit ?? "")) fail("declaring component must record its full upstream build commit");
  if (!Array.isArray(component.componentNotices) || component.componentNotices.length === 0) fail("declaring component carries no component notices");
  const materialsByComponent = new Map();
  for (const notice of component.componentNotices) {
    if (!notice || typeof notice !== "object" || typeof notice.component !== "string" || !Array.isArray(notice.materials)) fail("component notice has an unexpected shape");
    if (materialsByComponent.has(notice.component)) fail(`component notice is duplicated: ${notice.component}`);
    materialsByComponent.set(notice.component, {
      version: notice.version ?? null,
      manifestLicense: notice.manifestLicense,
      materials: notice.materials.map((material) => {
        if (!material || typeof material !== "object" || !SHA256.test(material.sha256 ?? "")) fail(`component notice material has an unexpected shape: ${notice.component}`);
        return { sourcePath: assertSafeRelativePath(material.sourcePath, `component notice material for ${notice.component}`), sha256: material.sha256 };
      })
    });
  }
  if (!Array.isArray(component.obligations) || component.obligations.some((obligation) => !["material-bound", "open"].includes(obligation?.status))) {
    fail("declaring component obligations must be material-bound or open");
  }
  const raw = component.deliveryMaterials;
  const label = `delivery materials for ${component.id}`;
  requireExactKeys(raw, ["accompanyingDocumentation", "outputDirectoryName", "purpose", "rustCrateMaterials", "rustNoticeMaterials", "sourceMaterials"], label);
  boundedString(raw.purpose, 40, 1200, `${label} purpose`);
  if (!/not legal clearance/u.test(raw.purpose)) fail(`${label} purpose must state that it is not legal clearance`);
  if (typeof raw.outputDirectoryName !== "string" || !DIRECTORY_NAME.test(raw.outputDirectoryName)) fail(`${label} outputDirectoryName is invalid`);
  const manifests = {};
  for (const key of ["sourceMaterials", "rustCrateMaterials", "rustNoticeMaterials"]) {
    const path = assertSafeRelativePath(raw[key], `${label} ${key}`);
    if (!MANIFEST_PATH.test(path)) fail(`${label} ${key} must be one tracked JSON document under Config`);
    manifests[key] = path;
  }
  if (new Set(Object.values(manifests)).size !== 3) fail(`${label} must name three distinct manifests`);
  const documentation = raw.accompanyingDocumentation;
  requireExactKeys(documentation, ["clarifications", "path", "statements"], `${label} accompanyingDocumentation`);
  const documentPath = assertSafeRelativePath(documentation.path, `${label} accompanying documentation path`);
  if (!DOCUMENT_PATH.test(documentPath)) fail(`${label} accompanying documentation must be one tracked Markdown document under docs`);
  if (!Array.isArray(documentation.statements) || documentation.statements.length === 0 || documentation.statements.length > MAXIMUM_STATEMENTS) {
    fail(`${label} must declare one to ${MAXIMUM_STATEMENTS} accompanying-documentation statements`);
  }
  if (!Array.isArray(documentation.clarifications) || documentation.clarifications.length > MAXIMUM_STATEMENTS) fail(`${label} clarifications must be a bounded array`);
  const ids = new Set();
  const statements = documentation.statements.map((entry) => {
    requireExactKeys(entry, ["basis", "component", "id", "material", "statement"], `${label} statement`);
    const id = boundedString(entry.id, 3, 64, `${label} statement id`);
    if (!IDENTIFIER.test(id) || ids.has(id)) fail(`${label} statement has a duplicate or invalid id: ${id}`);
    ids.add(id);
    const record = materialsByComponent.get(entry.component);
    if (record === undefined) fail(`${label} statement ${id} names a component without a bound notice: ${String(entry.component)}`);
    const material = record.materials.find((candidate) => candidate.sourcePath === entry.material);
    if (material === undefined) fail(`${label} statement ${id} names a material that is not bound for component ${entry.component}: ${String(entry.material)}`);
    return {
      id,
      component: entry.component,
      version: record.version,
      material,
      basis: boundedString(entry.basis, 16, 600, `${label} statement ${id} basis`),
      statement: boundedString(entry.statement, 16, 600, `${label} statement ${id} text`)
    };
  });
  const clarifications = documentation.clarifications.map((entry) => {
    requireExactKeys(entry, ["component", "id", "retainedTexts", "statement", "upstreamLabel"], `${label} clarification`);
    const id = boundedString(entry.id, 3, 64, `${label} clarification id`);
    if (!IDENTIFIER.test(id) || ids.has(id)) fail(`${label} clarification has a duplicate or invalid id: ${id}`);
    ids.add(id);
    const record = materialsByComponent.get(entry.component);
    if (record === undefined) fail(`${label} clarification ${id} names a component without a bound notice: ${String(entry.component)}`);
    if (entry.upstreamLabel !== record.manifestLicense) fail(`${label} clarification ${id} does not quote the upstream licence declaration exactly`);
    const bound = record.materials.map((material) => material.sourcePath).sort(byCodePoint);
    if (!Array.isArray(entry.retainedTexts) || [...entry.retainedTexts].sort(byCodePoint).join("\0") !== bound.join("\0")) {
      fail(`${label} clarification ${id} must name exactly the retained texts bound for component ${entry.component}`);
    }
    return {
      id,
      component: entry.component,
      version: record.version,
      upstreamLabel: record.manifestLicense,
      retainedTexts: record.materials,
      statement: boundedString(entry.statement, 16, 600, `${label} clarification ${id} text`)
    };
  });
  return {
    path: provenancePath,
    relativePath,
    projectRoot,
    sha256: sha256(bytes),
    component: {
      id: component.id,
      packageName: component.packageName,
      version: component.version,
      lockfilePath: component.lockfilePath,
      buildCommit: component.upstream.buildCommit,
      openObligations: component.obligations.filter(({ status }) => status === "open").map(({ id }) => String(id))
    },
    delivery: {
      purpose: raw.purpose,
      outputDirectoryName: raw.outputDirectoryName,
      ...manifests,
      documentation: { path: documentPath, statements, clarifications }
    }
  };
}

async function requireTrackedPath(projectRoot, relativePath, label) {
  const absolute = join(projectRoot, ...relativePath.split("/"));
  if (await realpath(absolute) !== absolute) fail(`${label} must not traverse aliases or symbolic links: ${relativePath}`);
  return absolute;
}

// Verifies both material directories against the tracked manifests and binds
// them to the provenance component. Returns everything the staged inventory
// needs, in a shape that is identical for stage and verify.
async function verifyInputs(provenance, upstreamDirectory, crateDirectory) {
  const { projectRoot, delivery } = provenance;
  const sourceManifestPath = await requireTrackedPath(projectRoot, delivery.sourceMaterials, "corresponding-source manifest");
  const crateManifestPath = await requireTrackedPath(projectRoot, delivery.rustCrateMaterials, "crate manifest");
  const noticeManifestPath = await requireTrackedPath(projectRoot, delivery.rustNoticeMaterials, "notice-materials manifest");
  const documentPath = await requireTrackedPath(projectRoot, delivery.documentation.path, "accompanying documentation");
  const upstream = await verifyMaterials(sourceManifestPath, resolve(upstreamDirectory));
  if (upstream.manifest.provenanceStatuses !== undefined) fail("sourceMaterials must name the upstream corresponding-source manifest, not a crate manifest");
  const crates = await verifyMaterials(crateManifestPath, resolve(crateDirectory), noticeManifestPath);
  if (crates.manifest.provenanceStatuses === undefined) fail("rustCrateMaterials must name a rust-crate manifest");
  const { binary } = crates.manifest;
  if (JSON.stringify(upstream.manifest.binary) !== JSON.stringify(binary)) fail("the corresponding-source manifest and the crate manifest describe different binaries");
  if (binary.packageName !== provenance.component.packageName || binary.version !== provenance.component.version || binary.buildCommit !== provenance.component.buildCommit) {
    fail("the material manifests do not describe the provenance component's package, version and build commit");
  }
  if (crates.manifest.provenanceRecord !== provenance.relativePath) {
    fail(`the crate manifest names ${crates.manifest.provenanceRecord} as its provenance record, not ${provenance.relativePath}`);
  }
  const manifestBytes = {
    provenance: await boundedRegularBytes(provenance.path, MAXIMUM_TEXT_BYTES, "provenance record"),
    sourceMaterials: await boundedRegularBytes(sourceManifestPath, MAXIMUM_TEXT_BYTES, "corresponding-source manifest"),
    rustCrateMaterials: await boundedRegularBytes(crateManifestPath, MAXIMUM_TEXT_BYTES, "crate manifest"),
    rustNoticeMaterials: await boundedRegularBytes(noticeManifestPath, MAXIMUM_TEXT_BYTES, "notice-materials manifest")
  };
  if (sha256(manifestBytes.provenance) !== provenance.sha256) fail("provenance record changed while it was being read");
  if (sha256(manifestBytes.sourceMaterials) !== upstream.manifestSHA256) fail("corresponding-source manifest changed while it was being read");
  if (sha256(manifestBytes.rustCrateMaterials) !== crates.manifestSHA256) fail("crate manifest changed while it was being read");
  if (sha256(manifestBytes.rustNoticeMaterials) !== crates.noticeMaterials.sha256) fail("notice-materials manifest changed while it was being read");
  const { bytes: documentBytes, text: documentText } = await boundedCanonicalText(documentPath, MAXIMUM_TEXT_BYTES, "accompanying documentation");
  const quoted = blockquotedStatements(documentText);
  for (const statement of delivery.documentation.statements) {
    if (!quoted.has(statement.statement)) fail(`accompanying documentation ${delivery.documentation.path} does not carry the exact statement ${statement.id}`);
  }
  const externalMaterials = [];
  const externalNames = new Set();
  for (const record of crates.noticeMaterials.records) {
    for (const material of record.materials) {
      const name = basename(material.sourcePath);
      if (externalNames.has(name)) fail(`external notice material file names collide: ${name}`);
      externalNames.add(name);
      externalMaterials.push({
        record,
        material,
        sourceAbsolute: join(projectRoot, ...material.sourcePath.split("/")),
        stagedPath: `${EXTERNAL_DIRECTORY}/${name}`
      });
    }
  }
  return { upstream, crates, manifestBytes, documentBytes, documentSHA256: sha256(documentBytes), externalMaterials };
}

// ---------------------------------------------------------------------------
// Staged layout, inventory and status record

function plannedFiles(provenance, inputs) {
  const { delivery } = provenance;
  const { upstream, crates } = inputs;
  const upstreamRoot = `${UPSTREAM_DIRECTORY}/${upstream.manifest.outputDirectoryName}`;
  const cratesRoot = `${CRATES_DIRECTORY}/${crates.manifest.outputDirectoryName}`;
  const files = [];
  for (const item of upstream.manifest.items) {
    files.push({ path: `${upstreamRoot}/${item.fileName}`, source: join(upstream.destination, item.fileName), sha256: item.sha256, size: item.size, maximumBytes: upstream.manifest.limits.maximumFileBytes });
  }
  files.push({ path: `${upstreamRoot}/INVENTORY.json`, source: join(upstream.destination, "INVENTORY.json"), sha256: upstream.inventorySHA256, size: Buffer.byteLength(upstream.inventoryText), maximumBytes: MAXIMUM_TEXT_BYTES });
  files.push({ path: `${upstreamRoot}/SHA256SUMS`, source: join(upstream.destination, "SHA256SUMS"), sha256: upstream.sumsSHA256, size: Buffer.byteLength(upstream.sumsText), maximumBytes: MAXIMUM_TEXT_BYTES });
  for (const item of crates.manifest.items) {
    files.push({ path: `${cratesRoot}/${item.fileName}`, source: join(crates.destination, item.fileName), sha256: item.sha256, size: item.size, maximumBytes: crates.manifest.limits.maximumFileBytes });
  }
  files.push({ path: `${cratesRoot}/INVENTORY.json`, source: join(crates.destination, "INVENTORY.json"), sha256: crates.inventorySHA256, size: Buffer.byteLength(crates.inventoryText), maximumBytes: MAXIMUM_TEXT_BYTES });
  files.push({ path: `${cratesRoot}/SHA256SUMS`, source: join(crates.destination, "SHA256SUMS"), sha256: crates.sumsSHA256, size: Buffer.byteLength(crates.sumsText), maximumBytes: MAXIMUM_TEXT_BYTES });
  files.push({ path: `${cratesRoot}/RUST_CRATE_NOTICES.md`, source: join(crates.destination, "RUST_CRATE_NOTICES.md"), sha256: crates.rustNoticesSHA256, size: Buffer.byteLength(crates.noticesText), maximumBytes: MAXIMUM_TEXT_BYTES * 16 });
  const manifestFile = (key, relativePath) => ({ path: `${MANIFESTS_DIRECTORY}/${basename(relativePath)}`, bytes: inputs.manifestBytes[key], sha256: sha256(inputs.manifestBytes[key]), size: inputs.manifestBytes[key].byteLength });
  files.push(manifestFile("provenance", provenance.relativePath));
  files.push(manifestFile("sourceMaterials", delivery.sourceMaterials));
  files.push(manifestFile("rustCrateMaterials", delivery.rustCrateMaterials));
  files.push(manifestFile("rustNoticeMaterials", delivery.rustNoticeMaterials));
  files.push({ path: `${NOTICES_DIRECTORY}/${basename(delivery.documentation.path)}`, bytes: inputs.documentBytes, sha256: inputs.documentSHA256, size: inputs.documentBytes.byteLength });
  for (const external of inputs.externalMaterials) {
    files.push({ path: external.stagedPath, source: external.sourceAbsolute, sha256: external.material.sha256, size: external.material.size, maximumBytes: MAXIMUM_TEXT_BYTES });
  }
  const seen = new Set();
  let total = 0;
  for (const file of files) {
    assertSafeRelativePath(file.path, "staged file path");
    if (file.path.split("/").length > MAXIMUM_DEPTH) fail(`staged file path is too deep: ${file.path}`);
    if (seen.has(file.path) || [INVENTORY_NAME, SUMS_NAME, STATUS_NAME].includes(file.path)) fail(`staged file path collides: ${file.path}`);
    seen.add(file.path);
    total += file.size;
  }
  if (files.length + 3 > MAXIMUM_FILES) fail(`delivery set exceeds ${MAXIMUM_FILES} files`);
  if (total > MAXIMUM_TOTAL_BYTES) fail(`delivery set exceeds ${MAXIMUM_TOTAL_BYTES} bytes`);
  return { files, upstreamRoot, cratesRoot, totalBytes: total };
}

function renderStatus(provenance, inputs, plan) {
  const { component, delivery } = provenance;
  const { upstream, crates } = inputs;
  const crateItems = crates.manifest.items;
  const observed = crateItems.filter((item) => item.provenanceStatus === "compiled-per-build-log");
  const approximated = crateItems.filter((item) => item.provenanceStatus === "resolved-approximation");
  const notice = crates.noticeMaterials;
  const kinds = new Map();
  for (const item of upstream.manifest.items) kinds.set(item.kind, (kinds.get(item.kind) ?? 0) + 1);
  const kindSummary = [...kinds.entries()].sort(([left], [right]) => byCodePoint(left, right)).map(([kind, count]) => `${count} ${kind}`).join(", ");
  const transport = (verified) => `${verified.transport} transport${verified.authoritative ? " (authoritative acquisition)" : " (NOT authoritative: an offline re-read of retained bytes whose digests equal the manifest pins)"}`;
  const identities = (list) => list.map((identity) => `\`${identity}\``).join(", ") || "none";
  const lines = [
    `# Delivery material preparation set: ${component.packageName} ${component.version}`,
    "",
    `This directory is a material-delivery preparation set for the redistributed combined binary \`${component.packageName}\` ${component.version} (build commit \`${component.buildCommit}\`, provenance record \`${provenance.relativePath}\` \`sha256:${provenance.sha256}\`). It was assembled by \`scripts/stage-libvips-delivery-materials.mjs\` from inputs that passed their manifest-bound verification, and every file is listed with its SHA-256 in \`${INVENTORY_NAME}\` and \`${SUMS_NAME}\`. It is not a public source offer, not a release asset and not legal clearance; no obligation recorded in the provenance record is closed by its existence.`,
    "",
    "## What is here",
    "",
    `- Upstream corresponding-source materials (\`${plan.upstreamRoot}/\`): ${upstream.manifest.items.length} items (${kindSummary}), ${upstream.manifest.totalBytes} bytes, verified against \`${delivery.sourceMaterials}\` (\`sha256:${upstream.manifestSHA256}\`); ${transport(upstream)}. Archives are opaque and unmodified.`,
    `- Rust crate materials (\`${plan.cratesRoot}/\`): ${crateItems.length} crates.io archives, ${crates.manifest.totalBytes} bytes, verified by size, SHA-256 and complete tar framing against \`${delivery.rustCrateMaterials}\` (\`sha256:${crates.manifestSHA256}\`); ${transport(crates)}.`,
    `- Complete Rust crate notices (\`${plan.cratesRoot}/RUST_CRATE_NOTICES.md\`, \`sha256:${crates.rustNoticesSHA256}\`), rendered with the version-bound external notice material of \`${delivery.rustNoticeMaterials}\` (\`sha256:${notice.sha256}\`); the external texts themselves are staged under \`${EXTERNAL_DIRECTORY}/\` with that manifest as their provenance.`,
    `- The tracked manifests this set was verified against (\`${MANIFESTS_DIRECTORY}/\`) and the accompanying-documentation statements (\`${NOTICES_DIRECTORY}/${basename(delivery.documentation.path)}\`, \`sha256:${inputs.documentSHA256}\`; ${delivery.documentation.statements.length} required statement${delivery.documentation.statements.length === 1 ? "" : "s"}).`,
    "",
    "## Status (facts, not conclusions)",
    "",
    `- Historical compilation: **observed** for ${observed.length} registry crates${crates.manifest.workspaceMembers.length === 0 ? "" : ` and the workspace packages ${crates.manifest.workspaceMembers.map((member) => `\`${member}\``).join(", ")}`}${crates.manifest.historicalBuildLog === undefined ? "" : ` in the retained job log (raw \`sha256:${crates.manifest.historicalBuildLog.rawSHA256}\`)`}; ${approximated.length} crate${approximated.length === 1 ? "" : "s"} remain approximation-only (${identities(approximated.map((item) => `${item.crateName} ${item.crateVersion}`))}). compiledInHistoricalBuild=${crates.manifest.provenanceStatuses.compiledInHistoricalBuild}.`,
    `- Incorporation into the shipped dylib: **unverified** (incorporatedIntoShippedBinary=${crates.manifest.provenanceStatuses.incorporatedIntoShippedBinary}). Observed compilation is not a linkage map; which crate code survives fat LTO and dead-stripping is not established here.`,
    `- Crate notices: exact external material for ${notice.summary.established.length} crate${notice.summary.established.length === 1 ? "" : "s"} (${identities(notice.summary.established)}); **${notice.summary.unresolved.length} remain UNRESOLVED** (${identities(notice.summary.unresolved)}) because no upstream-published licence text or copyright statement exists for those exact versions — nothing is rendered for them and none is asserted.`,
    `- Open items this set does not resolve (provenance obligations still open: ${component.openObligations.map((id) => `\`${id}\``).join(", ") || "none"}): the unresolved crate notices above; the mechanism and duration by which corresponding source is made available; relinking and Installation Information under Developer ID signing; legal clearance.`,
    `- No source offer is published, no release asset is defined and no hosting location is chosen by this directory; its existence infers nothing about clearance.`,
    ""
  ];
  return lines.join("\n");
}

function renderInventory(provenance, inputs, plan, statusSHA256, statusSize) {
  const { component, delivery } = provenance;
  const { upstream, crates } = inputs;
  const notice = crates.noticeMaterials;
  const files = [
    ...plan.files.map((file) => ({ path: file.path, size: file.size, sha256: file.sha256 })),
    { path: STATUS_NAME, size: statusSize, sha256: statusSHA256 }
  ].sort((left, right) => byCodePoint(left.path, right.path));
  const inventory = {
    schemaVersion: 1,
    inventoryType: INVENTORY_TYPE,
    generator: "scripts/stage-libvips-delivery-materials.mjs",
    purpose: delivery.purpose,
    binary: crates.manifest.binary,
    component: { id: component.id, packageName: component.packageName, version: component.version, lockfilePath: component.lockfilePath, buildCommit: component.buildCommit, openObligations: component.openObligations },
    provenanceRecord: { path: provenance.relativePath, sha256: provenance.sha256, stagedPath: `${MANIFESTS_DIRECTORY}/${basename(provenance.relativePath)}` },
    manifests: {
      sourceMaterials: { path: delivery.sourceMaterials, sha256: upstream.manifestSHA256, stagedPath: `${MANIFESTS_DIRECTORY}/${basename(delivery.sourceMaterials)}` },
      rustCrateMaterials: { path: delivery.rustCrateMaterials, sha256: crates.manifestSHA256, stagedPath: `${MANIFESTS_DIRECTORY}/${basename(delivery.rustCrateMaterials)}` },
      rustNoticeMaterials: { path: delivery.rustNoticeMaterials, sha256: notice.sha256, stagedPath: `${MANIFESTS_DIRECTORY}/${basename(delivery.rustNoticeMaterials)}` }
    },
    upstreamSource: {
      directory: plan.upstreamRoot,
      manifestSHA256: upstream.manifestSHA256,
      transport: upstream.transport,
      authoritative: upstream.authoritative,
      itemCount: upstream.manifest.items.length,
      totalBytes: upstream.manifest.totalBytes,
      inventorySHA256: upstream.inventorySHA256,
      sumsSHA256: upstream.sumsSHA256,
      items: upstream.manifest.items.map((item) => ({ id: item.id, kind: item.kind, fileName: item.fileName, size: item.size, sha256: item.sha256 }))
    },
    rustCrates: {
      directory: plan.cratesRoot,
      manifestSHA256: crates.manifestSHA256,
      transport: crates.transport,
      authoritative: crates.authoritative,
      itemCount: crates.manifest.items.length,
      totalBytes: crates.manifest.totalBytes,
      inventorySHA256: crates.inventorySHA256,
      sumsSHA256: crates.sumsSHA256,
      rustNoticesSHA256: crates.rustNoticesSHA256,
      historicalBuildProvenance: crates.manifest.provenanceStatuses,
      ...(crates.manifest.historicalBuildLog === undefined ? {} : { historicalBuildLog: crates.manifest.historicalBuildLog }),
      observedRegistryCrates: crates.manifest.items.filter((item) => item.provenanceStatus === "compiled-per-build-log").length,
      approximationOnlyCrates: crates.manifest.items.filter((item) => item.provenanceStatus === "resolved-approximation").map((item) => `${item.crateName} ${item.crateVersion}`),
      workspaceMembers: crates.manifest.workspaceMembers,
      noticeMaterials: { manifestSHA256: notice.sha256, researchedOn: notice.researchedOn, established: notice.summary.established, unresolved: notice.summary.unresolved },
      items: crates.manifest.items.map((item) => ({ id: item.id, crateName: item.crateName, crateVersion: item.crateVersion, fileName: item.fileName, size: item.size, sha256: item.sha256, provenanceStatus: item.provenanceStatus, noticeStatus: item.noticeStatus }))
    },
    externalNoticeMaterials: inputs.externalMaterials.map(({ record, material, stagedPath }) => ({
      crate: record.identity,
      status: record.status,
      kind: material.kind,
      sourcePath: material.sourcePath,
      stagedPath,
      sha256: material.sha256,
      size: material.size,
      upstreamSHA256: material.upstreamSHA256,
      upstreamSize: material.upstreamSize,
      origin: material.origin,
      normalization: material.normalization,
      retrievedOn: material.retrievedOn
    })),
    unresolvedNotices: notice.records.filter((record) => record.status === "unresolved").map((record) => ({
      crate: record.identity, licenseExpression: record.licenseExpression, crateSHA256: record.crateSHA256, connection: record.connection, missingEvidence: record.unresolved.missingEvidence
    })),
    accompanyingDocumentation: {
      path: delivery.documentation.path,
      stagedPath: `${NOTICES_DIRECTORY}/${basename(delivery.documentation.path)}`,
      sha256: inputs.documentSHA256,
      statements: delivery.documentation.statements.map(({ id, component: name, version, material, basis, statement }) => ({ id, component: name, version, material, basis, statement })),
      clarifications: delivery.documentation.clarifications.map(({ id, component: name, version, upstreamLabel, retainedTexts, statement }) => ({ id, component: name, version, upstreamLabel, retainedTexts, statement }))
    },
    status: {
      kind: "material-delivery-preparation-set",
      historicalCompilation: crates.manifest.provenanceStatuses.compiledInHistoricalBuild,
      dylibIncorporation: crates.manifest.provenanceStatuses.incorporatedIntoShippedBinary,
      unresolvedNoticeCount: notice.summary.unresolved.length,
      openObligations: component.openObligations,
      statement: "A material-delivery preparation set assembled from verified inputs. Historical compilation is observed, dylib incorporation is unverified, the listed crate notices remain unresolved, and no legal clearance or public source offer is inferred from this directory's existence."
    },
    fileCount: files.length,
    totalBytes: files.reduce((total, file) => total + file.size, 0),
    files
  };
  return `${JSON.stringify(inventory, null, 2)}\n`;
}

function renderSums(entries) {
  return `${[...entries].sort((left, right) => byCodePoint(left.path, right.path)).map((entry) => `${entry.sha256}  ${entry.path}`).join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Staging

async function writeExclusive(root, relativePath, bytes) {
  const segments = relativePath.split("/");
  let directory = root;
  for (const segment of segments.slice(0, -1)) {
    directory = join(directory, segment);
    await mkdir(directory, { mode: 0o700, recursive: false }).catch((error) => { if (error?.code !== "EEXIST") throw error; });
  }
  const handle = await open(join(root, ...segments), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectories(root) {
  const handle = await open(root, constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isDirectory()) await syncDirectories(join(root, entry.name));
  }
}

// Walks one published or staged tree: only real directories and unlinked
// regular files, bounded in depth and count, returned as relative paths.
async function walkTree(root, label, expected) {
  const found = new Map();
  const expectedPaths = expected === undefined ? null : [...expected.keys()];
  let entries = 0;
  async function visit(directory, relative, depth) {
    if (depth > MAXIMUM_DEPTH) fail(`${label} is nested too deeply: ${relative}`);
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((left, right) => byCodePoint(left.name, right.name))) {
      entries += 1;
      if (entries > MAXIMUM_FILES * MAXIMUM_DEPTH) fail(`${label} carries more than ${MAXIMUM_FILES * MAXIMUM_DEPTH} filesystem entries`);
      const path = join(directory, entry.name);
      const details = await lstat(path);
      const relativePath = relative === "" ? entry.name : `${relative}/${entry.name}`;
      if (details.isSymbolicLink()) fail(`${label} carries a symbolic link: ${relativePath}`);
      if (details.isDirectory()) {
        if (expectedPaths !== null && !expectedPaths.some((path) => path.startsWith(`${relativePath}/`))) fail(`${label} carries an unlisted directory: ${relativePath}`);
        await visit(path, relativePath, depth + 1);
      } else if (details.isFile()) {
        if (details.nlink !== 1) fail(`${label} carries a hard-linked file: ${relativePath}`);
        found.set(relativePath, details.size);
        if (found.size > MAXIMUM_FILES) fail(`${label} carries more than ${MAXIMUM_FILES} files`);
      } else {
        fail(`${label} carries a special file: ${relativePath}`);
      }
    }
  }
  await visit(root, "", 1);
  return found;
}

async function hashTree(root, expected, label) {
  const found = await walkTree(root, label, expected);
  const expectedPaths = [...expected.keys()].sort(byCodePoint);
  const foundPaths = [...found.keys()].sort(byCodePoint);
  for (const path of foundPaths) if (!expected.has(path)) fail(`${label} carries an unlisted file: ${path}`);
  for (const path of expectedPaths) if (!found.has(path)) fail(`${label} is missing a listed file: ${path}`);
  for (const path of expectedPaths) {
    const entry = expected.get(path);
    if (found.get(path) !== entry.size) fail(`${label} file size drifted: ${path}`);
    const bytes = await boundedRegularBytes(join(root, ...path.split("/")), Math.max(entry.size, 1), `${label} file ${path}`);
    if (sha256(bytes) !== entry.sha256) fail(`${label} file SHA-256 drifted: ${path}`);
  }
}

async function stage(provenanceArgument, upstreamArgument, crateArgument, destinationArgument) {
  const provenance = await loadProvenance(provenanceArgument);
  const destination = resolve(destinationArgument);
  const parent = dirname(destination);
  await requirePrivateDirectory(parent, "destination parent directory");
  if (basename(destination) !== provenance.delivery.outputDirectoryName) fail(`destination must be named ${provenance.delivery.outputDirectoryName} as the provenance record requires`);
  try {
    await lstat(destination);
    fail("destination already exists; verify it or remove it deliberately instead of overwriting");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const inputs = await verifyInputs(provenance, upstreamArgument, crateArgument);
  for (const directory of [inputs.upstream.destination, inputs.crates.destination]) {
    if (directory === destination || directory.startsWith(`${destination}/`) || destination.startsWith(`${directory}/`)) fail("destination must not overlap an input directory");
  }
  const plan = plannedFiles(provenance, inputs);
  const staging = join(parent, `.${provenance.delivery.outputDirectoryName}.staging.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: 0o700 });
  let published = false;
  try {
    const expected = new Map();
    for (const file of plan.files) {
      const bytes = file.bytes ?? await boundedRegularBytes(file.source, file.maximumBytes, `input ${file.path}`);
      if (bytes.byteLength !== file.size || sha256(bytes) !== file.sha256) fail(`input drifted between verification and staging: ${file.path}`);
      await writeExclusive(staging, file.path, bytes);
      expected.set(file.path, { size: file.size, sha256: file.sha256 });
      process.stderr.write(`staged ${file.path} (${file.size} bytes, sha256:${file.sha256})\n`);
    }
    const statusText = renderStatus(provenance, inputs, plan);
    const statusBytes = Buffer.from(statusText, "utf8");
    await writeExclusive(staging, STATUS_NAME, statusBytes);
    expected.set(STATUS_NAME, { size: statusBytes.byteLength, sha256: sha256(statusBytes) });
    const inventoryText = renderInventory(provenance, inputs, plan, sha256(statusBytes), statusBytes.byteLength);
    const inventoryBytes = Buffer.from(inventoryText, "utf8");
    await writeExclusive(staging, INVENTORY_NAME, inventoryBytes);
    expected.set(INVENTORY_NAME, { size: inventoryBytes.byteLength, sha256: sha256(inventoryBytes) });
    const sumsBytes = Buffer.from(renderSums([...expected.entries()].map(([path, entry]) => ({ path, sha256: entry.sha256 }))), "utf8");
    await writeExclusive(staging, SUMS_NAME, sumsBytes);
    expected.set(SUMS_NAME, { size: sumsBytes.byteLength, sha256: sha256(sumsBytes) });
    // Every output is re-read and re-hashed before publication.
    await hashTree(staging, expected, "staged delivery set");
    await syncDirectories(staging);
    await rename(staging, destination);
    published = true;
    process.stderr.write(`published ${expected.size} files (${plan.totalBytes + statusBytes.byteLength + inventoryBytes.byteLength + sumsBytes.byteLength} bytes) to ${destination}; ${INVENTORY_NAME} sha256:${sha256(inventoryBytes)}; ${SUMS_NAME} sha256:${sha256(sumsBytes)}; upstream ${inputs.upstream.transport}${inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${inputs.crates.transport}${inputs.crates.authoritative ? "" : " (NOT authoritative)"}; unresolved notices ${inputs.crates.noticeMaterials.summary.unresolved.length}\n`);
  } finally {
    if (!published) await rm(staging, { recursive: true, force: true });
  }
}

async function verify(provenanceArgument, destinationArgument) {
  const provenance = await loadProvenance(provenanceArgument);
  const destination = resolve(destinationArgument);
  await requireCanonicalDirectory(destination, "destination");
  if (basename(destination) !== provenance.delivery.outputDirectoryName) fail(`destination must be named ${provenance.delivery.outputDirectoryName}`);
  const found = await walkTree(destination, "delivery set");
  if (!found.has(INVENTORY_NAME) || !found.has(SUMS_NAME) || !found.has(STATUS_NAME)) fail("delivery set is missing its inventory, checksum list or status record");
  const inventoryBytes = await boundedRegularBytes(join(destination, INVENTORY_NAME), MAXIMUM_TEXT_BYTES, "delivery inventory");
  let inventory;
  try { inventory = JSON.parse(inventoryBytes.toString("utf8")); }
  catch { fail("delivery inventory is not valid JSON"); }
  if (inventory?.inventoryType !== INVENTORY_TYPE || inventory.schemaVersion !== 1 || !Array.isArray(inventory.files)
      || inventory.provenanceRecord?.sha256 !== provenance.sha256 || inventory.component?.id !== provenance.component.id) {
    fail("delivery inventory does not describe this provenance record");
  }
  // The nested material directories are located from the TRACKED manifests and
  // verified against them (never against the copies inside the set), so a
  // stale or relabelled set is rejected.
  const sourceManifest = await loadManifest(await requireTrackedPath(provenance.projectRoot, provenance.delivery.sourceMaterials, "corresponding-source manifest"));
  const crateManifest = await loadManifest(await requireTrackedPath(provenance.projectRoot, provenance.delivery.rustCrateMaterials, "crate manifest"));
  const inputs = await verifyInputs(provenance,
    join(destination, UPSTREAM_DIRECTORY, sourceManifest.manifest.outputDirectoryName),
    join(destination, CRATES_DIRECTORY, crateManifest.manifest.outputDirectoryName));
  const plan = plannedFiles(provenance, inputs);
  const expected = new Map(plan.files.map((file) => [file.path, { size: file.size, sha256: file.sha256 }]));
  const statusBytes = await boundedRegularBytes(join(destination, STATUS_NAME), MAXIMUM_TEXT_BYTES, "delivery status record");
  const statusText = renderStatus(provenance, inputs, plan);
  if (statusBytes.toString("utf8") !== statusText) fail("delivery status record drifted from the verified inputs");
  expected.set(STATUS_NAME, { size: statusBytes.byteLength, sha256: sha256(statusBytes) });
  const inventoryText = renderInventory(provenance, inputs, plan, sha256(statusBytes), statusBytes.byteLength);
  if (inventoryBytes.toString("utf8") !== inventoryText) fail("delivery inventory drifted from the verified inputs");
  expected.set(INVENTORY_NAME, { size: inventoryBytes.byteLength, sha256: sha256(inventoryBytes) });
  const sumsBytes = await boundedRegularBytes(join(destination, SUMS_NAME), MAXIMUM_TEXT_BYTES, "delivery checksum list");
  const sumsText = renderSums([...expected.entries()].map(([path, entry]) => ({ path, sha256: entry.sha256 })));
  if (sumsBytes.toString("utf8") !== sumsText) fail("delivery checksum list drifted from the verified files");
  expected.set(SUMS_NAME, { size: sumsBytes.byteLength, sha256: sha256(sumsBytes) });
  await hashTree(destination, expected, "delivery set");
  process.stderr.write(`verified ${expected.size} files in ${destination}; ${INVENTORY_NAME} sha256:${sha256(inventoryBytes)}; upstream ${inputs.upstream.transport}${inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${inputs.crates.transport}${inputs.crates.authoritative ? "" : " (NOT authoritative)"}; unresolved notices ${inputs.crates.noticeMaterials.summary.unresolved.length}; dylib incorporation ${inputs.crates.manifest.provenanceStatuses.incorporatedIntoShippedBinary}\n`);
}

function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  const [command, ...operands] = process.argv.slice(2);
  if (operands.some((operand) => typeof operand !== "string" || operand.length === 0 || operand.startsWith("--"))) fail(USAGE);
  if (command === "stage" && operands.length === 4) {
    await stage(...operands);
  } else if (command === "verify" && operands.length === 2) {
    await verify(...operands);
  } else {
    fail(USAGE);
  }
}

export { loadProvenance, stage, verify };
