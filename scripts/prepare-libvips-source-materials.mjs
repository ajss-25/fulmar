// Acquires and verifies the exact upstream source archives, patches and build
// recipe files that produced the redistributed sharp-libvips combined binary,
// as pinned by a reviewed manifest (Config/SharpLibvipsSourceMaterials.json).
//
// Contract:
// - Only URLs named by the manifest are fetched, over HTTPS, with at most the
//   manifest's redirect budget and only to redirect hosts the item explicitly
//   allows. Nothing is derived, discovered, or followed opportunistically.
// - Every byte is counted and hashed while streaming; the exact expected size
//   and SHA-256 must match or the run fails. Over-long responses are aborted
//   before the expected size is exceeded by more than one chunk.
// - Output is assembled in a private staging directory and renamed into place
//   only after every item verified and the inventory was written. A partial
//   failure removes the staging directory and leaves no destination.
// - Archives are kept opaque: nothing is extracted, configured, built or run.
// - `verify` re-hashes an existing destination against the manifest and fails
//   on drift, extra files, or a missing/inconsistent inventory.
// - The `local-fixture` transport exists for hermetic tests only. It reads
//   files from a directory instead of the network and is recorded in the
//   inventory as the transport, so fixture output is never mistakable for an
//   authoritative acquisition.
// - `--notice-materials <Config/…NoticeMaterials.json>` binds the version-bound
//   external notice material (or precise unresolved record) for every crate
//   whose archive carries no licence text. When given, every tracked material
//   is re-verified (bytes, digests, crate/revision binding, external
//   provenance) before its exact text is rendered, clearly distinct from the
//   archive-contained members; the inventory records the binding. Without it
//   the rendering is unchanged, and a destination rendered one way is refused
//   by a verification run the other way.
//
// The verification and rendering functions are exported for the notice
// generator and the delivery staging tool; the CLI runs only when this file is
// the entry point.
import { createHash, randomBytes } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, rm } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const USAGE = "usage: prepare-libvips-source-materials.mjs <acquire|verify> <manifest.json> <destination-directory> [--transport https|local-fixture:<directory>] [--notice-materials <notice-materials.json>]";
const MAXIMUM_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAXIMUM_ITEMS = 512;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,119}$/u;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/u;
const KINDS = new Set(["build-recipe", "patch", "source-archive", "rust-crate"]);
const CRATE_ROLES = new Set(["normal", "proc-macro", "build-only"]);
const CRATE_NAME = /^[A-Za-z0-9_-]{1,64}$/u;
const CRATE_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,64})?$/u;
const NOTICE_MEMBER = /^(?:licen[cs]e|copying|copyright|notice|patents|unlicense)(?:[._-][A-Za-z0-9._-]{0,64})?$/iu;
const INVENTORY_NAME = "INVENTORY.json";
const SUMS_NAME = "SHA256SUMS";
const RUST_NOTICES_NAME = "RUST_CRATE_NOTICES.md";
const CHUNK_BYTES = 1024 * 1024;
const MAXIMUM_CRATE_UNPACKED_BYTES = 256 * 1024 * 1024;
const MAXIMUM_TAR_ENTRIES = 50000;
const MAXIMUM_NOTICE_MEMBER_BYTES = 1024 * 1024;
const MAXIMUM_NOTICE_MEMBERS = 8;
const MAXIMUM_NOTICE_RECORDS = 64;
const MAXIMUM_NOTICE_MATERIAL_BYTES = 4 * 1024 * 1024;
const TRACKED_LICENCE_PREFIX = "Resources/ThirdPartyLicenses/";
const NOTICE_MATERIAL_KINDS = new Set(["external-upstream-file", "external-spdx-licence-text"]);
const NOTICE_NORMALIZATION = "append-terminal-lf-v1";
const CONNECTION_KINDS = new Set(["cargo-vcs-info", "version-tag"]);
const GITHUB_BLOB = /^\/([^/]+)\/([^/]+)\/blob\/([a-f0-9]{40})\/(.+)$/u;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/u;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
  throw new Error(message);
}

function boundedString(value, minimum, maximum, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length < minimum || value.length > maximum
      || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded single-line string`);
  }
  return value;
}

function boundedInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`${label} must be an integer in [${minimum}, ${maximum}]`);
  return value;
}

function cleanHTTPSURL(value, label) {
  boundedString(value, 16, 1024, label);
  let parsed;
  try { parsed = new URL(value); }
  catch { fail(`${label} is not a URL`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash
      || parsed.port !== "" || !HOST.test(parsed.hostname)) {
    fail(`${label} must be one clean HTTPS URL without credentials, port, query or fragment`);
  }
  return parsed;
}

function assertSafeRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024
      || isAbsolute(value) || value.includes("\\") || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded POSIX relative path`);
  }
  if (value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    fail(`${label} contains an unsafe path segment`);
  }
  return value;
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
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || BigInt(bytes.byteLength) !== after.size) {
      fail(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

// Reads one bounded regular file that must be canonical UTF-8 text without NUL
// or CR bytes, reachable without traversing any alias or symbolic link.
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
}

// ---------------------------------------------------------------------------
// Manifest

function validateManifest(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) fail("manifest must be a JSON object");
  if (document.schemaVersion !== 1) fail("manifest has an unsupported schema version");
  boundedString(document.purpose, 40, 2000, "manifest purpose");
  if (!/not legal clearance/u.test(document.purpose)) fail("manifest purpose must state that it is not legal clearance");
  const binary = document.binary;
  if (!binary || typeof binary !== "object" || Array.isArray(binary)) fail("manifest binary record must be an object");
  boundedString(binary.packageName, 3, 200, "binary packageName");
  boundedString(binary.version, 1, 64, "binary version");
  cleanHTTPSURL(binary.buildRepository, "binary buildRepository");
  boundedString(binary.buildTag, 1, 64, "binary buildTag");
  if (!COMMIT.test(binary.buildCommit ?? "")) fail("binary buildCommit must be one full commit");
  boundedString(binary.buildPlatform, 1, 64, "binary buildPlatform");
  assertSafeRelativePath(binary.shippedBinary, "binary shippedBinary");
  if (!SHA256.test(binary.shippedBinarySHA256 ?? "")) fail("binary shippedBinarySHA256 must be one SHA-256");
  assertSafeRelativePath(binary.provenanceRecord, "binary provenanceRecord");

  if (!FILE_NAME.test(document.outputDirectoryName ?? "")) fail("manifest outputDirectoryName is invalid");
  const limits = document.limits;
  if (!limits || typeof limits !== "object" || Array.isArray(limits)) fail("manifest limits must be an object");
  const maximumFileBytes = boundedInteger(limits.maximumFileBytes, 1, 1024 * 1024 * 1024, "limits.maximumFileBytes");
  const maximumTotalBytes = boundedInteger(limits.maximumTotalBytes, maximumFileBytes, 8 * 1024 * 1024 * 1024, "limits.maximumTotalBytes");
  const maximumRedirects = boundedInteger(limits.maximumRedirects, 0, 5, "limits.maximumRedirects");
  const requestTimeoutMilliseconds = boundedInteger(limits.requestTimeoutMilliseconds, 1000, 600000, "limits.requestTimeoutMilliseconds");

  if (!Array.isArray(document.items) || document.items.length === 0 || document.items.length > MAXIMUM_ITEMS) {
    fail(`manifest must name between 1 and ${MAXIMUM_ITEMS} items`);
  }
  const ids = new Set();
  const fileNames = new Set();
  const versionKeys = new Set();
  const crateIdentities = new Set();
  let total = 0;
  const items = document.items.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) fail("manifest item must be an object");
    const id = item.id;
    if (typeof id !== "string" || !IDENTIFIER.test(id) || ids.has(id)) fail(`manifest item has a duplicate or invalid id: ${String(id)}`);
    ids.add(id);
    if (!KINDS.has(item.kind)) fail(`manifest item has an unknown kind: ${id}`);
    const fileName = item.fileName;
    if (typeof fileName !== "string" || !FILE_NAME.test(fileName) || fileNames.has(fileName)
        || fileName === INVENTORY_NAME || fileName === SUMS_NAME) {
      fail(`manifest item has a duplicate or invalid fileName: ${id}`);
    }
    fileNames.add(fileName);
    const url = cleanHTTPSURL(item.url, `manifest item url for ${id}`);
    const size = boundedInteger(item.size, 1, maximumFileBytes, `manifest item size for ${id}`);
    total += size;
    if (!SHA256.test(item.sha256 ?? "")) fail(`manifest item sha256 is invalid: ${id}`);
    if (!Array.isArray(item.allowedRedirectHosts) || item.allowedRedirectHosts.length > 4
        || item.allowedRedirectHosts.some((host) => typeof host !== "string" || !HOST.test(host))
        || new Set(item.allowedRedirectHosts).size !== item.allowedRedirectHosts.length) {
      fail(`manifest item allowedRedirectHosts must be up to four unique lowercase hosts: ${id}`);
    }
    boundedString(item.immutability, 3, 80, `manifest item immutability for ${id}`);
    if (item.kind === "rust-crate") {
      if (typeof item.crateName !== "string" || !CRATE_NAME.test(item.crateName)) fail(`rust-crate crateName is invalid: ${id}`);
      if (typeof item.crateVersion !== "string" || !CRATE_VERSION.test(item.crateVersion)) fail(`rust-crate crateVersion is invalid: ${id}`);
      const identity = `${item.crateName} ${item.crateVersion}`;
      if (crateIdentities.has(identity)) fail(`manifest names one crate identity twice: ${identity}`);
      crateIdentities.add(identity);
      if (fileName !== `${item.crateName}-${item.crateVersion}.crate`) fail(`rust-crate fileName must be <name>-<version>.crate: ${id}`);
      if (url.hostname !== "static.crates.io" || url.pathname !== `/crates/${item.crateName}/${item.crateName}-${item.crateVersion}.crate`) {
        fail(`rust-crate url must be the exact static.crates.io path for the crate identity: ${id}`);
      }
      if (item.allowedRedirectHosts.length !== 0) fail(`rust-crate items must not allow redirects: ${id}`);
      cleanHTTPSURL(item.registry, `rust-crate registry for ${id}`);
      boundedString(item.checksumSource, 16, 400, `rust-crate checksumSource for ${id}`);
      if (!CRATE_ROLES.has(item.role)) fail(`rust-crate role must be normal, proc-macro or build-only: ${id}`);
      boundedString(item.licenseExpression, 2, 200, `rust-crate licenseExpression for ${id}`);
      if (item.provenanceStatus !== "resolved-approximation" && item.provenanceStatus !== "compiled-per-build-log") {
        fail(`rust-crate provenanceStatus must be resolved-approximation or compiled-per-build-log: ${id}`);
      }
      if (item.provenanceStatus === "compiled-per-build-log") {
        const observed = item.observedCompilation;
        if (!observed || typeof observed !== "object" || Array.isArray(observed)
            || Object.keys(observed).sort().join("\0") !== "logLine\0timestamp"
            || !Number.isSafeInteger(observed.logLine) || observed.logLine < 1
            || typeof observed.timestamp !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/u.test(observed.timestamp)) {
          fail(`rust-crate compiled-per-build-log items must carry the observed log line and timestamp: ${id}`);
        }
      } else if (item.observedCompilation !== undefined && item.observedCompilation !== null) {
        fail(`rust-crate resolved-approximation items must not carry an observed compilation record: ${id}`);
      }
      if (!Array.isArray(item.noticeMembers) || item.noticeMembers.length > MAXIMUM_NOTICE_MEMBERS) fail(`rust-crate noticeMembers must be a bounded array: ${id}`);
      const memberNames = new Set();
      for (const member of item.noticeMembers) {
        if (!member || typeof member !== "object" || Object.keys(member).sort().join("\0") !== "member\0sha256\0size") fail(`rust-crate notice member has an unexpected shape: ${id}`);
        assertSafeRelativePath(member.member, `rust-crate notice member for ${id}`);
        const segments = member.member.split("/");
        if (segments.length !== 2 || segments[0] !== `${item.crateName}-${item.crateVersion}` || !NOTICE_MEMBER.test(segments[1]) || memberNames.has(member.member)) {
          fail(`rust-crate notice member must be one unique top-level licence file of the crate: ${id}`);
        }
        memberNames.add(member.member);
        boundedInteger(member.size, 1, MAXIMUM_NOTICE_MEMBER_BYTES, `rust-crate notice member size for ${id}`);
        if (!SHA256.test(member.sha256 ?? "")) fail(`rust-crate notice member sha256 is invalid: ${id}`);
      }
      const expectedStatus = item.noticeMembers.length === 0 ? "no-licence-text-in-crate" : "crate-carries-licence-text";
      if (item.noticeStatus !== expectedStatus) fail(`rust-crate noticeStatus does not match its notice members: ${id}`);
      if (item.authors !== undefined && (!Array.isArray(item.authors) || item.authors.length > 16
          || item.authors.some((author) => typeof author !== "string" || author.length === 0 || author.length > 200 || /[\0\r\n]/u.test(author)))) {
        fail(`rust-crate authors must be a bounded list of single-line strings: ${id}`);
      }
      if (item.licenseFile !== undefined) assertSafeRelativePath(item.licenseFile, `rust-crate licenseFile for ${id}`);
    } else if (item.kind === "source-archive") {
      boundedString(item.component, 1, 64, `source-archive component for ${id}`);
      boundedString(item.versionKey, 1, 64, `source-archive versionKey for ${id}`);
      if (versionKeys.has(item.versionKey)) fail(`manifest names one version key twice: ${item.versionKey}`);
      versionKeys.add(item.versionKey);
      boundedString(item.version, 1, 64, `source-archive version for ${id}`);
      cleanHTTPSURL(item.upstreamRepository, `source-archive upstreamRepository for ${id}`);
      if (!COMMIT.test(item.upstreamRevision ?? "")) fail(`source-archive upstreamRevision must be one full commit: ${id}`);
      boundedString(item.revisionEvidence, 16, 400, `source-archive revisionEvidence for ${id}`);
      boundedString(item.recipeReference, 3, 200, `source-archive recipeReference for ${id}`);
    } else {
      boundedString(item.role, 8, 600, `manifest item role for ${id}`);
      if (item.kind === "patch") boundedString(item.component, 1, 64, `patch component for ${id}`);
    }
    return {
      id,
      kind: item.kind,
      fileName,
      url: url.href,
      host: url.hostname,
      size,
      sha256: item.sha256,
      allowedRedirectHosts: [...item.allowedRedirectHosts],
      immutability: item.immutability,
      ...(item.kind === "source-archive" ? {
        component: item.component,
        versionKey: item.versionKey,
        version: item.version,
        upstreamRepository: item.upstreamRepository,
        upstreamRevision: item.upstreamRevision
      } : item.kind === "rust-crate" ? {
        crateName: item.crateName,
        crateVersion: item.crateVersion,
        registry: item.registry,
        role: item.role,
        licenseExpression: item.licenseExpression,
        provenanceStatus: item.provenanceStatus,
        ...(item.provenanceStatus === "compiled-per-build-log" ? { observedCompilation: { logLine: item.observedCompilation.logLine, timestamp: item.observedCompilation.timestamp } } : {}),
        noticeStatus: item.noticeStatus,
        noticeMembers: item.noticeMembers.map((member) => ({ member: member.member, size: member.size, sha256: member.sha256 })),
        ...(item.authors === undefined ? {} : { authors: [...item.authors] })
      } : { role: item.role, ...(item.component === undefined ? {} : { component: item.component }) })
    };
  });
  if (total > maximumTotalBytes) fail("manifest items exceed limits.maximumTotalBytes");
  if (!Array.isArray(document.unretained) || document.unretained.length === 0) fail("manifest must record a non-empty unretained array");
  if (document.buildTimeModifications !== undefined && !Array.isArray(document.buildTimeModifications)) fail("manifest buildTimeModifications must be an array");
  const hasCrates = items.some((item) => item.kind === "rust-crate");
  let provenanceStatuses;
  let historicalBuildLog;
  let workspaceMembers = [];
  if (hasCrates) {
    const categories = document.categories;
    if (!categories || typeof categories !== "object" || Array.isArray(categories)) fail("a manifest with rust-crate items must record provenance categories");
    provenanceStatuses = {};
    const compiledItems = items.filter((item) => item.kind === "rust-crate" && item.provenanceStatus === "compiled-per-build-log");
    const compiledStatus = categories.compiledInHistoricalBuild?.status;
    if (compiledStatus !== "unverified" && compiledStatus !== "observed") fail("categories.compiledInHistoricalBuild.status must be unverified or observed");
    if (compiledStatus === "unverified" && compiledItems.length > 0) {
      fail("categories.compiledInHistoricalBuild cannot be unverified while items claim compiled-per-build-log");
    }
    if (compiledStatus === "observed") {
      const log = document.historicalBuildEvidence?.jobLog;
      const observed = document.historicalBuildEvidence?.observedCompilation;
      if (!log || typeof log !== "object" || !SHA256.test(log.rawSHA256 ?? "") || !Number.isSafeInteger(log.rawBytes) || log.rawBytes < 1
          || !Number.isSafeInteger(log.lines) || log.lines < 1) {
        fail("categories.compiledInHistoricalBuild observed requires historicalBuildEvidence.jobLog with the raw log digest, size and line count");
      }
      if (!observed || typeof observed !== "object" || observed.registryCrateCount !== compiledItems.length || compiledItems.length === 0
          || !Array.isArray(observed.approximationNotObserved) || !Array.isArray(observed.observedNotInApproximation) || observed.observedNotInApproximation.length !== 0) {
        fail("categories.compiledInHistoricalBuild observed requires an observedCompilation record whose registry crate count equals the compiled-per-build-log items and which lists no observed crate outside the manifest");
      }
      const notObserved = new Set(observed.approximationNotObserved.map((entry) => `${entry?.name} ${entry?.version}`));
      const approximated = items.filter((item) => item.kind === "rust-crate" && item.provenanceStatus === "resolved-approximation").map((item) => `${item.crateName} ${item.crateVersion}`);
      if (approximated.length !== notObserved.size || approximated.some((identity) => !notObserved.has(identity))) {
        fail("categories.compiledInHistoricalBuild observed requires approximationNotObserved to name exactly the resolved-approximation items");
      }
      for (const item of compiledItems) {
        if (item.observedCompilation.logLine > log.lines) fail(`observed compilation log line exceeds the retained log length: ${item.id}`);
      }
      historicalBuildLog = { rawSHA256: log.rawSHA256, rawBytes: log.rawBytes, lines: log.lines };
    }
    provenanceStatuses.compiledInHistoricalBuild = compiledStatus;
    const incorporatedStatus = categories.incorporatedIntoShippedBinary?.status;
    if (incorporatedStatus !== "unverified") fail("categories.incorporatedIntoShippedBinary.status must remain unverified: observed compilation is not a linkage map");
    provenanceStatuses.incorporatedIntoShippedBinary = incorporatedStatus;
    // Workspace packages are recorded for the notice rendering only; they are
    // never items and never counted as registry crates.
    const members = categories.resolvedForTargetApproximation?.workspaceMembers;
    if (members !== undefined) {
      if (!Array.isArray(members) || members.length > 16 || members.some((member) => typeof member !== "string" || member.trim() !== member || member.length === 0 || member.length > 400 || /[\0\r\n]/u.test(member))) {
        fail("categories.resolvedForTargetApproximation.workspaceMembers must be a bounded list of single-line strings");
      }
      workspaceMembers = [...members];
    }
  }
  return {
    binary: {
      packageName: binary.packageName,
      version: binary.version,
      buildRepository: binary.buildRepository,
      buildTag: binary.buildTag,
      buildCommit: binary.buildCommit,
      buildPlatform: binary.buildPlatform,
      shippedBinary: binary.shippedBinary,
      shippedBinarySHA256: binary.shippedBinarySHA256
    },
    provenanceRecord: binary.provenanceRecord,
    outputDirectoryName: document.outputDirectoryName,
    limits: { maximumFileBytes, maximumTotalBytes, maximumRedirects, requestTimeoutMilliseconds },
    items,
    totalBytes: total,
    provenanceStatuses,
    ...(historicalBuildLog === undefined ? {} : { historicalBuildLog }),
    workspaceMembers
  };
}

// ---------------------------------------------------------------------------
// Version-bound external notice material for crates whose archive carries no
// licence text (Config/…NoticeMaterials.json). The manifest must name exactly
// those crates, bind each record to the pinned .crate digest and licence
// expression, connect the archive to one exact upstream revision, and either
// bind tracked external material proven equal to the immutable upstream bytes
// plus one terminal LF, or carry one precise unresolved record. External
// material is never presented as an archive member; an archive-contained
// notice is recorded separately and is re-verified against the archive itself
// when the crates are read.

function cleanGitHubBlob(value, label) {
  const url = cleanHTTPSURL(value, label);
  if (url.hostname !== "github.com") fail(`${label} must be a github.com file URL pinned to one commit`);
  const pinned = GITHUB_BLOB.exec(url.pathname);
  if (!pinned) fail(`${label} must be pinned to one full commit, not a branch or tag`);
  return { href: url.href, repository: `https://github.com/${pinned[1]}/${pinned[2]}`, revision: pinned[3], path: pinned[4] };
}

function requireKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== keys.join("\0")) {
    fail(`${label} has an unexpected shape (expected exactly: ${keys.join(", ")})`);
  }
}

export async function loadRustNoticeMaterials(noticeManifestArgument, crateManifest, crateManifestPath) {
  const noticeManifestPath = resolve(noticeManifestArgument);
  const configDirectory = dirname(noticeManifestPath);
  await requireCanonicalDirectory(configDirectory, "notice-materials manifest directory");
  const projectRoot = dirname(configDirectory);
  await requireCanonicalDirectory(projectRoot, "project root inferred from the notice-materials manifest");
  const { bytes, text } = await boundedCanonicalText(noticeManifestPath, MAXIMUM_MANIFEST_BYTES, "notice-materials manifest");
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail(`notice-materials manifest is not valid JSON: ${error.message}`); }
  requireKeys(document, ["crateManifest", "purpose", "records", "researchedOn", "schemaVersion", "summary"], "notice-materials manifest");
  if (document.schemaVersion !== 1) fail("notice-materials manifest has an unsupported schema version");
  boundedString(document.purpose, 40, 2000, "notice-materials manifest purpose");
  if (!/not legal clearance/u.test(document.purpose) || !/never a member of the original archive/u.test(document.purpose)) {
    fail("notice-materials manifest purpose must state that it is not legal clearance and that external material was never an archive member");
  }
  if (/cleared|compliant|legally (?:sufficient|satisfied)/iu.test(text)) fail("notice-materials manifest must not read as a legal conclusion");
  const crateManifestReference = assertSafeRelativePath(document.crateManifest, "notice-materials crateManifest");
  const referenced = join(projectRoot, ...crateManifestReference.split("/"));
  const boundCrateManifest = resolve(crateManifestPath);
  if (referenced !== boundCrateManifest || await realpath(boundCrateManifest) !== boundCrateManifest) {
    fail(`notice-materials manifest binds ${crateManifestReference}, which is not the crate manifest being processed`);
  }
  if (!ISO_DATE.test(document.researchedOn ?? "")) fail("notice-materials manifest researchedOn must be one ISO date");
  const summary = document.summary;
  requireKeys(summary, ["established", "unresolved"], "notice-materials manifest summary");
  if (!Array.isArray(summary.established) || !Array.isArray(summary.unresolved)
      || [...summary.established, ...summary.unresolved].some((entry) => typeof entry !== "string")) {
    fail("notice-materials manifest summary must list established and unresolved crate identities");
  }
  const withoutText = crateManifest.items.filter((item) => item.kind === "rust-crate" && item.noticeStatus === "no-licence-text-in-crate");
  const expected = new Map(withoutText.map((item) => [`${item.crateName} ${item.crateVersion}`, item]));
  if (!Array.isArray(document.records) || document.records.length > MAXIMUM_NOTICE_RECORDS) fail("notice-materials manifest records must be a bounded array");
  const identities = document.records.map((record) => `${record?.crateName} ${record?.crateVersion}`);
  const sortedExpected = [...expected.keys()].sort();
  if (identities.join("\0") !== sortedExpected.join("\0")) {
    fail(`notice-materials manifest must cover exactly the crates without archive licence text, once each, in sorted order (expected: ${sortedExpected.join(", ") || "none"}; found: ${identities.join(", ") || "none"})`);
  }
  if ([...summary.established, ...summary.unresolved].sort().join("\0") !== sortedExpected.join("\0")) {
    fail("notice-materials manifest summary does not partition the covered crates into established and unresolved");
  }
  const boundPaths = new Set();
  const records = [];
  for (const record of document.records) {
    const identity = `${record.crateName} ${record.crateVersion}`;
    const item = expected.get(identity);
    const label = `notice material for ${identity}`;
    const keys = Object.keys(record).sort();
    const allowed = ["archiveNotice", "connection", "crateName", "crateSHA256", "crateVersion", "licenseExpression", "materials", "status", "unresolved"];
    if (keys.some((key) => !allowed.includes(key))) fail(`${label} carries an unexpected field`);
    if (record.crateSHA256 !== item.sha256) fail(`${label} is not bound to the pinned crate archive digest`);
    if (record.licenseExpression !== item.licenseExpression) fail(`${label} does not carry the crate's licence expression`);
    if (record.status !== "established" && record.status !== "unresolved") fail(`${label} status must be established or unresolved`);
    if (!summary[record.status].includes(identity)) fail(`${label} summary entry does not match its status`);
    const connection = record.connection;
    if (!connection || typeof connection !== "object" || Array.isArray(connection) || !CONNECTION_KINDS.has(connection.kind)) {
      fail(`${label} connection kind must be cargo-vcs-info or version-tag`);
    }
    requireKeys(connection, connection.kind === "cargo-vcs-info"
      ? ["kind", "pathInVcs", "repository", "revision", "revisionEvidence"]
      : ["kind", "repository", "revision", "revisionEvidence"], `${label} connection`);
    const repositoryURL = cleanHTTPSURL(connection.repository, `${label} connection repository`);
    if (repositoryURL.hostname !== "github.com" || !/^\/[^/]+\/[^/]+$/u.test(repositoryURL.pathname)) fail(`${label} connection repository must be one github.com repository`);
    const repository = repositoryURL.href.replace(/\/$/u, "");
    if (!COMMIT.test(connection.revision ?? "")) fail(`${label} connection revision must be one full commit`);
    boundedString(connection.revisionEvidence, 80, 2000, `${label} connection evidence`);
    if (!connection.revisionEvidence.includes(`"${record.crateVersion}"`)) fail(`${label} connection evidence must cite the exact version at the revision`);
    if (connection.kind === "cargo-vcs-info") {
      assertSafeRelativePath(connection.pathInVcs, `${label} connection pathInVcs`);
      if (!/\.cargo_vcs_info\.json \(sha256 [a-f0-9]{64}\) records git sha1 [a-f0-9]{40}/u.test(connection.revisionEvidence)
          || !connection.revisionEvidence.includes(connection.revision) || !/byte-identical/u.test(connection.revisionEvidence)) {
        fail(`${label} cargo-vcs-info connection must cite the archive's .cargo_vcs_info.json and byte-identical members at the revision`);
      }
    }
    const materials = [];
    let archiveNotice;
    let unresolved;
    if (record.status === "established") {
      if (record.unresolved !== undefined) fail(`${label} established record cannot carry an unresolved record`);
      if (!Array.isArray(record.materials) || record.materials.length === 0 || record.materials.length > MAXIMUM_NOTICE_MEMBERS) {
        fail(`${label} established record must bind one to ${MAXIMUM_NOTICE_MEMBERS} materials`);
      }
      if (record.archiveNotice !== undefined) {
        const notice = record.archiveNotice;
        requireKeys(notice, ["member", "memberSHA256", "note", "text"], `${label} archive notice`);
        assertSafeRelativePath(notice.member, `${label} archive notice member`);
        if (!notice.member.startsWith(`${record.crateName}-${record.crateVersion}/`)) fail(`${label} archive notice member must be inside the crate root`);
        if (!SHA256.test(notice.memberSHA256 ?? "")) fail(`${label} archive notice member digest is invalid`);
        if (typeof notice.text !== "string" || notice.text.length < 16 || notice.text.length > 4000 || notice.text.includes("\0") || notice.text.includes("\r")) {
          fail(`${label} archive notice text is not bounded text`);
        }
        boundedString(notice.note, 40, 2000, `${label} archive notice note`);
        if (!/archive-contained/u.test(notice.note)) fail(`${label} archive notice must be labelled archive-contained`);
        archiveNotice = { member: notice.member, memberSHA256: notice.memberSHA256, text: notice.text, note: notice.note };
      }
      for (const raw of record.materials) {
        requireKeys(raw, ["describes", "kind", "normalization", "origin", "retrievedOn", "sha256", "size", "sourcePath", "upstreamSHA256", "upstreamSize"], `${label} material`);
        if (!NOTICE_MATERIAL_KINDS.has(raw.kind)) fail(`${label} material kind must be labelled external`);
        const sourcePath = assertSafeRelativePath(raw.sourcePath, `${label} material sourcePath`);
        if (!sourcePath.startsWith(TRACKED_LICENCE_PREFIX) || boundPaths.has(sourcePath)) fail(`${label} material must be one unique tracked file under ${TRACKED_LICENCE_PREFIX}`);
        boundPaths.add(sourcePath);
        boundedString(raw.describes, 8, 1000, `${label} material description`);
        if (!/external to the archive/u.test(raw.describes)) fail(`${label} material must be described as external to the archive`);
        if (raw.normalization !== NOTICE_NORMALIZATION) fail(`${label} material normalization must be ${NOTICE_NORMALIZATION}`);
        if (!SHA256.test(raw.sha256 ?? "") || !SHA256.test(raw.upstreamSHA256 ?? "")) fail(`${label} material requires exact tracked and raw upstream SHA-256 values`);
        boundedInteger(raw.upstreamSize, 1, MAXIMUM_NOTICE_MATERIAL_BYTES, `${label} material upstreamSize`);
        boundedInteger(raw.size, 2, MAXIMUM_NOTICE_MATERIAL_BYTES, `${label} material size`);
        if (raw.size !== raw.upstreamSize + 1) fail(`${label} material size must equal the upstream size plus one terminal LF`);
        if (!ISO_DATE.test(raw.retrievedOn ?? "")) fail(`${label} material retrievedOn must be one ISO date`);
        const origin = cleanGitHubBlob(raw.origin, `${label} material origin`);
        if (raw.kind === "external-upstream-file") {
          if (origin.repository !== repository || origin.revision !== connection.revision) {
            fail(`${label} upstream material must come from the connected repository at the connected revision, not another repository, branch or revision`);
          }
        } else {
          if (origin.repository !== "https://github.com/spdx/license-list-data") fail(`${label} SPDX material must come from spdx/license-list-data`);
          if (origin.path !== `text/${record.licenseExpression}.txt`) fail(`${label} SPDX material must be the text of the crate's own licence expression`);
          if (archiveNotice === undefined) fail(`${label} SPDX text may only stand in for a licence the archive itself designates`);
        }
        const absolute = join(projectRoot, ...sourcePath.split("/"));
        const { bytes: materialBytes, text: materialText } = await boundedCanonicalText(absolute, MAXIMUM_NOTICE_MATERIAL_BYTES, `${label} tracked material ${sourcePath}`);
        if (materialBytes.byteLength !== raw.size) fail(`${label} tracked material size drifted: ${sourcePath}`);
        if (sha256(materialBytes) !== raw.sha256) fail(`${label} tracked material SHA-256 drifted: ${sourcePath}`);
        if (materialBytes[materialBytes.byteLength - 1] !== 0x0a || sha256(materialBytes.subarray(0, materialBytes.byteLength - 1)) !== raw.upstreamSHA256) {
          fail(`${label} tracked material no longer equals the exact upstream bytes plus one terminal LF: ${sourcePath}`);
        }
        if (!/licen[cs]e|permission/iu.test(materialText)) fail(`${label} tracked material does not read as a licence text: ${sourcePath}`);
        materials.push({
          kind: raw.kind,
          sourcePath,
          describes: raw.describes,
          origin: origin.href,
          upstreamSHA256: raw.upstreamSHA256,
          upstreamSize: raw.upstreamSize,
          normalization: raw.normalization,
          sha256: raw.sha256,
          size: raw.size,
          retrievedOn: raw.retrievedOn,
          text: materialText
        });
      }
    } else {
      if (!Array.isArray(record.materials) || record.materials.length !== 0) fail(`${label} unresolved record cannot bind material`);
      if (record.archiveNotice !== undefined) fail(`${label} unresolved record cannot carry an archive notice`);
      requireKeys(record.unresolved, ["checksPerformed", "fallbackUsed", "missingEvidence"], `${label} unresolved record`);
      boundedString(record.unresolved.missingEvidence, 80, 2000, `${label} missing evidence`);
      if (!/none is asserted/u.test(record.unresolved.missingEvidence)) fail(`${label} unresolved record must assert nothing it cannot show`);
      const checks = record.unresolved.checksPerformed;
      if (!Array.isArray(checks) || checks.length < 4 || checks.length > 32) fail(`${label} unresolved record must list at least four checks`);
      for (const check of checks) {
        requireKeys(check, ["check", "result"], `${label} unresolved check`);
        boundedString(check.check, 3, 200, `${label} unresolved check name`);
        boundedString(check.result, 3, 2000, `${label} unresolved check result`);
      }
      if (!checks.some(({ check }) => /tag|revision/u.test(check)) || !checks.some(({ check }) => /crate archive/u.test(check))) {
        fail(`${label} unresolved record must record the crate archive and upstream revision checks`);
      }
      boundedString(record.unresolved.fallbackUsed, 20, 1000, `${label} fallback`);
      unresolved = {
        missingEvidence: record.unresolved.missingEvidence,
        checksPerformed: checks.map(({ check, result }) => ({ check, result })),
        fallbackUsed: record.unresolved.fallbackUsed
      };
    }
    records.push({
      crateName: record.crateName,
      crateVersion: record.crateVersion,
      identity,
      itemId: item.id,
      crateSHA256: item.sha256,
      licenseExpression: item.licenseExpression,
      status: record.status,
      connection: {
        kind: connection.kind,
        repository,
        revision: connection.revision,
        ...(connection.pathInVcs === undefined ? {} : { pathInVcs: connection.pathInVcs }),
        revisionEvidence: connection.revisionEvidence
      },
      ...(archiveNotice === undefined ? {} : { archiveNotice }),
      materials,
      ...(unresolved === undefined ? {} : { unresolved })
    });
  }
  // Nothing unbound may sit beside the bound external material.
  for (const directory of new Set([...boundPaths].map((path) => dirname(path)))) {
    for (const entry of await readdir(join(projectRoot, ...directory.split("/")), { withFileTypes: true })) {
      const relative = `${directory}/${entry.name}`;
      if (!entry.isFile() || !boundPaths.has(relative)) fail(`unbound entry beside the tracked Rust notice material: ${relative}`);
    }
  }
  return {
    path: noticeManifestPath,
    relativePath: `${basename(configDirectory)}/${basename(noticeManifestPath)}`,
    projectRoot,
    sha256: sha256(bytes),
    researchedOn: document.researchedOn,
    summary: { established: [...summary.established], unresolved: [...summary.unresolved] },
    records
  };
}

// ---------------------------------------------------------------------------
// Bounded .crate (tar.gz) member reader. Only the notice members the manifest
// names (and any archive-contained notice member the notice-materials manifest
// records) are read; every entry must be a plain regular file or directory
// under the crate's own root. Links, absolute paths, traversal, long-name or
// pax extensions, oversized output and excess entries fail closed. Nothing is
// written to disk or executed.

function tarField(block, offset, length) {
  const end = block.indexOf(0, offset);
  return block.subarray(offset, end === -1 || end > offset + length ? offset + length : end).toString("latin1");
}

function tarNumber(block, offset, length, label) {
  const text = tarField(block, offset, length).trim();
  if (!/^[0-7]*$/u.test(text)) fail(`${label} carries a non-octal tar header field`);
  return text.length === 0 ? 0 : Number.parseInt(text, 8);
}

function isZeroBlock(block) {
  return block.every((byte) => byte === 0);
}

// Validates the complete ustar framing of one crate archive: every header must
// be a whole 512-byte block with a correct checksum and a ustar magic, every
// payload and its zero padding must be present in full, the archive must end
// with the two zero end-of-archive blocks, and nothing but zero padding may
// follow them. Success is only returned after the whole archive was walked.
export function readCrateNoticeMembers(crateBytes, item, archiveNotices = []) {
  const root = `${item.crateName}-${item.crateVersion}`;
  let tar;
  try {
    tar = gunzipSync(crateBytes, { maxOutputLength: MAXIMUM_CRATE_UNPACKED_BYTES });
  } catch (error) {
    fail(`crate archive could not be decompressed within bounds: ${item.id} (${error.code ?? error.message})`);
  }
  if (tar.byteLength < 1024 || tar.byteLength % 512 !== 0) {
    fail(`crate archive is not a whole-block tar stream (${tar.byteLength} bytes): ${item.id}`);
  }
  const wanted = new Map(item.noticeMembers.map((member) => [member.member, member]));
  // Archive-contained notices recorded by the notice-materials manifest: the
  // member must exist, match its recorded digest and begin with the recorded text.
  const verified = new Map();
  for (const notice of archiveNotices) {
    if (wanted.has(notice.member) || verified.has(notice.member)) fail(`archive-contained notice member is declared twice: ${item.id} -> ${notice.member}`);
    verified.set(notice.member, notice);
  }
  const found = new Map();
  let offset = 0;
  let entries = 0;
  let terminated = false;
  while (offset < tar.byteLength) {
    if (tar.byteLength - offset < 512) fail(`crate archive header is incomplete at byte ${offset}: ${item.id}`);
    const header = tar.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      // End-of-archive: a second zero block must follow, and only zero padding may follow that.
      if (tar.byteLength - offset < 1024 || !isZeroBlock(tar.subarray(offset + 512, offset + 1024))) {
        fail(`crate archive end-of-archive framing is incomplete at byte ${offset}: ${item.id}`);
      }
      if (!isZeroBlock(tar.subarray(offset + 1024))) fail(`crate archive carries non-zero bytes after its end-of-archive blocks: ${item.id}`);
      terminated = true;
      break;
    }
    entries += 1;
    if (entries > MAXIMUM_TAR_ENTRIES) fail(`crate archive has too many entries: ${item.id}`);
    if (header.subarray(257, 262).toString("latin1") !== "ustar") fail(`crate archive header lacks the ustar magic at byte ${offset}: ${item.id}`);
    let checksum = 0;
    for (let index = 0; index < 512; index += 1) checksum += index >= 148 && index < 156 ? 0x20 : header[index];
    if (tarNumber(header, 148, 8, item.id) !== checksum) fail(`crate archive header checksum is wrong at byte ${offset}: ${item.id}`);
    const type = String.fromCharCode(header[156]);
    const size = tarNumber(header, 124, 12, item.id);
    const prefix = tarField(header, 345, 155);
    const name = `${prefix.length > 0 ? `${prefix}/` : ""}${tarField(header, 0, 100)}`;
    if (!(type === "0" || type === "\0" || type === "5")) fail(`crate archive entry is not a plain file or directory (type ${JSON.stringify(type)}): ${item.id} -> ${name}`);
    if (name.length === 0 || name.startsWith("/") || name.includes("\\") || name.split("/").some((segment) => segment === "." || segment === "..")
        || !(name === root || name === `${root}/` || name.startsWith(`${root}/`))) {
      fail(`crate archive entry escapes the crate root: ${item.id} -> ${name}`);
    }
    if (type === "5" && size !== 0) fail(`crate archive directory entry carries data: ${item.id} -> ${name}`);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const paddedEnd = dataEnd + ((512 - (size % 512)) % 512);
    if (dataEnd > tar.byteLength) fail(`crate archive entry payload is truncated: ${item.id} -> ${name}`);
    if (paddedEnd > tar.byteLength) fail(`crate archive entry padding is truncated: ${item.id} -> ${name}`);
    if (!isZeroBlock(tar.subarray(dataEnd, paddedEnd))) fail(`crate archive entry padding is not zero: ${item.id} -> ${name}`);
    if (type !== "5" && wanted.has(name)) {
      const expected = wanted.get(name);
      if (size !== expected.size) fail(`notice member size drifted: ${item.id} -> ${name}`);
      const bytes = tar.subarray(dataStart, dataEnd);
      if (sha256(bytes) !== expected.sha256) fail(`notice member SHA-256 drifted: ${item.id} -> ${name}`);
      if (found.has(name)) fail(`notice member appears twice in the archive: ${item.id} -> ${name}`);
      const text = bytes.toString("utf8");
      if (text.includes("\0") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail(`notice member is not UTF-8 text: ${item.id} -> ${name}`);
      found.set(name, text);
    } else if (type !== "5" && verified.has(name)) {
      const expected = verified.get(name);
      if (size > MAXIMUM_NOTICE_MEMBER_BYTES) fail(`archive-contained notice member exceeds the bounded size: ${item.id} -> ${name}`);
      const bytes = tar.subarray(dataStart, dataEnd);
      if (sha256(bytes) !== expected.memberSHA256) fail(`archive-contained notice member SHA-256 drifted: ${item.id} -> ${name}`);
      if (found.has(name)) fail(`archive-contained notice member appears twice in the archive: ${item.id} -> ${name}`);
      const text = bytes.toString("utf8");
      if (text.includes("\0") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail(`archive-contained notice member is not UTF-8 text: ${item.id} -> ${name}`);
      if (!text.startsWith(expected.text)) fail(`archive-contained notice member does not begin with the recorded notice text: ${item.id} -> ${name}`);
      found.set(name, text);
    }
    offset = paddedEnd;
  }
  if (!terminated) fail(`crate archive ends without end-of-archive blocks: ${item.id}`);
  if (entries === 0) fail(`crate archive contains no entries: ${item.id}`);
  for (const name of wanted.keys()) {
    if (!found.has(name)) fail(`notice member is missing from the crate archive: ${item.id} -> ${name}`);
  }
  for (const name of verified.keys()) {
    if (!found.has(name)) fail(`archive-contained notice member is missing from the crate archive: ${item.id} -> ${name}`);
  }
  return found;
}

function escapeCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ").replaceAll("\r", " ");
}

function normalizedText(text) {
  return text.replaceAll("\r\n", "\n").replaceAll("\r", "\n").trimEnd();
}

// Renders the section for crates whose archive carries no licence text when
// the notice-materials manifest is bound: exact external material (never an
// archive member) for established records, and the exact unresolved status
// with its bounded reason for the others.
export function renderBoundNoticeMaterials(withoutText, noticeMaterials, headingLevel = 2) {
  const escape = escapeCell;
  const heading = (depth) => "#".repeat(headingLevel + depth);
  const lines = [
    "",
    `${heading(0)} Crates whose archive carries no licence text`,
    "",
    `These ${withoutText.length} crates are identified by their Cargo.toml licence expression; their .crate archives carry no licence member. \`${escape(noticeMaterials.relativePath)}\` (\`sha256:${noticeMaterials.sha256}\`, researched ${noticeMaterials.researchedOn}) records for each the exact upstream revision the archive was packaged from, the evidence connecting the archive to it, and either exact external notice material (retained in the repository, verified against the immutable upstream bytes plus one terminal LF, and never a member of the archive) or one precise unresolved record. Established with external material: ${noticeMaterials.summary.established.length} (${noticeMaterials.summary.established.map((identity) => `\`${escape(identity)}\``).join(", ") || "none"}). Unresolved: ${noticeMaterials.summary.unresolved.length} (${noticeMaterials.summary.unresolved.map((identity) => `\`${escape(identity)}\``).join(", ") || "none"}); no licence text or copyright statement is rendered for them and none is asserted.`
  ];
  for (const item of withoutText) {
    const record = noticeMaterials.records.find((candidate) => candidate.itemId === item.id);
    const identity = `\`${escape(item.crateName)}\` ${escape(item.crateVersion)}`;
    const title = record.status === "established"
      ? `${identity} — established (${record.archiveNotice ? "archive-contained notice plus external licence text" : "external material"})`
      : `${identity} — UNRESOLVED`;
    lines.push("", `${heading(1)} ${title}`, "",
      `Licence expression (Cargo.toml): ${escape(item.licenseExpression)}; crate \`${item.url}\` (\`sha256:${item.sha256}\`)${item.authors ? `; authors: ${escape(item.authors.join("; "))}` : ""}; provenance status: ${item.provenanceStatus}.`,
      `Packaged from: \`${escape(record.connection.repository)}\` @ \`${record.connection.revision}\` (${record.connection.kind}${record.connection.pathInVcs ? `, path \`${escape(record.connection.pathInVcs)}\`` : ""}).`,
      `Connection evidence: ${escape(record.connection.revisionEvidence)}`);
    if (record.status === "established") {
      if (record.archiveNotice) {
        lines.push("", `Archive-contained notice: member \`${escape(record.archiveNotice.member)}\` (\`sha256:${record.archiveNotice.memberSHA256}\`, verified in the .crate archive) begins with:`, "",
          ...record.archiveNotice.text.split("\n").map((line) => `    ${line}`), "",
          `Note: ${escape(record.archiveNotice.note)}`);
      }
      for (const material of record.materials) {
        lines.push("", `${heading(2)} External material for ${identity}: \`${escape(material.sourcePath)}\``, "",
          `Kind: ${material.kind} — external to the .crate archive; this text was never an archive member.`,
          `Describes: ${escape(material.describes)}`,
          `Upstream: ${material.origin} (raw \`sha256:${material.upstreamSHA256}\`, ${material.upstreamSize} bytes; retrieved ${material.retrievedOn})`,
          `Exact tracked SHA-256: \`${material.sha256}\` (${material.size} bytes)`,
          "Repository normalization: one terminal LF appended; all upstream text bytes are otherwise identical.",
          "", normalizedText(material.text));
      }
    } else {
      lines.push("",
        "Status: UNRESOLVED — no upstream-published licence text or copyright statement exists for this exact version; nothing is rendered for it and none is asserted.",
        `Missing evidence: ${escape(record.unresolved.missingEvidence)}`,
        "Checks performed:",
        ...record.unresolved.checksPerformed.map(({ check, result }) => `- ${escape(check)}: ${escape(result)}`),
        `Fallback used: ${escape(record.unresolved.fallbackUsed)}`);
    }
  }
  return lines;
}

export function renderRustNotices(manifest, manifestSHA256, noticeTexts, noticeMaterials) {
  const crates = manifest.items.filter((item) => item.kind === "rust-crate");
  const withoutText = crates.filter((item) => item.noticeStatus === "no-licence-text-in-crate");
  const bound = noticeMaterials === undefined ? "" : ` Version-bound notice material for the ${withoutText.length} crates whose archive carries no licence text is bound from \`${escapeCell(noticeMaterials.relativePath)}\` (\`sha256:${noticeMaterials.sha256}\`): exact external material for ${noticeMaterials.summary.established.length}, precise unresolved records for ${noticeMaterials.summary.unresolved.length}; see "Crates whose archive carries no licence text".`;
  const lines = [
    "# Rust crate notices for the redistributed libvips combined binary",
    "",
    `Package: \`${manifest.binary.packageName}\` ${manifest.binary.version}; build commit \`${manifest.binary.buildCommit}\`; manifest \`sha256:${manifestSHA256}\`.`,
    "",
    `This file lists ${crates.length} crates.io crates identified by the manifest for the Rust dependencies of the librsvg-c static library of this binary (${crates.filter((item) => item.provenanceStatus === "compiled-per-build-log").length} observed compiling in the retained historical build log, ${crates.filter((item) => item.provenanceStatus === "resolved-approximation").length} resolved by approximation only), with the exact licence texts each .crate archive carries (verified by SHA-256 against the crates.io checksum recorded in the pinned Cargo.lock). Historical build provenance: compiledInHistoricalBuild=${manifest.provenanceStatuses.compiledInHistoricalBuild}, incorporatedIntoShippedBinary=${manifest.provenanceStatuses.incorporatedIntoShippedBinary}. Observed compilation is not a linkage map. This is an auditable material inventory, explicitly partial where marked, not a corresponding-source offer and not legal clearance.${bound}`,
    "",
    "| Crate | Version | Role | Licence expression (Cargo.toml) | Provenance status | Notice material in crate | .crate SHA-256 |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  const escape = escapeCell;
  for (const item of crates) {
    let members = item.noticeMembers.length === 0 ? "none in crate" : item.noticeMembers.map((member) => `\`${escape(member.member.split("/")[1])}\``).join("<br>");
    if (noticeMaterials !== undefined && item.noticeMembers.length === 0) {
      const record = noticeMaterials.records.find((candidate) => candidate.itemId === item.id);
      members = record.status === "established" ? "none in crate; external material bound (see below)" : "none in crate; UNRESOLVED (see below)";
    }
    lines.push(`| \`${escape(item.crateName)}\` | \`${escape(item.crateVersion)}\` | ${item.role} | ${escape(item.licenseExpression)} | ${item.provenanceStatus} | ${members} | \`${item.sha256}\` |`);
  }
  if (withoutText.length > 0) {
    if (noticeMaterials === undefined) {
      lines.push("", "## Crates whose archive carries no licence text", "",
        "These crates are identified only by their Cargo.toml licence expression; the applicable licence text and any copyright statement are not retained here.", "");
      for (const item of withoutText) {
        lines.push(`- \`${escape(item.crateName)}\` ${escape(item.crateVersion)}: ${escape(item.licenseExpression)}${item.authors ? ` (authors: ${escape(item.authors.join("; "))})` : ""}`);
      }
    } else {
      lines.push(...renderBoundNoticeMaterials(withoutText, noticeMaterials));
    }
  }
  lines.push("", "## Licence texts", "");
  for (const item of crates) {
    for (const member of item.noticeMembers) {
      lines.push(`### \`${escape(item.crateName)}\` ${escape(item.crateVersion)}: \`${escape(member.member.split("/")[1])}\``, "",
        `Crate: \`${item.url}\` (\`sha256:${item.sha256}\`); member \`${escape(member.member)}\` (\`sha256:${member.sha256}\`, ${member.size} bytes); licence expression: ${escape(item.licenseExpression)}${item.authors ? `; authors: ${escape(item.authors.join("; "))}` : ""}.`,
        "", normalizedText(noticeTexts.get(`${item.id}\0${member.member}`)), "");
    }
  }
  return `${lines.join("\n")}\n`;
}

export async function collectRustNotices(manifest, directory, noticeMaterials) {
  const texts = new Map();
  for (const item of manifest.items) {
    if (item.kind !== "rust-crate") continue;
    const bytes = await boundedRegularBytes(join(directory, item.fileName), manifest.limits.maximumFileBytes, `crate archive ${item.fileName}`);
    if (bytes.byteLength !== item.size || sha256(bytes) !== item.sha256) fail(`crate archive drifted before notice extraction: ${item.id}`);
    const archiveNotices = noticeMaterials === undefined ? []
      : noticeMaterials.records.filter((record) => record.itemId === item.id && record.archiveNotice !== undefined).map((record) => record.archiveNotice);
    for (const [member, text] of readCrateNoticeMembers(bytes, item, archiveNotices)) texts.set(`${item.id}\0${member}`, text);
  }
  return texts;
}

// ---------------------------------------------------------------------------
// Transports. Each yields a bounded byte stream for one exact URL and reports
// the redirect hosts it traversed. Redirects are followed only when the item
// allows the target host explicitly (or the target host equals the origin).

function redirectAllowed(item, fromURL, target) {
  if (target.protocol !== "https:" || target.username || target.password || target.port !== "") return false;
  return target.hostname === new URL(item.url).hostname || item.allowedRedirectHosts.includes(target.hostname);
}

async function httpsFetchToSink(item, limits, sink) {
  let current = new URL(item.url);
  const visitedHosts = [];
  for (let hop = 0; hop <= limits.maximumRedirects; hop += 1) {
    const outcome = await new Promise((resolveRequest, rejectRequest) => {
      const request = httpsRequest(current, {
        method: "GET",
        headers: { "user-agent": "fulmar-source-materials/1 (+exact-digest-verification)", accept: "*/*" },
        timeout: limits.requestTimeoutMilliseconds
      }, (response) => {
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          const location = response.headers.location;
          response.resume();
          if (typeof location !== "string") return rejectRequest(new Error(`redirect without location from ${current.hostname}: ${item.id}`));
          let target;
          try { target = new URL(location, current); }
          catch { return rejectRequest(new Error(`redirect to an unparseable location: ${item.id}`)); }
          if (!redirectAllowed(item, current, target)) {
            return rejectRequest(new Error(`redirect to a host the manifest does not allow (${target.hostname}): ${item.id}`));
          }
          return resolveRequest({ redirect: target });
        }
        if (status !== 200) {
          response.resume();
          return rejectRequest(new Error(`unexpected HTTP status ${status} for ${item.id}`));
        }
        const declared = response.headers["content-length"];
        if (declared !== undefined && Number(declared) !== item.size) {
          response.destroy();
          return rejectRequest(new Error(`declared content length ${declared} differs from the manifest size ${item.size}: ${item.id}`));
        }
        sink.consume(response, item).then(() => resolveRequest({ done: true }), rejectRequest);
      });
      request.on("timeout", () => request.destroy(new Error(`request timed out: ${item.id}`)));
      request.on("error", rejectRequest);
      request.end();
    });
    if (outcome.done) return { transport: "https", redirectHosts: visitedHosts };
    visitedHosts.push(outcome.redirect.hostname);
    current = outcome.redirect;
  }
  fail(`redirect budget exhausted: ${item.id}`);
}

// Test-only transport: <root>/<host>/<path> holds the bytes; an adjacent
// "<file>.redirect" holds one absolute URL to simulate a redirect hop.
async function fixtureFetchToSink(item, limits, sink, fixtureRoot) {
  let current = new URL(item.url);
  const visitedHosts = [];
  for (let hop = 0; hop <= limits.maximumRedirects; hop += 1) {
    const relative = `${current.hostname}${current.pathname}`;
    assertSafeRelativePath(relative, `fixture path for ${item.id}`);
    const filePath = join(fixtureRoot, ...relative.split("/"));
    let redirectTarget;
    try {
      const redirectBytes = await boundedRegularBytes(`${filePath}.redirect`, 4096, `fixture redirect for ${item.id}`);
      redirectTarget = new URL(redirectBytes.toString("utf8").trim());
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (redirectTarget !== undefined) {
      if (!redirectAllowed(item, current, redirectTarget)) {
        fail(`redirect to a host the manifest does not allow (${redirectTarget.hostname}): ${item.id}`);
      }
      visitedHosts.push(redirectTarget.hostname);
      current = redirectTarget;
      continue;
    }
    let handle;
    try {
      handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      fail(`fixture has no bytes for ${item.id}: ${error.code ?? error.message}`);
    }
    try {
      await sink.consume(handle.createReadStream({ autoClose: false, highWaterMark: CHUNK_BYTES }), item);
    } finally {
      await handle.close();
    }
    return { transport: "local-fixture", redirectHosts: visitedHosts };
  }
  fail(`redirect budget exhausted: ${item.id}`);
}

// Streams one response into an exclusive staging file while counting and
// hashing, aborting as soon as the byte count can no longer match.
function makeSink(stagingDirectory) {
  return {
    async consume(stream, item) {
      const target = join(stagingDirectory, item.fileName);
      const handle = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const hash = createHash("sha256");
      let received = 0;
      try {
        for await (const chunk of stream) {
          received += chunk.byteLength;
          if (received > item.size) {
            stream.destroy?.();
            fail(`response exceeds the manifest size ${item.size}: ${item.id}`);
          }
          hash.update(chunk);
          await handle.write(chunk);
        }
        if (received !== item.size) fail(`received ${received} bytes but the manifest pins ${item.size}: ${item.id}`);
        const digest = hash.digest("hex");
        if (digest !== item.sha256) fail(`SHA-256 ${digest} differs from the manifest digest ${item.sha256}: ${item.id}`);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
  };
}

// ---------------------------------------------------------------------------
// Inventory

function inventoryNoticeMaterials(noticeMaterials) {
  return {
    manifest: noticeMaterials.relativePath,
    manifestSHA256: noticeMaterials.sha256,
    researchedOn: noticeMaterials.researchedOn,
    summary: noticeMaterials.summary,
    records: noticeMaterials.records.map((record) => ({
      crateName: record.crateName,
      crateVersion: record.crateVersion,
      itemId: record.itemId,
      crateSHA256: record.crateSHA256,
      licenseExpression: record.licenseExpression,
      status: record.status,
      connection: record.connection,
      ...(record.archiveNotice === undefined ? {} : { archiveNotice: { member: record.archiveNotice.member, memberSHA256: record.archiveNotice.memberSHA256 } }),
      materials: record.materials.map((material) => ({
        kind: material.kind,
        sourcePath: material.sourcePath,
        origin: material.origin,
        upstreamSHA256: material.upstreamSHA256,
        upstreamSize: material.upstreamSize,
        normalization: material.normalization,
        sha256: material.sha256,
        size: material.size,
        retrievedOn: material.retrievedOn
      })),
      ...(record.unresolved === undefined ? {} : { unresolved: record.unresolved })
    }))
  };
}

export function renderInventory(manifest, manifestSHA256, acquisitions, transport, rustNoticesSHA256, noticeMaterials) {
  const items = manifest.items.map((item) => ({
    id: item.id,
    kind: item.kind,
    fileName: item.fileName,
    size: item.size,
    sha256: item.sha256,
    url: item.url,
    immutability: item.immutability,
    redirectHosts: [...(acquisitions.get(item.id) ?? [])].sort(),
    ...(item.kind === "source-archive" ? {
      component: item.component,
      versionKey: item.versionKey,
      version: item.version,
      upstreamRepository: item.upstreamRepository,
      upstreamRevision: item.upstreamRevision
    } : item.kind === "rust-crate" ? {
      crateName: item.crateName,
      crateVersion: item.crateVersion,
      role: item.role,
      licenseExpression: item.licenseExpression,
      provenanceStatus: item.provenanceStatus,
      ...(item.observedCompilation === undefined ? {} : { observedCompilation: item.observedCompilation }),
      noticeStatus: item.noticeStatus,
      noticeMembers: item.noticeMembers
    } : {})
  }));
  const inventory = {
    schemaVersion: 1,
    inventoryType: "fulmar-libvips-corresponding-source-materials",
    authoritative: transport === "https",
    transport,
    manifestSHA256,
    binary: manifest.binary,
    itemCount: items.length,
    totalBytes: manifest.totalBytes,
    ...(manifest.provenanceStatuses === undefined ? {} : {
      historicalBuildProvenance: manifest.provenanceStatuses,
      rustNoticesFile: RUST_NOTICES_NAME,
      rustNoticesSHA256,
      ...(noticeMaterials === undefined ? {} : { noticeMaterials: inventoryNoticeMaterials(noticeMaterials) })
    }),
    items,
    statement: "Exact upstream inputs identified by the pinned build recipe, verified by size and SHA-256. Archives are opaque and unmodified. This inventory is not a corresponding-source offer, does not prove a rebuild, and is not legal clearance."
  };
  const sums = [...manifest.items.map((item) => ({ fileName: item.fileName, sha256: item.sha256 })),
    ...(rustNoticesSHA256 === undefined ? [] : [{ fileName: RUST_NOTICES_NAME, sha256: rustNoticesSHA256 }])]
    .sort((left, right) => (left.fileName < right.fileName ? -1 : left.fileName > right.fileName ? 1 : 0))
    .map((item) => `${item.sha256}  ${item.fileName}`)
    .join("\n");
  return { inventoryText: `${JSON.stringify(inventory, null, 2)}\n`, sumsText: `${sums}\n` };
}

async function writeExclusive(path, text) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(text, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

// ---------------------------------------------------------------------------
// Commands

function parseTransport(argument) {
  if (argument === undefined || argument === "https") return { kind: "https" };
  if (argument.startsWith("local-fixture:")) {
    const root = resolve(argument.slice("local-fixture:".length));
    if (root.length === 0) fail(USAGE);
    return { kind: "local-fixture", root };
  }
  fail(USAGE);
}

export async function loadManifest(manifestArgument) {
  const manifestPath = resolve(manifestArgument);
  await requireCanonicalDirectory(dirname(manifestPath), "manifest directory");
  if (await realpath(manifestPath) !== manifestPath) fail("manifest must not traverse aliases or symbolic links");
  const bytes = await boundedRegularBytes(manifestPath, MAXIMUM_MANIFEST_BYTES, "manifest");
  const text = bytes.toString("utf8");
  if (text.includes("\0") || text.includes("\r") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail("manifest is not canonical UTF-8 text");
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail(`manifest is not valid JSON: ${error.message}`); }
  return { manifest: validateManifest(document), manifestSHA256: sha256(bytes), manifestPath, manifestBytes: bytes };
}

// Loads the crate manifest and, when an external notice-materials manifest is
// named, binds it to that exact crate manifest. The option only applies to a
// manifest with rust-crate items.
async function loadManifestWithNoticeMaterials(manifestArgument, noticeMaterialsArgument) {
  const loaded = await loadManifest(manifestArgument);
  let noticeMaterials;
  if (noticeMaterialsArgument !== undefined) {
    if (loaded.manifest.provenanceStatuses === undefined) fail("--notice-materials applies only to a manifest with rust-crate items");
    noticeMaterials = await loadRustNoticeMaterials(noticeMaterialsArgument, loaded.manifest, loaded.manifestPath);
  }
  return { ...loaded, noticeMaterials };
}

async function acquire(manifestArgument, destinationArgument, transport, noticeMaterialsArgument) {
  const { manifest, manifestSHA256, noticeMaterials } = await loadManifestWithNoticeMaterials(manifestArgument, noticeMaterialsArgument);
  const destination = resolve(destinationArgument);
  const parent = dirname(destination);
  await requireCanonicalDirectory(parent, "destination parent directory");
  if (basename(destination) !== manifest.outputDirectoryName) {
    fail(`destination must be named ${manifest.outputDirectoryName} as the manifest requires`);
  }
  try {
    await lstat(destination);
    fail("destination already exists; verify it or remove it deliberately instead of overwriting");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (transport.kind === "local-fixture") await requireCanonicalDirectory(transport.root, "fixture transport root");

  const staging = join(parent, `.${manifest.outputDirectoryName}.staging.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: 0o700 });
  let published = false;
  try {
    const sink = makeSink(staging);
    const acquisitions = new Map();
    let transportUsed = transport.kind;
    for (const item of manifest.items) {
      const outcome = transport.kind === "https"
        ? await httpsFetchToSink(item, manifest.limits, sink)
        : await fixtureFetchToSink(item, manifest.limits, sink, transport.root);
      acquisitions.set(item.id, outcome.redirectHosts);
      transportUsed = outcome.transport;
      process.stderr.write(`verified ${item.kind} ${item.fileName} (${item.size} bytes, sha256:${item.sha256})\n`);
    }
    let rustNoticesSHA256;
    if (manifest.provenanceStatuses !== undefined) {
      const noticesText = renderRustNotices(manifest, manifestSHA256, await collectRustNotices(manifest, staging, noticeMaterials), noticeMaterials);
      rustNoticesSHA256 = sha256(noticesText);
      await writeExclusive(join(staging, RUST_NOTICES_NAME), noticesText);
      process.stderr.write(`rendered ${RUST_NOTICES_NAME} (sha256:${rustNoticesSHA256}); historical build provenance ${JSON.stringify(manifest.provenanceStatuses)}${noticeMaterials === undefined ? "" : `; external notice material bound from ${noticeMaterials.relativePath} (sha256:${noticeMaterials.sha256}; established ${noticeMaterials.summary.established.length}, unresolved ${noticeMaterials.summary.unresolved.length})`}\n`);
    }
    const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, transportUsed, rustNoticesSHA256, noticeMaterials);
    await writeExclusive(join(staging, INVENTORY_NAME), inventoryText);
    await writeExclusive(join(staging, SUMS_NAME), sumsText);
    const directoryHandle = await open(staging, constants.O_RDONLY);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    await rename(staging, destination);
    published = true;
    process.stderr.write(`published ${manifest.items.length} verified items (${manifest.totalBytes} bytes) to ${destination} via ${transportUsed} transport\n`);
  } finally {
    if (!published) await rm(staging, { recursive: true, force: true });
  }
}

// Verifies one published destination against its manifest and returns the
// verified state (manifest, notice materials, rendered notices, inventory and
// checksum texts with their digests) for callers that build on it.
export async function verifyMaterials(manifestArgument, destinationArgument, noticeMaterialsArgument) {
  const { manifest, manifestSHA256, manifestPath, noticeMaterials } = await loadManifestWithNoticeMaterials(manifestArgument, noticeMaterialsArgument);
  const destination = resolve(destinationArgument);
  await requireCanonicalDirectory(destination, "destination");
  if (basename(destination) !== manifest.outputDirectoryName) fail(`destination must be named ${manifest.outputDirectoryName}`);
  const entries = await readdir(destination, { withFileTypes: true });
  const expected = new Set([...manifest.items.map((item) => item.fileName), INVENTORY_NAME, SUMS_NAME,
    ...(manifest.provenanceStatuses === undefined ? [] : [RUST_NOTICES_NAME])]);
  for (const entry of entries) {
    if (!expected.has(entry.name)) fail(`destination carries an unexpected entry: ${entry.name}`);
    if (!entry.isFile()) fail(`destination entry is not a regular file: ${entry.name}`);
  }
  if (entries.length !== expected.size) fail("destination is missing expected entries");
  for (const item of manifest.items) {
    const handle = await open(join(destination, item.fileName), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const details = await handle.stat({ bigint: true });
      if (!details.isFile() || details.nlink !== 1n || details.size !== BigInt(item.size)) fail(`size or topology drifted: ${item.fileName}`);
      const hash = createHash("sha256");
      for await (const chunk of handle.createReadStream({ autoClose: false, highWaterMark: CHUNK_BYTES })) hash.update(chunk);
      const digest = hash.digest("hex");
      if (digest !== item.sha256) fail(`SHA-256 drifted: ${item.fileName} is ${digest}, manifest pins ${item.sha256}`);
    } finally {
      await handle.close();
    }
  }
  // Material framing is re-validated before any inventory metadata is trusted,
  // so a retained malformed archive is rejected on its own merits.
  let noticeTexts;
  if (manifest.provenanceStatuses !== undefined) noticeTexts = await collectRustNotices(manifest, destination, noticeMaterials);
  const inventoryBytes = await boundedRegularBytes(join(destination, INVENTORY_NAME), MAXIMUM_MANIFEST_BYTES, "inventory");
  let inventory;
  try { inventory = JSON.parse(inventoryBytes.toString("utf8")); }
  catch { fail("inventory is not valid JSON"); }
  if (inventory?.inventoryType !== "fulmar-libvips-corresponding-source-materials" || inventory.manifestSHA256 !== manifestSHA256
      || inventory.itemCount !== manifest.items.length || !["https", "local-fixture"].includes(inventory.transport)
      || inventory.authoritative !== (inventory.transport === "https")) {
    fail("inventory does not describe this manifest");
  }
  // A destination rendered with external notice material is verified only with
  // it, and one rendered without it is never relabelled as complete.
  if (noticeMaterials === undefined && inventory.noticeMaterials !== undefined) {
    fail(`inventory records external notice material bound from ${inventory.noticeMaterials?.manifest}; pass --notice-materials with that manifest to verify it`);
  }
  if (noticeMaterials !== undefined && inventory.noticeMaterials === undefined) {
    fail("inventory was rendered without external notice material; acquire again with --notice-materials instead of relabelling this destination");
  }
  let rustNoticesSHA256;
  let noticesText;
  if (noticeTexts !== undefined) {
    noticesText = renderRustNotices(manifest, manifestSHA256, noticeTexts, noticeMaterials);
    rustNoticesSHA256 = sha256(noticesText);
    const stored = await boundedRegularBytes(join(destination, RUST_NOTICES_NAME), MAXIMUM_MANIFEST_BYTES * 16, "rust notices");
    if (stored.toString("utf8") !== noticesText) fail("rust crate notices drifted from the verified crate archives");
  }
  const acquisitions = new Map(inventory.items.map((item) => [item.id, item.redirectHosts]));
  const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, inventory.transport, rustNoticesSHA256, noticeMaterials);
  if (inventoryText !== inventoryBytes.toString("utf8")) fail("inventory content drifted from the manifest");
  const sumsBytes = await boundedRegularBytes(join(destination, SUMS_NAME), MAXIMUM_MANIFEST_BYTES, "checksum list");
  if (sumsText !== sumsBytes.toString("utf8")) fail("checksum list drifted from the manifest");
  return {
    destination,
    manifest,
    manifestSHA256,
    manifestPath,
    noticeMaterials,
    noticeTexts,
    noticesText,
    rustNoticesSHA256,
    inventory,
    inventoryText,
    inventorySHA256: sha256(inventoryBytes),
    sumsText,
    sumsSHA256: sha256(sumsBytes),
    transport: inventory.transport,
    authoritative: inventory.authoritative
  };
}

async function verify(manifestArgument, destinationArgument, noticeMaterialsArgument) {
  const verified = await verifyMaterials(manifestArgument, destinationArgument, noticeMaterialsArgument);
  const { manifest, noticeMaterials } = verified;
  process.stderr.write(`verified ${manifest.items.length} items (${manifest.totalBytes} bytes) in ${verified.destination}; transport ${verified.transport}${verified.authoritative ? "" : " (NOT authoritative)"}${noticeMaterials === undefined ? "" : `; external notice material ${noticeMaterials.relativePath} (sha256:${noticeMaterials.sha256}; established ${noticeMaterials.summary.established.length}, unresolved ${noticeMaterials.summary.unresolved.length})`}\n`);
}

function parseCommandLine(argv) {
  const [command, manifestArgument, destinationArgument, ...rest] = argv;
  if (!manifestArgument || !destinationArgument) fail(USAGE);
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const option = rest[index];
    const value = rest[index + 1];
    if (value === undefined || value.length === 0 || value.startsWith("--")) fail(USAGE);
    if (option === "--transport" && options.transport === undefined) options.transport = value;
    else if (option === "--notice-materials" && options.noticeMaterials === undefined) options.noticeMaterials = value;
    else fail(USAGE);
  }
  if (command === "verify" && options.transport !== undefined) fail(USAGE);
  return { command, manifestArgument, destinationArgument, ...options };
}

function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  const { command, manifestArgument, destinationArgument, transport, noticeMaterials } = parseCommandLine(process.argv.slice(2));
  if (command === "acquire") {
    await acquire(manifestArgument, destinationArgument, parseTransport(transport), noticeMaterials);
  } else if (command === "verify") {
    await verify(manifestArgument, destinationArgument, noticeMaterials);
  } else {
    fail(USAGE);
  }
}
