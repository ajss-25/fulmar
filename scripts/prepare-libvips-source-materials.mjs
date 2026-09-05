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
import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, rm } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";

const USAGE = "usage: prepare-libvips-source-materials.mjs <acquire|verify> <manifest.json> <destination-directory> [--transport https|local-fixture:<directory>]";
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
  if (hasCrates) {
    const categories = document.categories;
    if (!categories || typeof categories !== "object" || Array.isArray(categories)) fail("a manifest with rust-crate items must record provenance categories");
    provenanceStatuses = {};
    for (const name of ["compiledInHistoricalBuild", "incorporatedIntoShippedBinary"]) {
      const status = categories[name]?.status;
      if (status !== "unverified" && status !== "verified") fail(`categories.${name}.status must be verified or unverified`);
      if (status === "verified" && items.some((item) => item.kind === "rust-crate" && item.provenanceStatus !== "compiled-per-build-log")) {
        fail(`categories.${name} cannot be verified while any crate is only a resolved approximation`);
      }
      provenanceStatuses[name] = status;
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
    outputDirectoryName: document.outputDirectoryName,
    limits: { maximumFileBytes, maximumTotalBytes, maximumRedirects, requestTimeoutMilliseconds },
    items,
    totalBytes: total,
    provenanceStatuses
  };
}

// ---------------------------------------------------------------------------
// Bounded .crate (tar.gz) member reader. Only the notice members the manifest
// names are read; every entry must be a plain regular file or directory under
// the crate's own root. Links, absolute paths, traversal, long-name or pax
// extensions, oversized output and excess entries fail closed. Nothing is
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

function readCrateNoticeMembers(crateBytes, item) {
  const root = `${item.crateName}-${item.crateVersion}`;
  let tar;
  try {
    tar = gunzipSync(crateBytes, { maxOutputLength: MAXIMUM_CRATE_UNPACKED_BYTES });
  } catch (error) {
    fail(`crate archive could not be decompressed within bounds: ${item.id} (${error.code ?? error.message})`);
  }
  const wanted = new Map(item.noticeMembers.map((member) => [member.member, member]));
  const found = new Map();
  let offset = 0;
  let entries = 0;
  while (offset + 512 <= tar.byteLength) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    entries += 1;
    if (entries > MAXIMUM_TAR_ENTRIES) fail(`crate archive has too many entries: ${item.id}`);
    const type = String.fromCharCode(header[156]);
    const size = tarNumber(header, 124, 12, item.id);
    const prefix = tarField(header, 345, 155);
    const name = `${prefix.length > 0 ? `${prefix}/` : ""}${tarField(header, 0, 100)}`;
    if (!(type === "0" || type === "\0" || type === "5")) fail(`crate archive entry is not a plain file or directory (type ${JSON.stringify(type)}): ${item.id} -> ${name}`);
    if (name.length === 0 || name.startsWith("/") || name.includes("\\") || name.split("/").some((segment) => segment === "." || segment === "..")
        || !(name === root || name === `${root}/` || name.startsWith(`${root}/`))) {
      fail(`crate archive entry escapes the crate root: ${item.id} -> ${name}`);
    }
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.byteLength) fail(`crate archive entry is truncated: ${item.id} -> ${name}`);
    if (type !== "5" && wanted.has(name)) {
      const expected = wanted.get(name);
      if (size !== expected.size) fail(`notice member size drifted: ${item.id} -> ${name}`);
      const bytes = tar.subarray(dataStart, dataEnd);
      if (sha256(bytes) !== expected.sha256) fail(`notice member SHA-256 drifted: ${item.id} -> ${name}`);
      if (found.has(name)) fail(`notice member appears twice in the archive: ${item.id} -> ${name}`);
      const text = bytes.toString("utf8");
      if (text.includes("\0") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail(`notice member is not UTF-8 text: ${item.id} -> ${name}`);
      found.set(name, text);
    }
    offset = dataEnd + ((512 - (size % 512)) % 512);
  }
  for (const name of wanted.keys()) {
    if (!found.has(name)) fail(`notice member is missing from the crate archive: ${item.id} -> ${name}`);
  }
  return found;
}

function renderRustNotices(manifest, manifestSHA256, noticeTexts) {
  const crates = manifest.items.filter((item) => item.kind === "rust-crate");
  const withoutText = crates.filter((item) => item.noticeStatus === "no-licence-text-in-crate");
  const lines = [
    "# Rust crate notices for the redistributed libvips combined binary",
    "",
    `Package: \`${manifest.binary.packageName}\` ${manifest.binary.version}; build commit \`${manifest.binary.buildCommit}\`; manifest \`sha256:${manifestSHA256}\`.`,
    "",
    `This file lists ${crates.length} crates.io crates identified by the manifest as a resolved approximation of the Rust dependencies compiled into the librsvg-c static library of this binary, with the exact licence texts each .crate archive carries (verified by SHA-256 against the crates.io checksum recorded in the pinned Cargo.lock). Historical build provenance: compiledInHistoricalBuild=${manifest.provenanceStatuses.compiledInHistoricalBuild}, incorporatedIntoShippedBinary=${manifest.provenanceStatuses.incorporatedIntoShippedBinary}. This is an auditable material inventory, explicitly partial where marked, not a corresponding-source offer and not legal clearance.`,
    "",
    "| Crate | Version | Role | Licence expression (Cargo.toml) | Provenance status | Notice material in crate | .crate SHA-256 |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  const escape = (value) => String(value).replaceAll("|", "\\|").replaceAll("\n", " ").replaceAll("\r", " ");
  for (const item of crates) {
    const members = item.noticeMembers.length === 0 ? "none in crate" : item.noticeMembers.map((member) => `\`${escape(member.member.split("/")[1])}\``).join("<br>");
    lines.push(`| \`${escape(item.crateName)}\` | \`${escape(item.crateVersion)}\` | ${item.role} | ${escape(item.licenseExpression)} | ${item.provenanceStatus} | ${members} | \`${item.sha256}\` |`);
  }
  if (withoutText.length > 0) {
    lines.push("", "## Crates whose archive carries no licence text", "",
      "These crates are identified only by their Cargo.toml licence expression; the applicable licence text and any copyright statement are not retained here.", "");
    for (const item of withoutText) {
      lines.push(`- \`${escape(item.crateName)}\` ${escape(item.crateVersion)}: ${escape(item.licenseExpression)}${item.authors ? ` (authors: ${escape(item.authors.join("; "))})` : ""}`);
    }
  }
  lines.push("", "## Licence texts", "");
  for (const item of crates) {
    for (const member of item.noticeMembers) {
      lines.push(`### \`${escape(item.crateName)}\` ${escape(item.crateVersion)}: \`${escape(member.member.split("/")[1])}\``, "",
        `Crate: \`${item.url}\` (\`sha256:${item.sha256}\`); member \`${escape(member.member)}\` (\`sha256:${member.sha256}\`, ${member.size} bytes); licence expression: ${escape(item.licenseExpression)}${item.authors ? `; authors: ${escape(item.authors.join("; "))}` : ""}.`,
        "", noticeTexts.get(`${item.id}\0${member.member}`).replaceAll("\r\n", "\n").replaceAll("\r", "\n").trimEnd(), "");
    }
  }
  return `${lines.join("\n")}\n`;
}

async function collectRustNotices(manifest, directory) {
  const texts = new Map();
  for (const item of manifest.items) {
    if (item.kind !== "rust-crate") continue;
    const bytes = await boundedRegularBytes(join(directory, item.fileName), manifest.limits.maximumFileBytes, `crate archive ${item.fileName}`);
    if (bytes.byteLength !== item.size || sha256(bytes) !== item.sha256) fail(`crate archive drifted before notice extraction: ${item.id}`);
    for (const [member, text] of readCrateNoticeMembers(bytes, item)) texts.set(`${item.id}\0${member}`, text);
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

function renderInventory(manifest, manifestSHA256, acquisitions, transport, rustNoticesSHA256) {
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
      rustNoticesSHA256
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

async function loadManifest(manifestArgument) {
  const manifestPath = resolve(manifestArgument);
  await requireCanonicalDirectory(dirname(manifestPath), "manifest directory");
  if (await realpath(manifestPath) !== manifestPath) fail("manifest must not traverse aliases or symbolic links");
  const bytes = await boundedRegularBytes(manifestPath, MAXIMUM_MANIFEST_BYTES, "manifest");
  const text = bytes.toString("utf8");
  if (text.includes("\0") || text.includes("\r") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail("manifest is not canonical UTF-8 text");
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail(`manifest is not valid JSON: ${error.message}`); }
  return { manifest: validateManifest(document), manifestSHA256: sha256(bytes) };
}

async function acquire(manifestArgument, destinationArgument, transport) {
  const { manifest, manifestSHA256 } = await loadManifest(manifestArgument);
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
      const noticesText = renderRustNotices(manifest, manifestSHA256, await collectRustNotices(manifest, staging));
      rustNoticesSHA256 = sha256(noticesText);
      await writeExclusive(join(staging, RUST_NOTICES_NAME), noticesText);
      process.stderr.write(`rendered ${RUST_NOTICES_NAME} (sha256:${rustNoticesSHA256}); historical build provenance ${JSON.stringify(manifest.provenanceStatuses)}\n`);
    }
    const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, transportUsed, rustNoticesSHA256);
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

async function verify(manifestArgument, destinationArgument) {
  const { manifest, manifestSHA256 } = await loadManifest(manifestArgument);
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
  const inventoryBytes = await boundedRegularBytes(join(destination, INVENTORY_NAME), MAXIMUM_MANIFEST_BYTES, "inventory");
  let inventory;
  try { inventory = JSON.parse(inventoryBytes.toString("utf8")); }
  catch { fail("inventory is not valid JSON"); }
  if (inventory?.inventoryType !== "fulmar-libvips-corresponding-source-materials" || inventory.manifestSHA256 !== manifestSHA256
      || inventory.itemCount !== manifest.items.length || !["https", "local-fixture"].includes(inventory.transport)
      || inventory.authoritative !== (inventory.transport === "https")) {
    fail("inventory does not describe this manifest");
  }
  const acquisitions = new Map(inventory.items.map((item) => [item.id, item.redirectHosts]));
  let rustNoticesSHA256;
  if (manifest.provenanceStatuses !== undefined) {
    const noticesText = renderRustNotices(manifest, manifestSHA256, await collectRustNotices(manifest, destination));
    rustNoticesSHA256 = sha256(noticesText);
    const stored = await boundedRegularBytes(join(destination, RUST_NOTICES_NAME), MAXIMUM_MANIFEST_BYTES * 16, "rust notices");
    if (stored.toString("utf8") !== noticesText) fail("rust crate notices drifted from the verified crate archives");
  }
  const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, inventory.transport, rustNoticesSHA256);
  if (inventoryText !== inventoryBytes.toString("utf8")) fail("inventory content drifted from the manifest");
  const sumsBytes = await boundedRegularBytes(join(destination, SUMS_NAME), MAXIMUM_MANIFEST_BYTES, "checksum list");
  if (sumsText !== sumsBytes.toString("utf8")) fail("checksum list drifted from the manifest");
  process.stderr.write(`verified ${manifest.items.length} items (${manifest.totalBytes} bytes) in ${destination}; transport ${inventory.transport}${inventory.authoritative ? "" : " (NOT authoritative)"}\n`);
}

const [command, manifestArgument, destinationArgument, ...rest] = process.argv.slice(2);
if (!manifestArgument || !destinationArgument || rest.length > 2 || (rest.length > 0 && rest[0] !== "--transport")) fail(USAGE);
if (command === "acquire") {
  await acquire(manifestArgument, destinationArgument, parseTransport(rest[1]));
} else if (command === "verify") {
  if (rest.length > 0) fail(USAGE);
  await verify(manifestArgument, destinationArgument);
} else {
  fail(USAGE);
}
