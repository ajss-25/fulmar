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

const USAGE = "usage: prepare-libvips-source-materials.mjs <acquire|verify> <manifest.json> <destination-directory> [--transport https|local-fixture:<directory>]";
const MAXIMUM_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAXIMUM_ITEMS = 128;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const IDENTIFIER = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/u;
const HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/u;
const KINDS = new Set(["build-recipe", "patch", "source-archive"]);
const INVENTORY_NAME = "INVENTORY.json";
const SUMS_NAME = "SHA256SUMS";
const CHUNK_BYTES = 1024 * 1024;

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
    if (item.kind === "source-archive") {
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
      } : { role: item.role, ...(item.component === undefined ? {} : { component: item.component }) })
    };
  });
  if (total > maximumTotalBytes) fail("manifest items exceed limits.maximumTotalBytes");
  if (!Array.isArray(document.buildTimeModifications) || !Array.isArray(document.unretained)) {
    fail("manifest must record buildTimeModifications and unretained arrays");
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
    totalBytes: total
  };
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

function renderInventory(manifest, manifestSHA256, acquisitions, transport) {
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
    items,
    statement: "Exact upstream inputs identified by the pinned build recipe, verified by size and SHA-256. Archives are opaque and unmodified. This inventory is not a corresponding-source offer, does not prove a rebuild, and is not legal clearance."
  };
  const sums = [...manifest.items]
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
    const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, transportUsed);
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
  const expected = new Set([...manifest.items.map((item) => item.fileName), INVENTORY_NAME, SUMS_NAME]);
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
  const { inventoryText, sumsText } = renderInventory(manifest, manifestSHA256, acquisitions, inventory.transport);
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
