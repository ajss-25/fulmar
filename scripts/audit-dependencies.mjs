import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { lookup as lookupHost } from "node:dns/promises";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzip } from "node:zlib";
import { promisify } from "node:util";
import {
  publishAttestedRegularFileSync,
  readAttestedRegularFile
} from "./attested-regular-file.mjs";

export const advisoryBatchSize = 32;
export const advisoryEndpointSuffix = "-/npm/v1/security/advisories/bulk";
const maximumPackageJSONBytes = 1024 * 1024;
const maximumLockBytes = 32 * 1024 * 1024;
const maximumRequestBytes = 64 * 1024;
const maximumCompressedResponseBytes = 8 * 1024 * 1024;
const maximumDecodedResponseBytes = 16 * 1024 * 1024;
const perAttemptTimeoutMS = 30_000;
const overallTimeoutMS = 20 * 60_000;
const maximumResolvedAddresses = 64;
const gunzipAsync = promisify(gunzip);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const severities = Object.freeze(["info", "low", "moderate", "high", "critical"]);

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function parseJSON(bytes, label) {
  let text;
  try { text = utf8Decoder.decode(bytes); }
  catch { throw new Error(`${label} is not valid UTF-8`); }
  try { return JSON.parse(text); }
  catch { throw new Error(`${label} is not valid JSON`); }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validatePackageName(name) {
  if (typeof name !== "string" || name.length < 1 || Buffer.byteLength(name, "utf8") > 214
      || /[\u0000-\u001f\u007f\\]/u.test(name)
      || (name.startsWith("@") ? !/^@[^/\s]+\/[^/\s]+$/u.test(name) : !/^[^/@\s]+$/u.test(name))) {
    throw new Error(`package lock contains an invalid npm package name: ${String(name).slice(0, 80)}`);
  }
}

function packageNameFromLockPath(path) {
  if (typeof path !== "string" || path.length < 14 || Buffer.byteLength(path, "utf8") > 4096
      || path.startsWith("/") || path.includes("\\") || path.split("/").includes("..")) {
    throw new Error("package lock contains an invalid package path");
  }
  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  if (index < 0) throw new Error(`package lock path is not beneath node_modules: ${path}`);
  const name = path.slice(index + marker.length);
  validatePackageName(name);
  return name;
}

/** Build the exact production package/version payload accepted by npm's bulk advisory API. */
export function productionAdvisoryPayload(packageDocument, lockDocument) {
  if (!plainObject(packageDocument) || !plainObject(lockDocument)
      || lockDocument.lockfileVersion !== 3 || !plainObject(lockDocument.packages)
      || !plainObject(lockDocument.packages[""])) {
    throw new Error("dependency audit requires a complete npm lockfileVersion 3 package graph");
  }
  const root = lockDocument.packages[""];
  if ((typeof packageDocument.name === "string" && root.name !== packageDocument.name)
      || (typeof packageDocument.version === "string" && root.version !== packageDocument.version)) {
    throw new Error("package.json does not match the package-lock root identity");
  }

  const versionsByName = new Map();
  for (const [path, value] of Object.entries(lockDocument.packages)) {
    if (path === "" || value?.dev === true) continue;
    if (!plainObject(value) || typeof value.version !== "string" || value.version.length < 1
        || Buffer.byteLength(value.version, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(value.version)) {
      throw new Error(`production package has no bounded exact version: ${path}`);
    }
    const name = packageNameFromLockPath(path);
    if (!versionsByName.has(name)) versionsByName.set(name, new Set());
    versionsByName.get(name).add(value.version);
  }
  if (versionsByName.size < 1) throw new Error("package lock contains no production packages to audit");

  const entries = [];
  let packageVersionCount = 0;
  for (const name of [...versionsByName.keys()].sort((left, right) => left.localeCompare(right, "en"))) {
    const versions = [...versionsByName.get(name)].sort((left, right) => left.localeCompare(right, "en"));
    entries.push([name, versions]);
    packageVersionCount += versions.length;
  }
  const payload = Object.fromEntries(entries);
  return Object.freeze({
    payload: Object.freeze(payload),
    packageNameCount: Object.keys(payload).length,
    packageVersionCount,
    graphSHA256: sha256(Buffer.from(JSON.stringify(payload), "utf8"))
  });
}

function productionAdvisoryPayloadFromTree(tree) {
  if (!tree || !tree.inventory || typeof tree.inventory.values !== "function") {
    throw new Error("bundled npm Arborist did not return a complete virtual dependency tree");
  }
  const versionsByName = new Map();
  const directNames = new Set();
  for (const node of tree.inventory.values()) {
    if (node?.isRoot === true || node?.dev === true) continue;
    validatePackageName(node?.name);
    if (typeof node.version !== "string" || node.version.length < 1
        || Buffer.byteLength(node.version, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(node.version)) {
      throw new Error(`bundled npm virtual tree contains an invalid exact version: ${node?.name}`);
    }
    if (!versionsByName.has(node.name)) versionsByName.set(node.name, new Set());
    versionsByName.get(node.name).add(node.version);
    if ([...node.edgesIn].some((edge) => edge?.from?.isRoot === true && edge.type !== "dev")) {
      directNames.add(node.name);
    }
  }
  if (versionsByName.size < 1) throw new Error("bundled npm virtual tree contains no production packages to audit");
  const entries = [];
  let packageVersionCount = 0;
  for (const name of [...versionsByName.keys()].sort((left, right) => left.localeCompare(right, "en"))) {
    const versions = [...versionsByName.get(name)].sort((left, right) => left.localeCompare(right, "en"));
    entries.push([name, versions]);
    packageVersionCount += versions.length;
  }
  const payload = Object.fromEntries(entries);
  return Object.freeze({
    payload: Object.freeze(payload),
    packageNameCount: Object.keys(payload).length,
    packageVersionCount,
    graphSHA256: sha256(Buffer.from(JSON.stringify(payload), "utf8")),
    directNames
  });
}

export function advisoryEndpoint(registryURL) {
  const endpoint = new URL(advisoryEndpointSuffix, registryURL);
  if (endpoint.origin !== registryURL.origin || endpoint.username || endpoint.password
      || endpoint.search || endpoint.hash) {
    throw new Error("dependency audit endpoint escaped its credential-free registry origin");
  }
  return endpoint;
}

export function splitAdvisoryBatches(payload) {
  const entries = Object.entries(payload);
  const batches = [];
  for (let offset = 0; offset < entries.length; offset += advisoryBatchSize) {
    batches.push(Object.fromEntries(entries.slice(offset, offset + advisoryBatchSize)));
  }
  return batches;
}

class AuditTransportError extends Error {
  constructor(message, retryable = false, options = undefined) {
    super(message, options);
    this.retryable = retryable;
  }
}

function normalizedTransportFailure(error, label) {
  if (error instanceof AuditTransportError) return error;
  const retryable = [
    "EADDRNOTAVAIL", "EAI_AGAIN", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET",
    "EHOSTUNREACH", "ENETDOWN", "ENETUNREACH", "EPIPE", "ETIMEDOUT",
    "ERR_STREAM_PREMATURE_CLOSE"
  ].includes(error?.code);
  return new AuditTransportError(label, retryable, { cause: error });
}

function normalizedHeader(headers, name) {
  const value = headers[name];
  if (value === undefined) return "";
  if (Array.isArray(value)) throw new AuditTransportError(`npm advisory response repeated ${name}`);
  return String(value).trim();
}

function fixedAddressLookup(address) {
  if (address === null) return undefined;
  return (_hostname, options, callback) => {
    if (options?.all === true) callback(null, [address]);
    else callback(null, address.address, address.family);
  };
}

async function resolvedAuditAddresses(endpoint) {
  if (endpoint.protocol === "http:") return [null];
  let records;
  try { records = await lookupHost(endpoint.hostname, { all: true, verbatim: true }); }
  catch (error) { throw new Error("dependency audit could not resolve its HTTPS registry", { cause: error }); }
  const unique = [];
  const seen = new Set();
  for (const record of records) {
    if (!plainObject(record) || ![4, 6].includes(record.family)
        || isIP(record.address) !== record.family || seen.has(record.address)) continue;
    seen.add(record.address);
    unique.push(Object.freeze({ address: record.address, family: record.family }));
  }
  if (unique.length < 1 || unique.length > maximumResolvedAddresses) {
    throw new Error("dependency audit registry resolved to an invalid bounded address set");
  }
  return unique;
}

function requestOnce(endpoint, body, timeoutMS, userAgent, address) {
  const transport = endpoint.protocol === "https:" ? https : http;
  return new Promise((resolveRequest, rejectRequest) => {
    let settled = false;
    let absoluteTimer = null;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      if (absoluteTimer !== null) clearTimeout(absoluteTimer);
      callback(value);
    };
    const request = transport.request(endpoint, {
      method: "POST",
      agent: false,
      lookup: fixedAddressLookup(address),
      servername: endpoint.protocol === "https:" ? endpoint.hostname : undefined,
      headers: {
        accept: "application/json",
        "accept-encoding": "gzip",
        "content-type": "application/json",
        "content-length": String(body.length),
        "npm-command": "audit",
        "user-agent": userAgent
      }
    }, (response) => {
      let status;
      let declared;
      try {
        status = response.statusCode ?? 0;
        declared = normalizedHeader(response.headers, "content-length");
      } catch (error) {
        response.resume();
        finish(rejectRequest, normalizedTransportFailure(error, "npm advisory response headers failed"));
        return;
      }
      if (declared && (!/^[0-9]+$/u.test(declared)
          || Number(declared) > maximumCompressedResponseBytes)) {
        const error = new AuditTransportError("npm advisory response exceeded its declared byte bound");
        response.destroy(error);
        request.destroy(error);
        finish(rejectRequest, error);
        return;
      }
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > maximumCompressedResponseBytes) {
          const error = new AuditTransportError("npm advisory response exceeded its byte bound");
          response.destroy(error);
          request.destroy(error);
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.once("error", (error) => finish(
        rejectRequest, normalizedTransportFailure(error, "npm advisory response failed")
      ));
      response.once("end", () => finish(resolveRequest, Object.freeze({
        status,
        headers: response.headers,
        bytes: Buffer.concat(chunks, bytes)
      })));
    });
    request.setTimeout(timeoutMS, () => {
      request.destroy(new AuditTransportError("npm advisory request timed out", true));
    });
    absoluteTimer = setTimeout(() => {
      request.destroy(new AuditTransportError("npm advisory request exceeded its absolute deadline", true));
    }, timeoutMS);
    request.once("error", (error) => {
      finish(rejectRequest, normalizedTransportFailure(error, "npm advisory request failed"));
    });
    request.end(body);
  });
}

async function decodedJSONResponse(response) {
  if (response.status !== 200) {
    const retryable = response.status === 408 || response.status === 429 || response.status >= 500;
    throw new AuditTransportError(`npm advisory endpoint returned HTTP ${response.status}`, retryable);
  }
  const contentType = normalizedHeader(response.headers, "content-type").toLowerCase();
  // npm's current bulk route can strip all entity headers when Cloudflare
  // compresses a larger advisory response. The authenticated origin, byte
  // bounds, gzip validation, fatal UTF-8 decoder and strict advisory schema
  // remain authoritative when Content-Type is absent.
  if (contentType !== "" && !/^application\/json(?:\s*;|$)/u.test(contentType)) {
    throw new AuditTransportError("npm advisory endpoint returned a non-JSON content type");
  }
  const encoding = normalizedHeader(response.headers, "content-encoding").toLowerCase();
  if (encoding !== "" && encoding !== "identity" && encoding !== "gzip") {
    throw new AuditTransportError("npm advisory endpoint returned an unsupported content encoding");
  }
  const gzipMagic = response.bytes.length >= 2 && response.bytes[0] === 0x1f && response.bytes[1] === 0x8b;
  let decoded = response.bytes;
  if (encoding === "gzip" || gzipMagic) {
    try { decoded = await gunzipAsync(response.bytes, { maxOutputLength: maximumDecodedResponseBytes }); }
    catch (error) { throw new AuditTransportError("npm advisory endpoint returned invalid bounded gzip data", false, { cause: error }); }
  }
  if (decoded.length < 2 || decoded.length > maximumDecodedResponseBytes) {
    throw new AuditTransportError("npm advisory response exceeded its decoded byte bounds");
  }
  return Object.freeze({ document: parseJSON(decoded, "npm advisory response"), decoded });
}

function orderedAddresses(addresses, startIndex, preferredAddress) {
  if (addresses.length === 1) return [addresses[0], addresses[0]];
  const rotated = addresses.map((_, index) => addresses[(startIndex + index) % addresses.length]);
  if (!preferredAddress) return rotated;
  return [preferredAddress, ...rotated.filter((value) => value.address !== preferredAddress.address)];
}

async function requestBatch(endpoint, batch, deadline, userAgent, addresses, startIndex, preferredAddress) {
  const body = Buffer.from(JSON.stringify(batch), "utf8");
  if (body.length < 2 || body.length > maximumRequestBytes) {
    throw new Error("npm advisory request exceeded its byte bounds");
  }
  let lastError;
  const candidates = orderedAddresses(addresses, startIndex, preferredAddress);
  for (let attempt = 1; attempt <= candidates.length; attempt += 1) {
    const remaining = deadline - Date.now();
    if (remaining < 1000) throw new Error("production dependency audit exceeded its overall deadline");
    try {
      const address = candidates[attempt - 1];
      const response = await requestOnce(
        endpoint, body, Math.min(perAttemptTimeoutMS, remaining), userAgent, address
      );
      const decoded = await decodedJSONResponse(response);
      return Object.freeze({
        ...decoded,
        attempt,
        requestSHA256: sha256(body),
        responseSHA256: sha256(decoded.decoded),
        address
      });
    } catch (error) {
      lastError = error;
      if (!(error instanceof AuditTransportError) || !error.retryable || attempt === candidates.length) break;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 200 * attempt));
    }
  }
  throw new Error("production dependency audit could not obtain one complete bulk advisory response", { cause: lastError });
}

function validateAdvisories(document, requestedNames, directNames) {
  if (!plainObject(document)) throw new Error("npm advisory response is not one object");
  const unresolved = [];
  const seen = new Set();
  for (const [name, advisories] of Object.entries(document)) {
    validatePackageName(name);
    if (!requestedNames.has(name)) throw new Error(`npm advisory response included an unrequested package: ${name}`);
    if (!Array.isArray(advisories)) throw new Error(`npm advisory response has a malformed advisory list: ${name}`);
    for (const advisory of advisories) {
      if (!plainObject(advisory)
          || !["number", "string"].includes(typeof advisory.id)
          || typeof advisory.title !== "string" || advisory.title.length < 1 || advisory.title.length > 4096
          || !severities.includes(advisory.severity)
          || typeof advisory.vulnerable_versions !== "string" || advisory.vulnerable_versions.length < 1
          || advisory.vulnerable_versions.length > 4096) {
        throw new Error(`npm advisory response contains a malformed advisory: ${name}`);
      }
      const identity = `${name}\u0000${advisory.id}\u0000${advisory.vulnerable_versions}`;
      if (seen.has(identity)) throw new Error(`npm advisory response repeated an advisory: ${name}`);
      seen.add(identity);
      unresolved.push(Object.freeze({
        name,
        advisoryID: String(advisory.id),
        title: advisory.title,
        severity: advisory.severity,
        direct: directNames.has(name),
        range: advisory.vulnerable_versions
      }));
    }
  }
  return unresolved;
}

export async function runDependencyAudit(packagePath, lockPath, npmCLIPath, destination) {
  const npmCLI = resolve(npmCLIPath);
  const destinationPath = resolve(destination);
  const destinationDirectory = dirname(destinationPath);
  await mkdir(destinationDirectory, { recursive: true, mode: 0o755 });
  // Invalidate any earlier green receipt before input validation or network I/O.
  // A killed, timed-out or malformed audit must never leave reusable passing
  // evidence for the same lockfile within the verifier's freshness window.
  publishAttestedRegularFileSync(destinationDirectory, basename(destinationPath),
    `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      productionOnly: true,
      state: "audit-incomplete"
    }, null, 2)}\n`, {
      label: "production dependency audit evidence",
      publishMode: "upsert",
      fileMode: 0o644,
      maximumBytes: 8 * 1024 * 1024
    });
  const packageRead = await readAttestedRegularFile(resolve(packagePath), {
    label: "production package.json",
    maximumBytes: maximumPackageJSONBytes,
    requireOwnerControlledMode: true,
    requireCanonicalPath: true
  });
  const lockRead = await readAttestedRegularFile(resolve(lockPath), {
    label: "production package lock",
    maximumBytes: maximumLockBytes,
    requireOwnerControlledMode: true,
    requireCanonicalPath: true
  });
  const npmPackageRead = await readAttestedRegularFile(resolve(dirname(npmCLI), "../package.json"), {
    label: "bundled npm package identity",
    maximumBytes: maximumPackageJSONBytes,
    requireOwnerControlledMode: true,
    requireCanonicalPath: true
  });
  const packageDocument = parseJSON(packageRead.bytes, "package.json");
  const lockDocument = parseJSON(lockRead.bytes, "package-lock.json");
  const npmPackage = parseJSON(npmPackageRead.bytes, "bundled npm package.json");
  if (!plainObject(npmPackage) || typeof npmPackage.version !== "string"
      || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(npmPackage.version)) {
    throw new Error("bundled npm package has no exact version identity");
  }

  const registry = process.env.NPM_CONFIG_REGISTRY ?? "https://registry.npmjs.org/";
  const registryURL = new URL(registry);
  if (registryURL.username || registryURL.password || registryURL.search || registryURL.hash
      || (registryURL.protocol !== "https:" && !(registryURL.protocol === "http:"
        && ["127.0.0.1", "::1", "localhost"].includes(registryURL.hostname)))) {
    throw new Error("dependency audit registry must be credential-free HTTPS or a literal loopback test endpoint");
  }
  const endpoint = advisoryEndpoint(registryURL);
  const lockGraph = productionAdvisoryPayload(packageDocument, lockDocument);
  const isolatedRoot = await mkdtemp(join(tmpdir(), "fulmar-dependency-audit-"));
  let graph;
  try {
    await writeFile(join(isolatedRoot, "package.json"), packageRead.bytes, { mode: 0o600, flag: "wx" });
    await writeFile(join(isolatedRoot, "package-lock.json"), lockRead.bytes, { mode: 0o600, flag: "wx" });
    const requireFromNPM = createRequire(npmCLI);
    const Arborist = requireFromNPM("@npmcli/arborist");
    const tree = await new Arborist({ path: isolatedRoot }).loadVirtual();
    graph = productionAdvisoryPayloadFromTree(tree);
  } finally {
    await rm(isolatedRoot, { recursive: true, force: true });
  }
  if (graph.graphSHA256 !== lockGraph.graphSHA256
      || graph.packageNameCount !== lockGraph.packageNameCount
      || graph.packageVersionCount !== lockGraph.packageVersionCount) {
    throw new Error("bundled npm virtual tree disagrees with the attested production lock graph");
  }
  const batches = splitAdvisoryBatches(graph.payload);
  const directNames = graph.directNames;
  const deadline = Date.now() + overallTimeoutMS;
  const addresses = await resolvedAuditAddresses(endpoint);
  const unresolved = [];
  const batchEvidence = [];
  const userAgent = `npm/${npmPackage.version} node/${process.version} ${process.platform} ${process.arch} workspaces/false fulmar-audit/1`;

  let preferredAddress = null;
  for (const [index, batch] of batches.entries()) {
    const result = await requestBatch(
      endpoint, batch, deadline, userAgent, addresses, index % addresses.length, preferredAddress
    );
    preferredAddress = result.address;
    unresolved.push(...validateAdvisories(result.document, new Set(Object.keys(batch)), directNames));
    batchEvidence.push(Object.freeze({
      index,
      packageNameCount: Object.keys(batch).length,
      attemptCount: result.attempt,
      requestSHA256: result.requestSHA256,
      responseSHA256: result.responseSHA256
    }));
  }
  unresolved.sort((left, right) => left.name.localeCompare(right.name, "en")
    || left.advisoryID.localeCompare(right.advisoryID, "en"));
  const vulnerabilities = Object.fromEntries([...severities, "total"].map((severity) => [severity, 0]));
  for (const advisory of unresolved) {
    vulnerabilities[advisory.severity] += 1;
    vulnerabilities.total += 1;
  }
  const summary = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    productionOnly: true,
    packageLockSHA256: sha256(lockRead.bytes),
    nodeVersion: process.version,
    npmVersion: npmPackage.version,
    registry: registryURL.href,
    auditTransport: "npm-bulk-advisory-v1",
    auditEndpoint: endpoint.href,
    auditReportVersion: 2,
    advisoryBatchSize,
    packageNameCount: graph.packageNameCount,
    packageVersionCount: graph.packageVersionCount,
    packageGraphSHA256: graph.graphSHA256,
    batchCount: batches.length,
    batches: batchEvidence,
    vulnerabilities,
    unresolved
  };
  publishAttestedRegularFileSync(destinationDirectory, basename(destinationPath),
    `${JSON.stringify(summary, null, 2)}\n`, {
      label: "production dependency audit evidence",
      publishMode: "upsert",
      fileMode: 0o644,
      maximumBytes: 8 * 1024 * 1024
    });
  if (vulnerabilities.total !== 0 || unresolved.length !== 0) {
    throw new Error(`production dependency audit found ${vulnerabilities.total} unresolved vulnerabilities`);
  }
  process.stdout.write(`Production dependency audit passed with zero findings across ${graph.packageNameCount} packages using npm ${npmPackage.version}.\n`);
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  const [packagePath, lockPath, npmCLIPath, destination] = process.argv.slice(2);
  if (!packagePath || !lockPath || !npmCLIPath || !destination) {
    throw new Error("usage: audit-dependencies.mjs <package.json> <package-lock.json> <npm-cli.js> <summary.json>");
  }
  await runDependencyAudit(packagePath, lockPath, npmCLIPath, destination);
}
