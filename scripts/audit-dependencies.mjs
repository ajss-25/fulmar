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
export const osvQueryBatchSize = 32;
export const osvQueryBatchEndpoint = "https://api.osv.dev/v1/querybatch";
export const publicNPMRegistry = "https://registry.npmjs.org/";
const maximumPackageJSONBytes = 1024 * 1024;
const maximumLockBytes = 32 * 1024 * 1024;
const maximumRequestBytes = 64 * 1024;
const maximumCompressedResponseBytes = 8 * 1024 * 1024;
const maximumDecodedResponseBytes = 16 * 1024 * 1024;
const perAttemptTimeoutMS = 30_000;
const overallTimeoutMS = 20 * 60_000;
const osvOverallTimeoutMS = 5 * 60_000;
const maximumResolvedAddresses = 64;
const maximumOSVVulnerabilitiesPerResult = 1000;
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

function isLoopbackTestRegistry(registryURL) {
  return registryURL.protocol === "http:"
    && ["127.0.0.1", "::1", "localhost"].includes(registryURL.hostname);
}

function osvEndpointForRegistry(registryURL) {
  if (registryURL.href === publicNPMRegistry) return new URL(osvQueryBatchEndpoint);
  // HTTP is already admitted above only as a literal loopback test registry.
  // This sealed seam lets the hostile transport suite exercise both authorities;
  // published evidence is independently restricted to the literal public URLs.
  if (isLoopbackTestRegistry(registryURL)) return new URL("/v1/querybatch", registryURL);
  throw new Error("OSV fallback is restricted to integrity-bound public npm registry packages");
}

export function splitAdvisoryBatches(payload) {
  const entries = Object.entries(payload);
  const batches = [];
  for (let offset = 0; offset < entries.length; offset += advisoryBatchSize) {
    batches.push(Object.fromEntries(entries.slice(offset, offset + advisoryBatchSize)));
  }
  return batches;
}

/** Build deterministic OSV npm queries for every exact production name/version pair. */
export function splitOSVQueryBatches(payload) {
  const queries = [];
  for (const [name, versions] of Object.entries(payload)) {
    validatePackageName(name);
    if (!Array.isArray(versions) || versions.length < 1) {
      throw new Error(`OSV fallback received no exact versions for package: ${name}`);
    }
    for (const version of versions) {
      if (typeof version !== "string" || version.length < 1
          || Buffer.byteLength(version, "utf8") > 256 || /[\u0000-\u001f\u007f]/u.test(version)) {
        throw new Error(`OSV fallback received an invalid exact version for package: ${name}`);
      }
      queries.push(Object.freeze({
        version,
        package: Object.freeze({ name, ecosystem: "npm" })
      }));
    }
  }
  const batches = [];
  for (let offset = 0; offset < queries.length; offset += osvQueryBatchSize) {
    batches.push(Object.freeze({ queries: Object.freeze(queries.slice(offset, offset + osvQueryBatchSize)) }));
  }
  return batches;
}

/**
 * Prove every production lock node is an integrity-bound public npm tarball
 * before disclosing its identity to OSV as a secondary advisory authority.
 */
export function osvFallbackProvenance(lockDocument) {
  if (!plainObject(lockDocument) || lockDocument.lockfileVersion !== 3
      || !plainObject(lockDocument.packages)) {
    throw new Error("OSV fallback requires a complete npm lockfileVersion 3 package graph");
  }
  const records = [];
  for (const [path, value] of Object.entries(lockDocument.packages)) {
    if (path === "" || value?.dev === true) continue;
    if (!plainObject(value) || value.link === true || typeof value.version !== "string") {
      throw new Error(`OSV fallback requires one public npm tarball for production node: ${path}`);
    }
    const name = packageNameFromLockPath(path);
    if (value.name !== undefined && value.name !== name) {
      throw new Error(`OSV fallback found an aliased production package identity: ${path}`);
    }
    const leaf = name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
    const expectedResolved = `${publicNPMRegistry}${name}/-/${leaf}-${value.version}.tgz`;
    let resolvedURL;
    try { resolvedURL = new URL(value.resolved); }
    catch { throw new Error(`OSV fallback found invalid public npm provenance: ${path}`); }
    if (resolvedURL.href !== value.resolved || value.resolved !== expectedResolved
        || resolvedURL.origin !== new URL(publicNPMRegistry).origin
        || resolvedURL.username || resolvedURL.password || resolvedURL.search || resolvedURL.hash) {
      throw new Error(`OSV fallback found non-public npm provenance: ${path}`);
    }
    const integrityMatch = /^sha512-([A-Za-z0-9+/]+={0,2})$/u.exec(value.integrity ?? "");
    const integrityBytes = integrityMatch ? Buffer.from(integrityMatch[1], "base64") : Buffer.alloc(0);
    if (!integrityMatch || integrityBytes.length !== 64
        || integrityBytes.toString("base64") !== integrityMatch[1]) {
      throw new Error(`OSV fallback requires canonical SHA-512 integrity: ${path}`);
    }
    records.push(Object.freeze({
      path,
      name,
      version: value.version,
      resolved: value.resolved,
      integrity: value.integrity
    }));
  }
  records.sort((left, right) => left.path.localeCompare(right.path, "en"));
  if (records.length < 1) throw new Error("OSV fallback found no public npm production nodes");
  return Object.freeze({
    packageNodeCount: records.length,
    packageNodeProvenanceSHA256: sha256(Buffer.from(JSON.stringify(records), "utf8"))
  });
}

class AuditTransportError extends Error {
  constructor(message, retryable = false, failureClass = "invalid-response", options = undefined) {
    super(message, options);
    this.retryable = retryable;
    this.failureClass = failureClass;
  }
}

class AuditBatchError extends Error {
  constructor(message, cause, attemptCount, requestSHA256) {
    super(message, { cause });
    this.attemptCount = attemptCount;
    this.requestSHA256 = requestSHA256;
  }
}

function normalizedTransportFailure(error, label) {
  if (error instanceof AuditTransportError) return error;
  const retryable = [
    "EADDRNOTAVAIL", "EAI_AGAIN", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET",
    "EHOSTUNREACH", "ENETDOWN", "ENETUNREACH", "EPIPE", "ETIMEDOUT",
    "ERR_STREAM_PREMATURE_CLOSE"
  ].includes(error?.code);
  return new AuditTransportError(
    label,
    retryable,
    retryable ? "network-unavailable" : "transport-failure",
    { cause: error }
  );
}

function normalizedHeader(headers, name, responseLabel) {
  const value = headers[name];
  if (value === undefined) return "";
  if (Array.isArray(value)) throw new AuditTransportError(`${responseLabel} repeated ${name}`);
  return String(value).trim();
}

function fixedAddressLookup(address) {
  if (address === null) return undefined;
  return (_hostname, options, callback) => {
    if (options?.all === true) callback(null, [address]);
    else callback(null, address.address, address.family);
  };
}

async function resolvedAuditAddresses(endpoint, authorityLabel) {
  if (endpoint.protocol === "http:") return [null];
  let records;
  try { records = await lookupHost(endpoint.hostname, { all: true, verbatim: true }); }
  catch (error) { throw new Error(`dependency audit could not resolve ${authorityLabel}`, { cause: error }); }
  const unique = [];
  const seen = new Set();
  for (const record of records) {
    if (!plainObject(record) || ![4, 6].includes(record.family)
        || isIP(record.address) !== record.family || seen.has(record.address)) continue;
    seen.add(record.address);
    unique.push(Object.freeze({ address: record.address, family: record.family }));
  }
  if (unique.length < 1 || unique.length > maximumResolvedAddresses) {
    throw new Error(`${authorityLabel} resolved to an invalid bounded address set`);
  }
  return unique;
}

function requestOnce(endpoint, body, timeoutMS, userAgent, address, authorityLabel, npmCommand) {
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
    const headers = {
      accept: "application/json",
      "accept-encoding": "gzip",
      "content-type": "application/json",
      "content-length": String(body.length),
      "user-agent": userAgent
    };
    if (npmCommand) headers["npm-command"] = "audit";
    const request = transport.request(endpoint, {
      method: "POST",
      agent: false,
      lookup: fixedAddressLookup(address),
      servername: endpoint.protocol === "https:" ? endpoint.hostname : undefined,
      headers
    }, (response) => {
      let status;
      let declared;
      try {
        status = response.statusCode ?? 0;
        declared = normalizedHeader(response.headers, "content-length", authorityLabel);
      } catch (error) {
        response.resume();
        finish(rejectRequest, normalizedTransportFailure(error, `${authorityLabel} headers failed`));
        return;
      }
      if (declared && (!/^[0-9]+$/u.test(declared)
          || Number(declared) > maximumCompressedResponseBytes)) {
        const error = new AuditTransportError(`${authorityLabel} exceeded its declared byte bound`);
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
          const error = new AuditTransportError(`${authorityLabel} exceeded its byte bound`);
          response.destroy(error);
          request.destroy(error);
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.once("error", (error) => finish(
        rejectRequest, normalizedTransportFailure(error, `${authorityLabel} failed`)
      ));
      response.once("end", () => finish(resolveRequest, Object.freeze({
        status,
        headers: response.headers,
        bytes: Buffer.concat(chunks, bytes)
      })));
    });
    request.setTimeout(timeoutMS, () => {
      request.destroy(new AuditTransportError(
        `${authorityLabel} timed out`, true, "deadline-exceeded"
      ));
    });
    absoluteTimer = setTimeout(() => {
      request.destroy(new AuditTransportError(
        `${authorityLabel} exceeded its absolute deadline`, true, "deadline-exceeded"
      ));
    }, timeoutMS);
    request.once("error", (error) => {
      finish(rejectRequest, normalizedTransportFailure(error, `${authorityLabel} request failed`));
    });
    request.end(body);
  });
}

async function decodedJSONResponse(response, authorityLabel, allowMissingContentType) {
  if (response.status !== 200) {
    const retryable = response.status === 408 || response.status === 429
      || (response.status >= 500 && response.status <= 599);
    throw new AuditTransportError(
      `${authorityLabel} returned HTTP ${response.status}`,
      retryable,
      retryable ? "retryable-http" : "invalid-response"
    );
  }
  const contentType = normalizedHeader(response.headers, "content-type", authorityLabel).toLowerCase();
  // npm's current bulk route can strip all entity headers when Cloudflare
  // compresses a larger advisory response. The authenticated origin, byte
  // bounds, gzip validation, fatal UTF-8 decoder and strict advisory schema
  // remain authoritative when Content-Type is absent.
  if ((!allowMissingContentType && contentType === "")
      || (contentType !== "" && !/^application\/json(?:\s*;|$)/u.test(contentType))) {
    throw new AuditTransportError(`${authorityLabel} returned a non-JSON content type`);
  }
  const encoding = normalizedHeader(response.headers, "content-encoding", authorityLabel).toLowerCase();
  if (encoding !== "" && encoding !== "identity" && encoding !== "gzip") {
    throw new AuditTransportError(`${authorityLabel} returned an unsupported content encoding`);
  }
  const gzipMagic = response.bytes.length >= 2 && response.bytes[0] === 0x1f && response.bytes[1] === 0x8b;
  let decoded = response.bytes;
  if (encoding === "gzip" || gzipMagic) {
    try { decoded = await gunzipAsync(response.bytes, { maxOutputLength: maximumDecodedResponseBytes }); }
    catch (error) {
      throw new AuditTransportError(
        `${authorityLabel} returned invalid bounded gzip data`, false, "invalid-response", { cause: error }
      );
    }
  }
  if (decoded.length < 2 || decoded.length > maximumDecodedResponseBytes) {
    throw new AuditTransportError(`${authorityLabel} exceeded its decoded byte bounds`);
  }
  return Object.freeze({ document: parseJSON(decoded, authorityLabel), decoded });
}

function orderedAddresses(addresses, startIndex, preferredAddress) {
  if (addresses.length === 1) return [addresses[0], addresses[0]];
  const rotated = addresses.map((_, index) => addresses[(startIndex + index) % addresses.length]);
  if (!preferredAddress) return rotated;
  return [preferredAddress, ...rotated.filter((value) => value.address !== preferredAddress.address)];
}

async function requestBatch(
  endpoint, batch, deadline, userAgent, addresses, startIndex, preferredAddress, maximumAttempts
) {
  const body = Buffer.from(JSON.stringify(batch), "utf8");
  if (body.length < 2 || body.length > maximumRequestBytes) {
    throw new Error("npm advisory request exceeded its byte bounds");
  }
  let lastError;
  let attemptCount = 0;
  const candidates = orderedAddresses(addresses, startIndex, preferredAddress).slice(0, maximumAttempts);
  for (let attempt = 1; attempt <= candidates.length; attempt += 1) {
    const remaining = deadline - Date.now();
    if (remaining < 1000) throw new Error("production dependency audit exceeded its overall deadline");
    try {
      attemptCount = attempt;
      const address = candidates[attempt - 1];
      const response = await requestOnce(
        endpoint, body, Math.min(perAttemptTimeoutMS, remaining), userAgent, address,
        "npm advisory response", true
      );
      const decoded = await decodedJSONResponse(response, "npm advisory response", true);
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
  throw new AuditBatchError(
    "production dependency audit could not obtain one complete bulk advisory response",
    lastError,
    attemptCount,
    sha256(body)
  );
}

async function requestOSVBatch(
  endpoint, batch, deadline, userAgent, addresses, startIndex, preferredAddress
) {
  const body = Buffer.from(JSON.stringify(batch), "utf8");
  if (body.length < 2 || body.length > maximumRequestBytes) {
    throw new Error("OSV query batch exceeded its byte bounds");
  }
  let lastError;
  let attemptCount = 0;
  const candidates = orderedAddresses(addresses, startIndex, preferredAddress).slice(0, 2);
  for (let attempt = 1; attempt <= candidates.length; attempt += 1) {
    const remaining = deadline - Date.now();
    if (remaining < 1000) throw new Error("OSV fallback exceeded its overall deadline");
    try {
      attemptCount = attempt;
      const address = candidates[attempt - 1];
      const response = await requestOnce(
        endpoint,
        body,
        Math.min(perAttemptTimeoutMS, remaining),
        userAgent,
        address,
        "OSV query-batch response",
        false
      );
      const decoded = await decodedJSONResponse(response, "OSV query-batch response", false);
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
  throw new AuditBatchError(
    "production dependency audit could not obtain one complete OSV query-batch response",
    lastError,
    attemptCount,
    sha256(body)
  );
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

function validateOSVResults(document, queryBatch, directNames) {
  if (!plainObject(document) || Object.keys(document).length !== 1
      || !Array.isArray(document.results) || document.results.length !== queryBatch.queries.length) {
    throw new Error("OSV query-batch response has incomplete result cardinality");
  }
  const unresolved = [];
  const seen = new Set();
  for (const [index, result] of document.results.entries()) {
    if (!plainObject(result)) throw new Error("OSV query-batch response contains a malformed result");
    const keys = Object.keys(result);
    if (keys.some((key) => key !== "vulns" && key !== "next_page_token")) {
      throw new Error("OSV query-batch response contains an unexpected result field");
    }
    if (Object.hasOwn(result, "next_page_token")) {
      throw new Error("OSV query-batch response requires unsupported pagination");
    }
    if (!Object.hasOwn(result, "vulns")) continue;
    if (!Array.isArray(result.vulns) || result.vulns.length > maximumOSVVulnerabilitiesPerResult) {
      throw new Error("OSV query-batch response contains a malformed vulnerability list");
    }
    const query = queryBatch.queries[index];
    for (const vulnerability of result.vulns) {
      if (!plainObject(vulnerability)
          || Object.keys(vulnerability).length !== 2
          || !Object.hasOwn(vulnerability, "id") || !Object.hasOwn(vulnerability, "modified")
          || typeof vulnerability.id !== "string" || vulnerability.id.length < 1
          || Buffer.byteLength(vulnerability.id, "utf8") > 256
          || /[\u0000-\u001f\u007f]/u.test(vulnerability.id)
          || typeof vulnerability.modified !== "string"
          || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u.test(vulnerability.modified)
          || !Number.isFinite(Date.parse(vulnerability.modified))) {
        throw new Error("OSV query-batch response contains a malformed vulnerability identity");
      }
      const identity = `${query.package.name}\u0000${query.version}\u0000${vulnerability.id}`;
      if (seen.has(identity)) throw new Error("OSV query-batch response repeated a vulnerability identity");
      seen.add(identity);
      unresolved.push(Object.freeze({
        source: "OSV",
        name: query.package.name,
        version: query.version,
        advisoryID: vulnerability.id,
        modified: vulnerability.modified,
        direct: directNames.has(query.package.name)
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
  const addresses = await resolvedAuditAddresses(endpoint, "the HTTPS npm registry");
  const unresolved = [];
  let batchEvidence = [];
  const userAgent = `npm/${npmPackage.version} node/${process.version} ${process.platform} ${process.arch} workspaces/false fulmar-audit/1`;
  const fallbackFailureClasses = new Set([
    "deadline-exceeded", "network-unavailable", "retryable-http"
  ]);

  let preferredAddress = null;
  let fallbackFrom = null;
  for (const [index, batch] of batches.entries()) {
    let result;
    try {
      result = await requestBatch(
        endpoint,
        batch,
        deadline,
        userAgent,
        addresses,
        index % addresses.length,
        preferredAddress,
        2
      );
    } catch (error) {
      const cause = error instanceof AuditBatchError ? error.cause : null;
      if (!(cause instanceof AuditTransportError) || !cause.retryable
          || !fallbackFailureClasses.has(cause.failureClass) || unresolved.length !== 0) throw error;
      fallbackFrom = Object.freeze({
        auditTransport: "npm-bulk-advisory-v1",
        auditEndpoint: endpoint.href,
        reason: "primary-service-unavailable",
        failureClass: cause.failureClass,
        failedBatchIndex: index,
        attemptCount: error.attemptCount,
        requestSHA256: error.requestSHA256
      });
      break;
    }
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

  let auditTransport = "npm-bulk-advisory-v1";
  let auditEndpoint = endpoint.href;
  let fallbackProvenance = null;
  let queryCount = null;
  if (fallbackFrom !== null) {
    // Never mix authorities: completed zero-finding npm batches are discarded,
    // then the complete exact graph is independently re-audited by OSV. Any npm
    // advisory or semantic/TLS failure has already failed hard above.
    if (unresolved.length !== 0) throw new Error("OSV fallback cannot suppress an npm advisory");
    const osvEndpoint = osvEndpointForRegistry(registryURL);
    fallbackProvenance = osvFallbackProvenance(lockDocument);
    const queryBatches = splitOSVQueryBatches(graph.payload);
    queryCount = queryBatches.reduce((total, batch) => total + batch.queries.length, 0);
    if (queryCount !== graph.packageVersionCount) {
      throw new Error("OSV fallback query graph disagrees with the production lock graph");
    }
    const osvAddresses = await resolvedAuditAddresses(osvEndpoint, "the HTTPS OSV API");
    const osvDeadline = Date.now() + osvOverallTimeoutMS;
    batchEvidence = [];
    let preferredOSVAddress = null;
    for (const [index, batch] of queryBatches.entries()) {
      const result = await requestOSVBatch(
        osvEndpoint,
        batch,
        osvDeadline,
        userAgent,
        osvAddresses,
        index % osvAddresses.length,
        preferredOSVAddress
      );
      preferredOSVAddress = result.address;
      const findings = validateOSVResults(result.document, batch, directNames);
      unresolved.push(...findings);
      batchEvidence.push(Object.freeze({
        index,
        queryCount: batch.queries.length,
        resultCount: result.document.results.length,
        findingCount: findings.length,
        attemptCount: result.attempt,
        requestSHA256: result.requestSHA256,
        responseSHA256: result.responseSHA256
      }));
    }
    auditTransport = "osv-querybatch-v1-fallback";
    auditEndpoint = osvEndpoint.href;
  }
  unresolved.sort((left, right) => left.name.localeCompare(right.name, "en")
    || String(left.version ?? "").localeCompare(String(right.version ?? ""), "en")
    || left.advisoryID.localeCompare(right.advisoryID, "en"));
  const vulnerabilities = Object.fromEntries(
    [...severities, "unknown", "total"].map((severity) => [severity, 0])
  );
  for (const advisory of unresolved) {
    vulnerabilities[advisory.severity ?? "unknown"] += 1;
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
    auditTransport,
    auditEndpoint,
    auditReportVersion: 2,
    packageNameCount: graph.packageNameCount,
    packageVersionCount: graph.packageVersionCount,
    packageGraphSHA256: graph.graphSHA256,
    batchCount: batchEvidence.length,
    batches: batchEvidence,
    vulnerabilities,
    unresolved
  };
  if (fallbackFrom === null) {
    summary.advisoryBatchSize = advisoryBatchSize;
  } else {
    summary.queryBatchSize = osvQueryBatchSize;
    summary.queryCount = queryCount;
    summary.packageNodeCount = fallbackProvenance.packageNodeCount;
    summary.packageNodeProvenanceSHA256 = fallbackProvenance.packageNodeProvenanceSHA256;
    summary.fallbackFrom = fallbackFrom;
  }
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
  process.stdout.write(
    `Production dependency audit passed with zero findings across ${graph.packageNameCount} packages using ${auditTransport}.\n`
  );
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  const [packagePath, lockPath, npmCLIPath, destination] = process.argv.slice(2);
  if (!packagePath || !lockPath || !npmCLIPath || !destination) {
    throw new Error("usage: audit-dependencies.mjs <package.json> <package-lock.json> <npm-cli.js> <summary.json>");
  }
  await runDependencyAudit(packagePath, lockPath, npmCLIPath, destination);
}
