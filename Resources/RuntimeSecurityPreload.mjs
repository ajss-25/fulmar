import http from "node:http";
import https from "node:https";
import http2 from "node:http2";
import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import dns from "node:dns";
import fs from "node:fs";
import childProcess from "node:child_process";
import workerThreads from "node:worker_threads";
import { AsyncLocalStorage } from "node:async_hooks";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import Module, { registerHooks, syncBuiltinESMExports } from "node:module";
import { isAbsolute, join, normalize } from "node:path";

const runtimeAuthenticationVersion = "FULMAR_RUNTIME_AUTH_V1";
const maximumRuntimeAuthenticationBytes = 384;

function consumeRuntimeAuthenticationInput() {
  let bytes;
  let before;
  try {
    before = fs.fstatSync(0, { bigint: true });
    const expectedOwner = BigInt(process.getuid());
    if (!before.isFile() || before.nlink !== 0n || before.uid !== expectedOwner
        || (before.mode & 0o777n) !== 0o600n || before.size < 64n
        || before.size > BigInt(maximumRuntimeAuthenticationBytes)) {
      throw new Error("unsafe metadata");
    }
    const expectedBytes = Number(before.size);
    bytes = Buffer.alloc(expectedBytes);
    let used = 0;
    while (used < expectedBytes) {
      const count = fs.readSync(0, bytes, used, expectedBytes - used, null);
      if (count === 0) break;
      used += count;
    }
    const extra = Buffer.alloc(1);
    const extraCount = fs.readSync(0, extra, 0, 1, null);
    extra.fill(0);
    const after = fs.fstatSync(0, { bigint: true });
    if (used !== expectedBytes || extraCount !== 0
        || before.dev !== after.dev || before.ino !== after.ino
        || before.mode !== after.mode || before.nlink !== after.nlink
        || before.uid !== after.uid || before.gid !== after.gid
        || before.size !== after.size) {
      throw new Error("changed input");
    }
    const frame = bytes.toString("utf8");
    const match = new RegExp(
      `^${runtimeAuthenticationVersion}:([A-Za-z0-9_-]{22,128}):([A-Za-z0-9_-]{22,128})\\n$`,
      "u"
    ).exec(frame);
    if (!match || Buffer.byteLength(frame, "utf8") !== expectedBytes) {
      throw new Error("malformed frame");
    }
    return Object.freeze({ token: match[1], nonce: match[2] });
  } catch {
    throw new Error("Fulmar refused an unsafe private runtime authentication input.");
  } finally {
    bytes?.fill(0);
    try { fs.closeSync(0); } catch {}
  }
}

const legacyRuntimeAuthentication = Object.hasOwn(process.env, "LOCAL_HARNESS_AUTH_TOKEN")
  || Object.hasOwn(process.env, "LOCAL_HARNESS_INSTANCE_NONCE");
delete process.env.LOCAL_HARNESS_AUTH_TOKEN;
delete process.env.LOCAL_HARNESS_INSTANCE_NONCE;
const { token, nonce } = consumeRuntimeAuthenticationInput();
if (legacyRuntimeAuthentication) {
  throw new Error("Fulmar refused legacy runtime authentication material.");
}
const strictLocal = process.env.LOCAL_HARNESS_STRICT_LOCAL === "1";
const sandboxHelper = process.env.LOCAL_HARNESS_SANDBOX_HELPER;
const credentialHelper = process.env.LOCAL_HARNESS_CREDENTIAL_HELPER;
const credentialHome = process.env.LOCAL_HARNESS_CREDENTIAL_HOME;
// The performance plugin removes the environment copy when it initializes.
// Keep this exact native-host path closed over so its lock subprocess can
// bypass the general tool sandbox without admitting arbitrary executables.
const performanceTelemetryLockHelper = process.env.LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER;
const allowedNativeRuntimeRoot = process.env.LOCAL_HARNESS_RUNTIME_ROOT;
const dshHome = process.env.DSH_HOME;
const productionMaximumProviderResponseBytes = 16 * 1024 * 1024;
const configuredMaximumProviderResponseBytes = Number(process.env.LOCAL_HARNESS_MAX_PROVIDER_RESPONSE_BYTES);
const maximumProviderResponseBytes = Number.isSafeInteger(configuredMaximumProviderResponseBytes)
  && configuredMaximumProviderResponseBytes > 0
  ? Math.min(configuredMaximumProviderResponseBytes, productionMaximumProviderResponseBytes)
  : productionMaximumProviderResponseBytes;
// Node's built-in fetch currently reaches the public `tls.connect` export in
// some bundled Node/Undici combinations. Keep a non-forgeable async capability
// around the exact, already-reviewed fetch origin so those internal TLS calls
// can proceed without admitting arbitrary direct TLS clients.
const guardedFetchTLSContext = new AsyncLocalStorage();
// A reviewed model-facing URL fetch is intentionally separate from provider
// traffic. The capability exists only while the signed fetch adapter performs
// one approved HTTPS request; it never broadens shell, MCP, or plugin network
// access and it never becomes an environment variable.
const auxiliaryWebFetchContext = new AsyncLocalStorage();
const auxiliaryLookupFunctions = new WeakSet();
const providerLookupFunctions = new WeakMap();
const originalDNSLookup = dns.lookup.bind(dns);
const providerOrigins = decodeProviderOrigins(process.env.LOCAL_HARNESS_PROVIDER_ORIGINS ?? "[]");
const originalRealpathSync = fs.realpathSync.native.bind(fs.realpathSync);
delete process.env.LOCAL_HARNESS_PROVIDER_ORIGINS;
delete process.env.LOCAL_HARNESS_MAX_PROVIDER_RESPONSE_BYTES;
delete process.env.LOCAL_HARNESS_CREDENTIAL_HOME;
// The resolver below captures this reviewed path, and the confined-filesystem
// module deletes the environment copy when DSH loads the native patch. The
// closed-over canonical path remains available to security checks without
// relying on a profile-local node_modules tree. Children strip it separately.

function securityError(message, syscall = "access", target = "") {
  const error = new Error(message);
  error.code = "EACCES";
  error.errno = -13;
  error.syscall = syscall;
  if (target) error.path = target;
  return error;
}

function pathString(value) {
  if (value instanceof URL && value.protocol === "file:") return fileURLToPath(value);
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return undefined;
}

function canonicalCandidate(value) {
  const raw = pathString(value);
  if (!raw) return undefined;
  let candidate = raw.startsWith("/") ? raw : `${process.cwd()}/${raw}`;
  candidate = candidate.replace(/\/+/g, "/");
  try { return originalRealpathSync(candidate); } catch {}

  const missing = [];
  let parent = candidate;
  while (parent !== "/") {
    const separator = parent.lastIndexOf("/");
    missing.unshift(parent.slice(separator + 1));
    parent = parent.slice(0, separator) || "/";
    try {
      const resolved = originalRealpathSync(parent);
      return [resolved, ...missing].join("/").replace(/\/+/g, "/");
    } catch {}
  }
  return candidate;
}

const protectedPathPatterns = [
  /^\/Users\/[^/]+\/Library\/Keychains(?:\/|$)/,
  /^\/Users\/[^/]+\/Library\/Mail(?:\/|$)/,
  /^\/Users\/[^/]+\/Library\/Messages(?:\/|$)/,
  /^\/Users\/[^/]+\/Library\/Safari(?:\/|$)/,
  /^\/Users\/[^/]+\/Library\/Application Support\/(?:Google\/Chrome|Firefox|BraveSoftware|1Password|Arc|Microsoft Edge)(?:\/|$)/,
  /^\/Users\/[^/]+\/\.(?:aws|azure)(?:\/|$)/,
  /^\/Users\/[^/]+\/\.(?:docker|gnupg|kube)(?:\/|$)/,
  /^\/Users\/[^/]+\/\.config\/(?:gcloud|gh)(?:\/|$)/,
  /^\/Users\/[^/]+\/\.(?:netrc|git-credentials|npmrc|pypirc)$/,
  /^\/Users\/[^/]+\/\.ssh(?:\/|$)/
];

function assertSafePath(value, syscall = "access") {
  const candidate = canonicalCandidate(value);
  if (candidate && protectedPathPatterns.some((pattern) => pattern.test(candidate))) {
    throw securityError("Access denied by Fulmar Strict Local mode.", syscall, candidate);
  }
}

function wrapPathMethod(object, name, indexes = [0]) {
  const original = object?.[name];
  if (typeof original !== "function") return;
  const guarded = (implementation) => function localHarnessProtectedPath(...args) {
    for (const index of indexes) assertSafePath(args[index], name);
    return implementation.apply(this, args);
  };
  const wrapped = guarded(original);
  // `fs.realpath` and `fs.realpathSync` expose a documented `.native`
  // variant. Replacing the parent function without carrying that member
  // breaks consumers after `syncBuiltinESMExports()` and, more importantly,
  // would tempt them to bypass the guarded API. Preserve it behind the same
  // exact path checks.
  if (typeof original.native === "function") {
    Object.defineProperty(wrapped, "native", {
      value: guarded(original.native),
      enumerable: true,
      writable: false,
      configurable: false
    });
  }
  object[name] = wrapped;
}

function hostnameFromOptions(value, defaultProtocol = "http:") {
  if (value instanceof URL) return value.hostname;
  if (typeof value === "string") {
    try { return new URL(value, `${defaultProtocol}//localhost`).hostname; }
    catch { return value; }
  }
  if (value && typeof value === "object") {
    if (value.socketPath) return undefined;
    let host = value.hostname ?? value.host ?? "localhost";
    if (typeof host !== "string") return undefined;
    if (host.startsWith("[") && host.includes("]")) return host.slice(1, host.indexOf("]"));
    const parts = host.split(":");
    if (parts.length === 2 && /^\d+$/.test(parts[1])) host = parts[0];
    return host;
  }
  return "localhost";
}

function embeddedPortFromOptions(value) {
  if (!value || typeof value !== "object" || typeof value.host !== "string") return undefined;
  const host = value.host;
  const bracketed = host.match(/^\[[^\]]+\]:(\d+)$/);
  if (bracketed) return Number(bracketed[1]);
  const plain = host.match(/^[^:]+:(\d+)$/);
  return plain ? Number(plain[1]) : undefined;
}

function destinationFromOptions(value, defaultProtocol = "http:") {
  const localTransportProtocol = defaultProtocol === "tcp:" || defaultProtocol === "tls:";
  if (typeof value === "string" && localTransportProtocol && !/^\d+$/.test(value)) {
    return { localSocket: true };
  }
  if (value && typeof value === "object"
      && (value.socketPath || (localTransportProtocol && value.path))) {
    return { localSocket: true };
  }
  let url;
  if (value instanceof URL) url = value;
  else if (typeof value === "string") {
    try { url = new URL(value, `${defaultProtocol}//localhost`); } catch {}
  }
  const host = hostnameFromOptions(value, defaultProtocol);
  let protocol = url?.protocol ?? (value && typeof value === "object" ? value.protocol : undefined) ?? defaultProtocol;
  if (protocol === "wss:" || protocol === "tls:") protocol = "https:";
  if (protocol === "ws:") protocol = "http:";
  if (protocol === "tcp:" || protocol === "dns:" || protocol === "udp:") protocol = undefined;
  let port = url?.port === "" ? undefined : Number(url?.port);
  if (value && typeof value === "object" && value.port !== undefined) port = Number(value.port);
  else if (value && typeof value === "object") port = embeddedPortFromOptions(value) ?? port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) port = protocol === "https:" ? 443 : protocol === "http:" ? 80 : undefined;
  return { host, scheme: typeof protocol === "string" ? protocol.replace(/:$/, "") : undefined, port };
}

function isLoopbackHost(host) {
  if (typeof host !== "string") return false;
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1" || normalized === "::ffff:127.0.0.1";
}

function isLiteralLoopbackHost(host) {
  if (typeof host !== "string") return false;
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return normalized === "127.0.0.1" || normalized === "::1" || normalized === "::ffff:127.0.0.1";
}

function normalizedProviderHost(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 253
      || /[^\x00-\x7f]/u.test(value) || value.startsWith("[") || value.endsWith("]")
      || value.startsWith(".") || value.endsWith(".")) return undefined;
  const host = value.toLowerCase();
  if (host === "localhost") return host;
  if (net.isIP(host) !== 0) return host;
  if (/^[0-9.]+$/u.test(host) || host.startsWith("0x")) return undefined;
  const labels = host.split(".");
  if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) return undefined;
  return host;
}

function ipv4Octets(address) {
  if (typeof address !== "string" || net.isIP(address) !== 4) return undefined;
  const octets = address.split(".").map(Number);
  return octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? octets
    : undefined;
}

function ipv6Bytes(address) {
  if (typeof address !== "string") return undefined;
  const withoutZone = address.split("%", 1)[0].toLowerCase();
  if (net.isIP(withoutZone) !== 6) return undefined;
  const halves = withoutZone.split("::");
  if (halves.length > 2) return undefined;
  const parseHalf = (half) => {
    if (half === "") return [];
    const values = [];
    for (const part of half.split(":")) {
      if (part.includes(".")) {
        const octets = ipv4Octets(part);
        if (!octets) return undefined;
        values.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/u.test(part)) return undefined;
        values.push(Number.parseInt(part, 16));
      }
    }
    return values;
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return undefined;
  const omitted = 8 - left.length - right.length;
  if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return undefined;
  const words = [...left, ...Array(omitted).fill(0), ...right];
  if (words.length !== 8) return undefined;
  return words.flatMap((word) => [word >> 8, word & 0xff]);
}

function mappedIPv4Address(bytes) {
  if (!bytes || bytes.length !== 16 || !bytes.slice(0, 10).every((byte) => byte === 0)
      || bytes[10] !== 0xff || bytes[11] !== 0xff) return undefined;
  return bytes.slice(12).join(".");
}

function isLoopbackIPAddress(address) {
  const octets = ipv4Octets(address);
  if (octets) return octets[0] === 127;
  const bytes = ipv6Bytes(address);
  if (!bytes) return false;
  const mapped = mappedIPv4Address(bytes);
  if (mapped) return isLoopbackIPAddress(mapped);
  return bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1;
}

function isLocalNetworkIPAddress(address) {
  const octets = ipv4Octets(address);
  if (octets) {
    const [a, b] = octets;
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const bytes = ipv6Bytes(address);
  if (!bytes) return false;
  const mapped = mappedIPv4Address(bytes);
  if (mapped) return isLocalNetworkIPAddress(mapped);
  return isLoopbackIPAddress(address) || (bytes[0] & 0xfe) === 0xfc;
}

function isProviderAddressAllowed(boundary, address) {
  if (boundary === "cloud") return isPublicIPAddress(address);
  if (boundary === "localNetwork") return isLocalNetworkIPAddress(address);
  if (boundary === "onDevice") return isLoopbackIPAddress(address);
  return false;
}

function decodeProviderOrigins(encoded) {
  if (typeof encoded !== "string" || encoded.length > 32_768) {
    throw securityError("Provider network capabilities exceed their startup bound.", "startup");
  }
  let decoded;
  try { decoded = JSON.parse(encoded); }
  catch { throw securityError("Provider network capabilities are not valid JSON.", "startup"); }
  if (!Array.isArray(decoded) || decoded.length > 8) {
    throw securityError("Provider network capabilities have an invalid shape.", "startup");
  }
  const result = [];
  const seen = new Map();
  const exactKeys = ["boundary", "host", "port", "scheme"];
  for (const entry of decoded) {
    if (!isPlainRecord(entry) || Object.keys(entry).sort().join("\0") !== exactKeys.join("\0")
        || !["http", "https"].includes(entry.scheme)
        || !["onDevice", "localNetwork", "cloud"].includes(entry.boundary)
        || !Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65_535) {
      throw securityError("A provider network capability is incomplete or malformed.", "startup");
    }
    const host = normalizedProviderHost(entry.host);
    if (!host || host !== entry.host) {
      throw securityError("A provider network capability has a non-canonical host.", "startup");
    }
    const literalFamily = net.isIP(host);
    if (entry.boundary === "cloud") {
      if (entry.scheme !== "https" || host === "localhost" || host === "metadata.google.internal"
          || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")
          || host.endsWith(".home") || host.endsWith(".lan")
          || (literalFamily !== 0 && !isPublicIPAddress(host))) {
        throw securityError("A cloud provider capability is not a public HTTPS origin.", "startup", host);
      }
    } else {
      const expected = entry.boundary === "onDevice" ? isLoopbackIPAddress : isLocalNetworkIPAddress;
      if ((host !== "localhost" && (literalFamily === 0 || !expected(host)))
          || (entry.scheme === "http" && entry.boundary === "onDevice" && !isLoopbackIPAddress(host))) {
        throw securityError("A local provider capability does not match its reviewed boundary.", "startup", host);
      }
    }
    const identity = `${entry.scheme}\0${host}\0${entry.port}`;
    const priorBoundary = seen.get(identity);
    if (priorBoundary !== undefined && priorBoundary !== entry.boundary) {
      throw securityError("Conflicting provider network capability boundaries were supplied.", "startup", host);
    }
    if (priorBoundary === undefined) {
      seen.set(identity, entry.boundary);
      result.push(Object.freeze({ scheme: entry.scheme, host, port: entry.port, boundary: entry.boundary }));
    }
  }
  return Object.freeze(result);
}

function normalizeAuxiliaryWebURL(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096
      || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw securityError("The web address is empty or exceeds Fulmar's safety limit.", "fetch", String(value ?? ""));
  }
  let url;
  try { url = new URL(value); }
  catch { throw securityError("The web address is not a valid absolute URL.", "fetch", value); }
  if (url.protocol !== "https:" || url.port !== "" || url.username !== "" || url.password !== "") {
    throw securityError("Approved web retrieval accepts HTTPS URLs on the standard port without embedded credentials.", "fetch", value);
  }
  const host = url.hostname.toLowerCase().replace(/\.$/u, "");
  if (host.length === 0 || host.length > 253 || net.isIP(host) !== 0 || !host.includes(".")
      || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")
      || host.endsWith(".internal") || host.endsWith(".home") || host.endsWith(".lan")
      || !host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw securityError("Approved web retrieval requires a public DNS hostname.", "fetch", host);
  }
  url.hostname = host;
  url.hash = "";
  return url;
}

function auxiliaryWebCapabilityFor(value, protocol = "https:") {
  const capability = auxiliaryWebFetchContext.getStore();
  if (!capability) return undefined;
  const destination = destinationFromOptions(value, protocol);
  const host = String(destination.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return destination.scheme === "https" && destination.port === 443 && host === capability.host
    ? capability
    : undefined;
}

function isPublicIPv4(address) {
  const octets = ipv4Octets(address);
  if (!octets) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function isPublicIPAddress(address) {
  if (typeof address !== "string") return false;
  const zoneIndex = address.indexOf("%");
  const normalized = (zoneIndex === -1 ? address : address.slice(0, zoneIndex)).toLowerCase();
  const family = net.isIP(normalized);
  if (family === 4) return isPublicIPv4(normalized);
  if (family !== 6) return false;
  const bytes = ipv6Bytes(normalized);
  if (!bytes) return false;
  const mapped = mappedIPv4Address(bytes);
  if (mapped) return isPublicIPv4(mapped);
  // Admit ordinary global-unicast IPv6 only. Translation/tunnelling prefixes
  // can encode a private IPv4 destination and are deliberately excluded.
  if ((bytes[0] & 0xe0) !== 0x20) return false;
  const first32 = (bytes[0] * 0x1000000) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
  if (first32 === 0x20010db8 || first32 === 0x20010000 || bytes[0] === 0x20 && bytes[1] === 0x02) return false;
  // Benchmarking, ORCHID/ORCHIDv2, documentation, and translation ranges.
  if (bytes[0] === 0x20 && bytes[1] === 0x01) {
    const secondHextet = (bytes[2] << 8) | bytes[3];
    const thirdHextet = (bytes[4] << 8) | bytes[5];
    if ((secondHextet === 0x0002 && thirdHextet === 0x0000)
        || (secondHextet >= 0x0010 && secondHextet <= 0x002f)) return false;
  }
  if ((bytes[0] === 0x3f && bytes[1] === 0xfe)
      || (bytes[0] === 0x3f && bytes[1] === 0xff && (bytes[2] & 0xf0) === 0x00)) return false;
  return true;
}

function auxiliaryPublicLookup(expectedHost) {
  const lookup = function localHarnessAuxiliaryLookup(hostname, options, callback) {
    const normalizedHost = String(hostname).toLowerCase().replace(/\.$/u, "");
    if (normalizedHost !== expectedHost) {
      callback(securityError("The approved web request attempted to resolve a different hostname.", "dns.lookup", normalizedHost));
      return;
    }
    const resolvedOptions = typeof options === "object" && options !== null ? { ...options } : options;
    originalDNSLookup(hostname, resolvedOptions, (error, address, family) => {
      if (error) { callback(error); return; }
      const addresses = Array.isArray(address) ? address.map((entry) => entry?.address) : [address];
      if (addresses.length === 0 || addresses.some((entry) => !isPublicIPAddress(entry))) {
        callback(securityError("The approved web hostname resolved to a private or reserved network address.", "dns.lookup", normalizedHost));
        return;
      }
      callback(null, address, family);
    });
  };
  auxiliaryLookupFunctions.add(lookup);
  return lookup;
}

function tlsArgumentsWithAuxiliaryLookup(args, capability) {
  const copy = [...args];
  if (isPlainRecord(copy[0])) {
    copy[0] = { ...copy[0], lookup: auxiliaryPublicLookup(capability.host) };
    return copy;
  }
  const optionsIndex = typeof copy[1] === "string" ? 2 : 1;
  const existing = isPlainRecord(copy[optionsIndex]) ? copy[optionsIndex] : {};
  copy[optionsIndex] = { ...existing, lookup: auxiliaryPublicLookup(capability.host) };
  return copy;
}

function canonicalIPAddress(address) {
  const octets = ipv4Octets(address);
  if (octets) return `4:${octets.join(".")}`;
  const bytes = ipv6Bytes(address);
  if (!bytes) return undefined;
  const mapped = mappedIPv4Address(bytes);
  if (mapped) return canonicalIPAddress(mapped);
  return `6:${Buffer.from(bytes).toString("hex")}`;
}

function providerBoundaryLookup(capability) {
  const state = { approvedAddresses: new Set(), completed: false };
  const literal = canonicalIPAddress(capability.host);
  if (literal !== undefined) {
    if (!isProviderAddressAllowed(capability.boundary, capability.host)) {
      throw securityError("The approved provider address no longer matches its data boundary.", "dns.lookup", capability.host);
    }
    state.approvedAddresses.add(literal);
    state.completed = true;
  }
  const lookup = function localHarnessProviderLookup(hostname, options, callback) {
    const normalizedHost = String(hostname).toLowerCase().replace(/\.$/u, "");
    if (normalizedHost !== capability.host) {
      callback(securityError("The provider request attempted to resolve a different hostname.", "dns.lookup", normalizedHost));
      return;
    }
    const requestedOptions = typeof options === "object" && options !== null
      ? { ...options }
      : (Number.isInteger(options) ? { family: options } : {});
    const requestedAll = requestedOptions.all === true;
    const requestedFamily = requestedOptions.family === 4 || requestedOptions.family === 6
      ? requestedOptions.family
      : 0;
    // Resolve the complete address-family set regardless of the caller's
    // preference. Only after every answer passes the boundary may the result
    // be narrowed back to the shape Node requested.
    const reviewedOptions = { all: true, verbatim: true, family: 0, hints: 0 };
    originalDNSLookup(hostname, reviewedOptions, (error, addresses) => {
      if (error) { callback(error); return; }
      const results = Array.isArray(addresses) ? addresses : [];
      const canonical = results.map((entry) => canonicalIPAddress(entry?.address));
      if (results.length === 0 || canonical.some((entry) => entry === undefined)
          || results.some((entry) => !isProviderAddressAllowed(capability.boundary, entry?.address))) {
        callback(securityError(
          "The provider hostname resolved outside its reviewed data boundary.",
          "dns.lookup",
          normalizedHost
        ));
        return;
      }
      state.approvedAddresses = new Set(canonical);
      state.completed = true;
      const returnedResults = requestedFamily === 0
        ? results
        : results.filter((entry) => entry.family === requestedFamily);
      if (returnedResults.length === 0) {
        callback(securityError("The provider hostname has no address in the requested family.", "dns.lookup", normalizedHost));
        return;
      }
      if (requestedAll) {
        callback(null, returnedResults);
      } else {
        const first = returnedResults[0];
        callback(null, first.address, first.family);
      }
    });
  };
  providerLookupFunctions.set(lookup, { token: capability.token, state });
  return { lookup, state };
}

function connectionArgumentsWithLookup(args, lookup) {
  const copy = [...args];
  if (Array.isArray(copy[0])) {
    const nested = [...copy[0]];
    if (isPlainRecord(nested[0])) nested[0] = { ...nested[0], lookup };
    else {
      const optionsIndex = typeof nested[1] === "string" ? 2 : 1;
      nested[optionsIndex] = { ...(isPlainRecord(nested[optionsIndex]) ? nested[optionsIndex] : {}), lookup };
    }
    copy[0] = nested;
    return copy;
  }
  if (isPlainRecord(copy[0])) {
    copy[0] = { ...copy[0], lookup };
    return copy;
  }
  const optionsIndex = typeof copy[1] === "string" ? 2 : 1;
  copy[optionsIndex] = { ...(isPlainRecord(copy[optionsIndex]) ? copy[optionsIndex] : {}), lookup };
  return copy;
}

function argumentsWithProviderLookup(args, capability) {
  const existing = connectionOptionsFromArgs(args)?.lookup;
  const reviewed = typeof existing === "function" ? providerLookupFunctions.get(existing) : undefined;
  if (reviewed?.token === capability.token) return { arguments: args, state: reviewed.state };
  const created = providerBoundaryLookup(capability);
  return {
    arguments: connectionArgumentsWithLookup(args, created.lookup),
    state: created.state
  };
}

function providerLookupIsReviewed(lookup, capability) {
  return typeof lookup === "function"
    && capability?.kind === "provider"
    && providerLookupFunctions.get(lookup)?.token === capability.token;
}

function enforceProviderPeer(socket, eventName, capability, state) {
  if (!socket || typeof socket.prependOnceListener !== "function") return socket;
  socket.prependOnceListener(eventName, () => {
    const remoteAddress = String(socket.remoteAddress ?? "");
    const canonical = canonicalIPAddress(remoteAddress);
    if (!state.completed || canonical === undefined || !state.approvedAddresses.has(canonical)
        || !isProviderAddressAllowed(capability.boundary, remoteAddress)) {
      socket.destroy(securityError(
        "The provider connection reached an address outside its reviewed DNS result or data boundary.",
        eventName === "secureConnect" ? "tls.connect" : "net.connect",
        remoteAddress || capability.host
      ));
    }
  });
  return socket;
}

function assertNetworkAllowed(value, syscall, protocol, { allowHostOnly = false } = {}) {
  const destination = destinationFromOptions(value, protocol);
  if (destination.localSocket) {
    throw securityError("Unix-domain and named-pipe sockets are disabled by Fulmar.", syscall, "local socket");
  }
  // Both privacy modes require one exact native-approved origin and port.
  // Strict Local additionally limits that origin to a literal loopback
  // address, so an unrelated service elsewhere on this Mac is never admitted.
  const approvedAuxiliaryWeb = auxiliaryWebCapabilityFor(value, protocol) !== undefined;
  const approvedProvider = providerOrigins.find((origin) =>
    origin.host === String(destination.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")
    && (destination.port === undefined ? allowHostOnly : origin.port === destination.port)
    && (destination.scheme === undefined || origin.scheme === destination.scheme)
  );
  const allowed = approvedAuxiliaryWeb
    || (approvedProvider !== undefined
      && (!strictLocal || (approvedProvider.boundary === "onDevice" && isLiteralLoopbackHost(destination.host))));
  if (!allowed) throw securityError(
    strictLocal ? "External network access denied by Fulmar Strict Local mode." : "Network destination is not an approved provider origin.",
    syscall,
    String(destination.host ?? "network destination")
  );
}

function exactApprovedProviderOrigin(value, protocol = "http:") {
  const destination = destinationFromOptions(value, protocol);
  const host = String(destination.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return providerOrigins.find((origin) => origin.host === host
    && origin.port === destination.port
    && (destination.scheme === undefined || origin.scheme === destination.scheme));
}

function exactApprovedStreamDestination(destination, scheme) {
  const host = String(destination.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return providerOrigins.some((origin) =>
    origin.scheme === scheme && origin.host === host && origin.port === destination.port
  );
}

function guardedFetchTLSOrigin(url) {
  const destination = destinationFromOptions(url, "http:");
  const providerOrigin = exactApprovedProviderOrigin(url, "http:");
  return Object.freeze({
    kind: providerOrigin === undefined ? "auxiliary" : "provider",
    scheme: destination.scheme,
    host: String(destination.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, ""),
    port: destination.port,
    boundary: providerOrigin?.boundary,
    token: Object.freeze({})
  });
}

function isGuardedFetchTLSDestination(destination) {
  const capability = guardedFetchTLSContext.getStore();
  if (!capability || capability.scheme !== "https") return false;
  const effective = destinationFromOptions(destination, "tls:");
  const host = String(effective.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return effective.scheme === "https"
    && host === capability.host
    && effective.port === capability.port;
}

function isGuardedFetchStreamDestination(destination) {
  const capability = guardedFetchTLSContext.getStore();
  if (!capability) return false;
  const effective = destinationFromOptions(destination, "tcp:");
  const host = String(effective.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return host === capability.host && effective.port === capability.port;
}

function assertRawTCPAllowed(value, syscall) {
  const destination = destinationFromOptions(value, "tcp:");
  if (destination.localSocket) {
    throw securityError("Unix-domain and named-pipe sockets are disabled by Fulmar.", syscall, "local socket");
  }
  if (isGuardedFetchStreamDestination(value)) return;
  // Direct raw streams are needed only for the literal loopback Ollama route.
  // Reviewed HTTP/TLS stacks use private captured primitives and never create
  // a process-global or forgeable bypass state.
  const isDirectLiteralLoopbackHTTP = isLiteralLoopbackHost(destination.host)
    && exactApprovedStreamDestination(destination, "http");
  if (isDirectLiteralLoopbackHTTP) return;
  throw securityError(
    strictLocal
      ? "External network access denied by Fulmar Strict Local mode."
      : "Raw TCP is not an approved provider transport.",
    syscall,
    String(destination.host ?? "network destination")
  );
}

function assertDatagramAllowed(value, syscall) {
  const host = hostnameFromOptions(value, "udp:");
  // Provider grants describe HTTP(S) origins. They must never be reinterpreted
  // as permission to send UDP to the same host or to arbitrary local services.
  // Provider grants describe HTTP(S) origins and can never authorize UDP,
  // including UDP traffic to another service on the same Mac.
  throw securityError(
    "Datagram traffic is not part of an approved provider origin.",
    syscall,
    String(host ?? "network destination")
  );
}

function assertLoopbackListener(args, syscall) {
  const first = args[0];
  let host;
  let port;
  if (Number.isInteger(first)) {
    port = first;
    host = typeof args[1] === "string" ? args[1] : undefined;
  } else if (isPlainRecord(first)) {
    if (first.path !== undefined || first.handle !== undefined || first.fd !== undefined) {
      throw securityError("Unix-domain, handle, and inherited-fd listeners are disabled by Fulmar.", syscall);
    }
    port = first.port;
    host = first.host;
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535 || !isLiteralLoopbackHost(host)) {
    throw securityError("Listeners must bind an explicit loopback address and bounded TCP port.", syscall, String(host ?? "unspecified address"));
  }
}

function assertLoopbackDatagramBind(args) {
  const first = args[0];
  let address;
  let port;
  if (Number.isInteger(first)) {
    port = first;
    address = typeof args[1] === "string" ? args[1] : undefined;
  } else if (isPlainRecord(first)) {
    port = first.port;
    address = first.address;
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535 || !isLiteralLoopbackHost(address)) {
    throw securityError(
      "Datagram listeners must bind an explicit loopback address and bounded port.",
      "dgram.bind",
      String(address ?? "unspecified address")
    );
  }
}

function connectionOptionsFromArgs(args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  if (isPlainRecord(first)) return first;
  const numericPort = typeof args[0] === "number"
    || (typeof args[0] === "string" && /^\d+$/.test(args[0]));
  if (!numericPort) return undefined;
  const optionsIndex = typeof args[1] === "string" ? 2 : 1;
  return isPlainRecord(args[optionsIndex]) ? args[optionsIndex] : undefined;
}

function assertSafeConnectionOptions(
  options,
  syscall,
  {
    httpTransport = false,
    tlsTransport = false,
    destination,
    allowReviewedAuxiliaryLookup = false,
    allowReviewedProviderLookup = false
  } = {}
) {
  if (!isPlainRecord(options)) return;
  for (const key of ["lookup", "createConnection", "dispatcher", "socket"]) {
    if (options[key] !== undefined && options[key] !== null) {
      if (key === "lookup" && allowReviewedAuxiliaryLookup
          && typeof options[key] === "function" && auxiliaryLookupFunctions.has(options[key])) continue;
      if (key === "lookup" && allowReviewedProviderLookup
          && providerLookupIsReviewed(options[key], guardedFetchTLSContext.getStore())) continue;
      throw securityError(`Caller-controlled ${key} hooks are disabled by Fulmar.`, syscall);
    }
  }
  if (httpTransport
      && options.agent !== undefined
      && options.agent !== null
      && options.agent !== false) {
    throw securityError("Caller-controlled HTTP agents are disabled by Fulmar.", syscall);
  }
  if (httpTransport) {
    if (options.setHost === false) {
      throw securityError("HTTP Host generation cannot be disabled by Fulmar clients.", syscall);
    }
    if (containsAuthorityHeader(options.headers)) {
      throw securityError("Caller-controlled HTTP authority headers are disabled by Fulmar.", syscall);
    }
  }
  if (tlsTransport) {
    if (options.rejectUnauthorized !== undefined && options.rejectUnauthorized !== true) {
      throw securityError("TLS certificate verification cannot be weakened by Fulmar clients.", syscall);
    }
    if (options.checkServerIdentity !== undefined && options.checkServerIdentity !== null) {
      throw securityError("Caller-controlled TLS identity checks are disabled by Fulmar.", syscall);
    }
    for (const key of [
      "socket", "secureContext", "ca", "cert", "key", "pfx", "crl", "dhparam",
      "pskCallback", "ALPNCallback", "secureProtocol", "ciphers", "sigalgs", "ecdhCurve"
    ]) {
      if (options[key] !== undefined && options[key] !== null) {
        throw securityError(`Caller-controlled TLS ${key} is disabled by Fulmar.`, syscall);
      }
    }
    for (const key of ["minVersion", "maxVersion"]) {
      if (options[key] !== undefined && !["TLSv1.2", "TLSv1.3"].includes(options[key])) {
        throw securityError(`Caller-controlled TLS ${key} is disabled by Fulmar.`, syscall);
      }
    }
    if (options.servername !== undefined) {
      const expected = String(destination?.host ?? "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      const actual = String(options.servername).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      const emptyForIPAddress = actual === "" && net.isIP(expected) !== 0;
      if (!emptyForIPAddress && actual !== expected) {
        throw securityError("TLS SNI must match the exact approved provider host.", syscall, actual);
      }
    }
  }
}

function containsAuthorityHeader(headers) {
  if (!headers) return false;
  let names = [];
  if (Array.isArray(headers)) {
    names = headers.every((entry) => Array.isArray(entry))
      ? headers.map((entry) => entry[0])
      : headers.filter((_entry, index) => index % 2 === 0);
  } else if (typeof headers?.keys === "function") {
    try { names = [...headers.keys()]; }
    catch { throw securityError("HTTP headers could not be inspected safely.", "headers"); }
  } else if (typeof headers === "object") {
    names = Object.keys(headers);
  }
  return names.some((name) => {
    const normalized = String(name).toLowerCase();
    return normalized === "host" || normalized === ":authority";
  });
}

const reviewedFetchOptionNames = new Set([
  "body", "cache", "credentials", "duplex", "headers", "integrity", "keepalive",
  "method", "mode", "priority", "redirect", "referrer", "referrerPolicy", "signal", "window"
]);
const privacyFilteredProviderHeaders = Object.freeze([
  "x-deepseek-harness-user-id",
  "x-deepseek-harness-session-id"
]);

function reviewedFetchOptions(value) {
  if (value === undefined) return { redirect: "manual" };
  if (!isPlainRecord(value)) {
    throw securityError("Fetch options must be a plain reviewed record.", "fetch");
  }
  for (const key of Object.keys(value)) {
    if (!reviewedFetchOptionNames.has(key)) {
      throw securityError(`Caller-controlled fetch option ${key} is disabled by Fulmar.`, "fetch");
    }
  }
  assertSafeConnectionOptions(value, "fetch", { httpTransport: true });
  const reviewed = {};
  for (const key of reviewedFetchOptionNames) {
    if (Object.hasOwn(value, key)) reviewed[key] = value[key];
  }
  // Provider redirects must be surfaced to the adapter. They are never
  // followed implicitly because the redirect target has not been consented.
  reviewed.redirect = "manual";
  return reviewed;
}

function wrapHTTPModule(module, protocol) {
  for (const name of ["request", "get"]) {
    const original = module[name];
    module[name] = function localHarnessHTTP(...args) {
      let destination = args[0];
      const requestOptions = isPlainRecord(args[0])
        ? args[0]
        : (isPlainRecord(args[1]) ? args[1] : undefined);
      // In request(url, options), Node lets destination-shaped options
      // override URL fields. Validate the effective merged destination so an
      // approved URL cannot smuggle a different host or port in argument two.
      if ((typeof args[0] === "string" || args[0] instanceof URL) && isPlainRecord(args[1])) {
        const base = destinationFromOptions(args[0], `${protocol}:`);
        const overrides = args[1];
        const overridesHost = Object.hasOwn(overrides, "hostname") || Object.hasOwn(overrides, "host");
        const overridesPort = Object.hasOwn(overrides, "port") || embeddedPortFromOptions(overrides) !== undefined;
        destination = overrides.socketPath ? { socketPath: overrides.socketPath } : {
          protocol: overrides.protocol ?? (base.scheme === undefined ? `${protocol}:` : `${base.scheme}:`),
          hostname: overridesHost ? hostnameFromOptions(overrides, `${protocol}:`) : base.host,
          port: overridesPort ? (overrides.port ?? embeddedPortFromOptions(overrides)) : base.port
        };
      }
      const effectiveDestination = destinationFromOptions(destination, `${protocol}:`);
      assertSafeConnectionOptions(requestOptions, `${protocol}.${name}`, {
        httpTransport: true,
        tlsTransport: protocol === "https",
        destination: effectiveDestination
      });
      assertNetworkAllowed(destination, `${protocol}.${name}`, `${protocol}:`);
      const effective = destinationFromOptions(destination, `${protocol}:`);
      if (!strictLocal && (protocol !== "http" || !isLiteralLoopbackHost(effective.host))) {
        throw securityError(
          "Connected provider requests must use the guarded fetch transport.",
          `${protocol}.${name}`,
          String(effective.host ?? "network destination")
        );
      }
      return original.apply(this, args);
    };
  }

  const agentPrototype = module.Agent?.prototype;
  const originalCreateConnection = agentPrototype?.createConnection;
  if (typeof originalCreateConnection === "function") {
    agentPrototype.createConnection = function localHarnessAgentConnection(...args) {
      const destination = numericConnectDestination(args, `${protocol}:`, protocol === "https");
      assertSafeConnectionOptions(connectionOptionsFromArgs(args), `${protocol}.Agent.createConnection`, {
        tlsTransport: protocol === "https",
        destination: destinationFromOptions(destination, `${protocol}:`)
      });
      assertNetworkAllowed(destination, `${protocol}.Agent.createConnection`, `${protocol}:`);
      const effective = destinationFromOptions(destination, `${protocol}:`);
      if (!strictLocal && (protocol !== "http" || !isLiteralLoopbackHost(effective.host))) {
        throw securityError(
          "Connected provider agents are disabled; use the guarded fetch transport.",
          `${protocol}.Agent.createConnection`,
          String(effective.host ?? "network destination")
        );
      }
      return originalCreateConnection.apply(this, args);
    };
  }
}

function numericConnectDestination(args, protocol, optionsAllowed) {
  const numericPort = typeof args[0] === "number"
    ? args[0]
    : (typeof args[0] === "string" && /^\d+$/.test(args[0]) ? Number(args[0]) : undefined);
  if (numericPort === undefined) return Array.isArray(args[0]) ? args[0][0] : args[0];
  const hostIndex = typeof args[1] === "string" ? 1 : -1;
  const optionsIndex = hostIndex === -1 ? 1 : 2;
  const options = optionsAllowed && isPlainRecord(args[optionsIndex]) ? args[optionsIndex] : undefined;
  return {
    protocol,
    hostname: options?.hostname ?? options?.host ?? (hostIndex === -1 ? "localhost" : args[hostIndex]),
    port: options?.port ?? numericPort,
    ...(options?.socketPath === undefined ? {} : { socketPath: options.socketPath })
  };
}

function executableString(value) {
  if (value instanceof URL && value.protocol === "file:") return fileURLToPath(value);
  return typeof value === "string" ? value : String(value);
}

const mcpGuardEnvironmentNames = Object.freeze([
  "LOCAL_HARNESS_MCP_GUARD_CHILD",
  "LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS",
  "LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP",
  "LOCAL_HARNESS_MCP_GUARD_PLAN"
]);
const mcpGuardBaseEnvironmentNames = Object.freeze(["HOME", "USER", "LOGNAME", "PATH", "LANG", "TMPDIR"]);
const mcpGuardCredentialPattern = /^[A-Z][A-Z0-9_]{0,63}$/;
const mcpGuardForbiddenCredentialNames = new Set([
  "BASH_ENV", "ENV", "HOME", "IFS", "LANG", "LOGNAME", "NODE_OPTIONS", "PATH", "PERL5OPT",
  "PYTHONHOME", "PYTHONPATH", "RUBYOPT", "SHELL", "TMPDIR", "USER", "ZDOTDIR"
]);
const mcpGuardPlanKeys = new Set([
  "schemaVersion", "serverID", "reviewFingerprint", "serverName", "executable", "reviewedArgumentFiles",
  "project", "command", "arguments", "workingDirectory", "credentialVariables", "limits"
]);
const mcpGuardExecutableKeys = new Set([
  "declaredPath", "canonicalPath", "contentSHA256", "byteCount", "ownerUID", "permissions", "fingerprint",
  "interpreterCanonicalPath", "interpreterContentSHA256"
]);
const mcpGuardReviewedFileKeys = new Set([
  "argumentIndex", "declaredPath", "canonicalPath", "contentSHA256", "byteCount", "ownerUID", "permissions"
]);
const mcpGuardProjectKeys = new Set(["canonicalPath", "ownerUID", "deviceID", "inode", "fingerprint"]);
const mcpGuardLimitKeys = new Set([
  "startupTimeoutMilliseconds", "toolCallTimeoutMilliseconds", "maximumDiscoveredTools", "maximumOutputBytes",
  "maximumInventoryBytes"
]);
const mcpGuardSpawnOptionKeys = new Set(["cwd", "env", "shell", "stdio", "windowsHide"]);
const maxMCPGuardPlanBytes = 2 * 1024 * 1024;

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecordKeys(value, allowed, required, label) {
  if (!isPlainRecord(value)) throw securityError(`${label} is invalid.`, "spawn");
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw securityError(`${label} contains an unreviewed field.`, "spawn");
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw securityError(`${label} is incomplete.`, "spawn");
  }
  return value;
}

function canonicalGuardPath(value, label, kind = "directory") {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || value.includes("\0")
      || !isAbsolute(value) || normalize(value) !== value) {
    throw securityError(`${label} is not a normalized absolute path.`, "spawn", String(value ?? ""));
  }
  let canonical;
  try { canonical = originalRealpathSync(value); }
  catch { throw securityError(`${label} does not exist.`, "spawn", value); }
  if (canonical !== value) throw securityError(`${label} cannot traverse a symbolic link.`, "spawn", value);
  let metadata;
  try { metadata = fs.lstatSync(canonical); }
  catch { throw securityError(`${label} could not be inspected.`, "spawn", canonical); }
  const currentUID = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
  const correctKind = kind === "file" ? metadata.isFile() : metadata.isDirectory();
  if (!correctKind || (metadata.uid !== currentUID && metadata.uid !== 0) || (metadata.mode & 0o022) !== 0) {
    throw securityError(`${label} has unsafe ownership, type, or permissions.`, "spawn", canonical);
  }
  return canonical;
}

function rejectProfileLocalModuleShadows() {
  const home = canonicalGuardPath(dshHome, "Private Harness home");
  const profiles = join(home, "profiles");
  let profileEntries;
  try { profileEntries = fs.readdirSync(profiles, { withFileTypes: true }); }
  catch (error) {
    if (error?.code === "ENOENT") return;
    throw securityError("Harness profiles could not be inspected safely.", "readdir", profiles);
  }
  if (profileEntries.length > 128) {
    throw securityError("Harness profile count exceeded the reviewed bound.", "readdir", profiles);
  }
  for (const entry of profileEntries) {
    if (entry.name === "node_modules") continue; // installation-owned fallback
    if (entry.isSymbolicLink()) {
      throw securityError("Linked Harness profiles are disabled by Fulmar.", "lstat", join(profiles, entry.name));
    }
    if (!entry.isDirectory()) continue;
    const modules = join(profiles, entry.name, "node_modules");
    let metadata;
    try { metadata = fs.lstatSync(modules); }
    catch (error) {
      if (error?.code === "ENOENT") continue;
      throw securityError("A profile module directory could not be inspected.", "lstat", modules);
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw securityError("Profile-local module overrides are disabled by Fulmar.", "lstat", modules);
    }
    let entries;
    try { entries = fs.readdirSync(modules); }
    catch { throw securityError("A profile module directory could not be read.", "readdir", modules); }
    if (entries.length !== 0) {
      throw securityError("Profile-local module overrides are disabled by Fulmar.", "resolve", modules);
    }
  }
}

rejectProfileLocalModuleShadows();

// The pinned DSH loader resolves a plugin entry's `name` as a normal ESM
// specifier and does not interpolate `!!js` there. Bind the six reviewed
// Fulmar package names to their exact signed in-bundle entry points so
// resolution is independent of DSH_HOME, cwd, NODE_PATH, or a user profile.
function installReviewedRuntimePluginResolver() {
  const runtimeRoot = canonicalGuardPath(allowedNativeRuntimeRoot, "Reviewed runtime root");
  const packageNames = [
    "dsh-credentials-keychain",
    "dsh-mcp-guarded",
    "dsh-client-security-bridge",
    "dsh-performance-profile",
    "dsh-fs-confined",
    "dsh-web-fetch-safe"
  ];
  const targets = new Map();
  for (const packageName of packageNames) {
    const specifier = `@local-harness/${packageName}`;
    const expected = join(runtimeRoot, "node_modules", "@local-harness", packageName, "index.mjs");
    const canonical = canonicalGuardPath(expected, `Bundled plugin ${specifier}`, "file");
    if (canonical !== expected) {
      throw securityError(`Bundled plugin ${specifier} escaped the reviewed runtime.`, "resolve", canonical);
    }
    targets.set(specifier, pathToFileURL(canonical).href);
  }
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const target = targets.get(specifier);
      if (target !== undefined) return { url: target, shortCircuit: true };
      return nextResolve(specifier, context);
    }
  });
}

installReviewedRuntimePluginResolver();
const denyAdditionalLoaderHooks = () => {
  throw securityError("Additional module-loader hooks are disabled by Fulmar.", "module.registerHooks");
};
Object.defineProperties(Module, {
  registerHooks: { value: denyAdditionalLoaderHooks, writable: false, configurable: false },
  register: { value: denyAdditionalLoaderHooks, writable: false, configurable: false }
});
syncBuiltinESMExports();

function exactMCPGuardSchema(plan) {
  exactRecordKeys(plan, mcpGuardPlanKeys, mcpGuardPlanKeys, "MCP guard plan");
  exactRecordKeys(
    plan.executable,
    mcpGuardExecutableKeys,
    new Set(["declaredPath", "canonicalPath", "contentSHA256", "byteCount", "ownerUID", "permissions", "fingerprint"]),
    "MCP guard executable"
  );
  if (!Array.isArray(plan.reviewedArgumentFiles) || plan.reviewedArgumentFiles.length > 16) {
    throw securityError("MCP guard reviewed files are invalid.", "spawn");
  }
  for (const file of plan.reviewedArgumentFiles) {
    exactRecordKeys(file, mcpGuardReviewedFileKeys, mcpGuardReviewedFileKeys, "MCP guard reviewed file");
  }
  exactRecordKeys(plan.project, mcpGuardProjectKeys, mcpGuardProjectKeys, "MCP guard project");
  exactRecordKeys(plan.limits, mcpGuardLimitKeys, mcpGuardLimitKeys, "MCP guard limits");
}

function decodeMCPGuardPlan(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > maxMCPGuardPlanBytes * 2
      || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw securityError("MCP guard plan metadata is invalid.", "spawn");
  }
  let bytes;
  try { bytes = Buffer.from(encoded, "base64url"); }
  catch { throw securityError("MCP guard plan metadata could not be decoded.", "spawn"); }
  if (bytes.length === 0 || bytes.length > maxMCPGuardPlanBytes || bytes.toString("base64url") !== encoded) {
    throw securityError("MCP guard plan metadata is not canonical.", "spawn");
  }
  let plan;
  try { plan = JSON.parse(bytes.toString("utf8")); }
  catch { throw securityError("MCP guard plan metadata is not valid JSON.", "spawn"); }
  exactMCPGuardSchema(plan);
  if (plan.schemaVersion !== 1 || !Array.isArray(plan.arguments) || plan.arguments.length > 64
      || !Array.isArray(plan.credentialVariables) || plan.credentialVariables.length > 12) {
    throw securityError("MCP guard plan metadata uses an unsupported shape.", "spawn");
  }
  const credentialVariables = plan.credentialVariables.map((name) => {
    if (typeof name !== "string" || !mcpGuardCredentialPattern.test(name)
        || mcpGuardForbiddenCredentialNames.has(name) || name.startsWith("DSH_")
        || name.startsWith("DYLD_") || name.startsWith("LD_") || name.startsWith("LOCAL_HARNESS_")) {
      throw securityError("MCP guard plan requested an unsafe credential variable.", "spawn");
    }
    return name;
  });
  if (new Set(credentialVariables).size !== credentialVariables.length) {
    throw securityError("MCP guard plan requested duplicate credential variables.", "spawn");
  }
  return { plan, credentialVariables };
}

function hasMCPGuardMarker(options) {
  const environment = options && typeof options === "object" ? options.env : undefined;
  if (!environment || typeof environment !== "object") return false;
  return mcpGuardEnvironmentNames.some((name) => Object.hasOwn(environment, name));
}

function rejectMCPGuardMarker(options, syscall) {
  if (hasMCPGuardMarker(options)) {
    throw securityError("MCP guard metadata is accepted only by the reviewed asynchronous stdio launch.", syscall);
  }
}

function prepareMCPGuardSpawn(file, args, options) {
  if (!hasMCPGuardMarker(options)) return undefined;
  if (!isPlainRecord(options) || !isPlainRecord(options.env)) {
    throw securityError("MCP guard launch options are invalid.", "spawn");
  }
  for (const key of Object.keys(options)) {
    if (!mcpGuardSpawnOptionKeys.has(key)) {
      throw securityError("MCP guard launch options contain an unreviewed field.", "spawn");
    }
  }
  const environment = options.env;
  if (environment.LOCAL_HARNESS_MCP_GUARD_CHILD !== "1") {
    throw securityError("MCP guard launch marker is invalid.", "spawn");
  }
  for (const name of mcpGuardEnvironmentNames) {
    if (typeof environment[name] !== "string" || environment[name].length === 0) {
      throw securityError("MCP guard launch metadata is incomplete.", "spawn");
    }
  }
  if (file !== process.execPath || !Array.isArray(args) || args.length !== 1) {
    throw securityError("MCP guard launch did not use the exact bundled Node runner contract.", "spawn");
  }
  const runtimeRoot = canonicalGuardPath(allowedNativeRuntimeRoot, "Reviewed runtime root");
  const expectedRunner = join(
    runtimeRoot,
    "node_modules", "@local-harness", "dsh-mcp-guarded", "stdio-guard-runner.mjs"
  );
  canonicalGuardPath(expectedRunner, "Bundled MCP guard runner", "file");
  if (args[0] !== expectedRunner) {
    throw securityError("MCP guard launch attempted to substitute its signed runner.", "spawn", String(args[0] ?? ""));
  }
  if (canonicalGuardPath(process.execPath, "Bundled Node runtime", "file") !== process.execPath) {
    throw securityError("MCP guard launch attempted to substitute its Node runtime.", "spawn", process.execPath);
  }
  if (options.shell !== false || options.windowsHide !== false
      || !Array.isArray(options.stdio) || options.stdio.length !== 3
      || options.stdio[0] !== "pipe" || options.stdio[1] !== "pipe" || options.stdio[2] !== "inherit") {
    throw securityError("MCP guard launch did not use the pinned stdio transport options.", "spawn");
  }

  const { plan, credentialVariables } = decodeMCPGuardPlan(environment.LOCAL_HARNESS_MCP_GUARD_PLAN);
  const project = canonicalGuardPath(plan.project.canonicalPath, "MCP project root");
  if (environment.LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS !== JSON.stringify([project])) {
    throw securityError("MCP guard project metadata does not match the reviewed project.", "spawn");
  }
  const workingDirectory = canonicalGuardPath(plan.workingDirectory, "MCP working directory");
  const projectPrefix = project.endsWith("/") ? project : `${project}/`;
  if ((workingDirectory !== project && !workingDirectory.startsWith(projectPrefix)) || options.cwd !== workingDirectory) {
    throw securityError("MCP guard working directory escaped its reviewed project.", "spawn", String(options.cwd ?? ""));
  }
  const sandboxTemp = canonicalGuardPath(environment.LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP, "MCP sandbox temp root");
  if (environment.TMPDIR !== sandboxTemp) {
    throw securityError("MCP guard temp environment does not match its private sandbox root.", "spawn");
  }

  const childEnvironment = Object.create(null);
  for (const name of mcpGuardBaseEnvironmentNames) {
    const value = environment[name];
    if (typeof value !== "string" || value.length === 0 || value.length > 16_384 || /[\0\r\n]/.test(value)) {
      throw securityError(`MCP guard base environment ${name} is invalid.`, "spawn");
    }
    childEnvironment[name] = value;
  }
  for (const name of mcpGuardEnvironmentNames) childEnvironment[name] = environment[name];
  for (const name of credentialVariables) {
    const value = environment[name];
    if (typeof value !== "string" || value.length === 0 || value.length > 1_048_576 || /[\0\r\n]/.test(value)) {
      throw securityError(`MCP guard credential environment ${name} is missing or invalid.`, "spawn");
    }
    childEnvironment[name] = value;
  }
  childEnvironment.LOCAL_HARNESS_STRICT_LOCAL = "1";
  childEnvironment.LOCAL_HARNESS_WORKSPACE_ROOTS = JSON.stringify([project]);
  childEnvironment.LOCAL_HARNESS_READONLY_ROOTS = "[]";
  childEnvironment.LOCAL_HARNESS_SANDBOX_TEMP = sandboxTemp;

  return {
    arguments: [
      "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
      "--", process.execPath, expectedRunner
    ],
    options: { ...options, cwd: workingDirectory, env: childEnvironment, shell: false, windowsHide: false }
  };
}

function bypassChildSandbox(file) {
  const executable = executableString(file);
  return executable === sandboxHelper
    || executable === credentialHelper
    || executable === performanceTelemetryLockHelper;
}

function credentialHelperOptions(options) {
  if (typeof credentialHome !== "string" || credentialHome.length === 0) {
    throw securityError("The native credential home boundary is missing.", "spawn");
  }
  const home = canonicalGuardPath(credentialHome, "Credential login home");
  const source = options && typeof options === "object" ? options : {};
  if (source.shell) {
    throw securityError("Shell-mode credential helper launches are disabled.", "spawn");
  }
  return {
    ...source,
    shell: false,
    env: {
      HOME: home,
      USER: NS_USER,
      LOGNAME: NS_LOGNAME,
      PATH: "/usr/bin:/bin"
    }
  };
}

const NS_USER = typeof process.env.USER === "string" && process.env.USER.length > 0
  ? process.env.USER : "unknown";
const NS_LOGNAME = typeof process.env.LOGNAME === "string" && process.env.LOGNAME.length > 0
  ? process.env.LOGNAME : NS_USER;

function replaceExecFileOptions(rest, options) {
  if (Array.isArray(rest[0])) {
    if (rest[1] && typeof rest[1] === "object") rest[1] = options;
    else rest.splice(1, 0, options);
  } else if (rest[0] && typeof rest[0] === "object") {
    rest[0] = options;
  } else {
    rest.unshift(options);
  }
  return rest;
}

function supervisorArguments(file, args = []) {
  return ["--supervisor-child", "--", executableString(file), ...args.map(String)];
}

function strictChildOptions(options) {
  const result = options && typeof options === "object" ? { ...options } : {};
  result.env = {
    ...(result.env ?? process.env),
    LOCAL_HARNESS_STRICT_LOCAL: "1"
  };
  if (result.shell) throw securityError("Shell-mode child processes are disabled by Fulmar Strict Local mode.", "spawn");
  return result;
}

function patchChildProcesses() {
  if (!sandboxHelper) throw new Error("Fulmar requires its child-process sandbox helper.");
  const originalSpawn = childProcess.spawn;
  const originalSpawnSync = childProcess.spawnSync;
  const originalExecFile = childProcess.execFile;
  const originalExecFileSync = childProcess.execFileSync;

  childProcess.spawn = function localHarnessSpawn(file, argsOrOptions, maybeOptions) {
    const args = Array.isArray(argsOrOptions) ? argsOrOptions : [];
    const options = Array.isArray(argsOrOptions) ? maybeOptions : argsOrOptions;
    const mcpGuard = prepareMCPGuardSpawn(file, args, options);
    if (mcpGuard) return originalSpawn.call(this, sandboxHelper, mcpGuard.arguments, mcpGuard.options);
    if (executableString(file) === credentialHelper) {
      return originalSpawn.call(this, file, args, credentialHelperOptions(options));
    }
    if (bypassChildSandbox(file)) return originalSpawn.apply(this, arguments);
    return originalSpawn.call(this, sandboxHelper, supervisorArguments(file, args), strictChildOptions(options));
  };

  childProcess.spawnSync = function localHarnessSpawnSync(file, argsOrOptions, maybeOptions) {
    const args = Array.isArray(argsOrOptions) ? argsOrOptions : [];
    const options = Array.isArray(argsOrOptions) ? maybeOptions : argsOrOptions;
    rejectMCPGuardMarker(options, "spawnSync");
    if (executableString(file) === credentialHelper) {
      return originalSpawnSync.call(this, file, args, credentialHelperOptions(options));
    }
    if (bypassChildSandbox(file)) return originalSpawnSync.apply(this, arguments);
    return originalSpawnSync.call(this, sandboxHelper, supervisorArguments(file, args), strictChildOptions(options));
  };

  childProcess.execFile = function localHarnessExecFile(file, ...rest) {
    const args = Array.isArray(rest[0]) ? rest.shift() : [];
    const options = rest[0] && typeof rest[0] === "object" ? rest[0] : undefined;
    rejectMCPGuardMarker(options, "execFile");
    if (executableString(file) === credentialHelper) {
      return originalExecFile.call(this, file, ...replaceExecFileOptions(rest, credentialHelperOptions(options)));
    }
    if (bypassChildSandbox(file)) return originalExecFile.call(this, file, ...rest);
    if (rest[0] && typeof rest[0] === "object") rest[0] = strictChildOptions(rest[0]);
    else rest.unshift(strictChildOptions());
    return originalExecFile.call(this, sandboxHelper, supervisorArguments(file, args), ...rest);
  };

  childProcess.execFileSync = function localHarnessExecFileSync(file, argsOrOptions, maybeOptions) {
    const args = Array.isArray(argsOrOptions) ? argsOrOptions : [];
    const options = Array.isArray(argsOrOptions) ? maybeOptions : argsOrOptions;
    rejectMCPGuardMarker(options, "execFileSync");
    if (executableString(file) === credentialHelper) {
      return originalExecFileSync.call(this, file, args, credentialHelperOptions(options));
    }
    if (bypassChildSandbox(file)) return originalExecFileSync.apply(this, arguments);
    return originalExecFileSync.call(this, sandboxHelper, supervisorArguments(file, args), strictChildOptions(options));
  };

  childProcess.exec = function localHarnessExec(command, options, callback) {
    rejectMCPGuardMarker(typeof options === "function" ? undefined : options, "exec");
    if (typeof options === "function") return originalExecFile.call(this, sandboxHelper, supervisorArguments("/bin/sh", ["-c", command]), strictChildOptions(), options);
    return originalExecFile.call(this, sandboxHelper, supervisorArguments("/bin/sh", ["-c", command]), strictChildOptions(options), callback);
  };

  childProcess.execSync = function localHarnessExecSync(command, options) {
    rejectMCPGuardMarker(options, "execSync");
    return originalExecFileSync.call(this, sandboxHelper, supervisorArguments("/bin/sh", ["-c", command]), strictChildOptions(options));
  };

  childProcess.fork = function localHarnessFork() {
    throw securityError("Forked Node processes are disabled by Fulmar Strict Local mode.", "fork");
  };
}

// Model-facing tools are confined in every privacy mode. Connected mode grants
// the trusted provider transport egress; it never grants arbitrary shell
// commands or plugin children direct network/credential access.
patchChildProcesses();
for (const name of [
  "access", "accessSync", "appendFile", "appendFileSync", "chmod", "chmodSync", "chown", "chownSync",
  "createReadStream", "createWriteStream", "lchmod", "lchmodSync", "lchown", "lchownSync", "lstat", "lstatSync",
  "open", "openSync", "opendir", "opendirSync", "readFile", "readFileSync", "readlink", "readlinkSync",
  "realpath", "realpathSync", "rm", "rmSync", "rmdir", "rmdirSync", "stat", "statSync", "truncate", "truncateSync",
  "unlink", "unlinkSync", "utimes", "utimesSync", "watch", "watchFile", "writeFile", "writeFileSync"
]) wrapPathMethod(fs, name);
for (const name of ["copyFile", "copyFileSync", "cp", "cpSync", "link", "linkSync", "rename", "renameSync"]) {
  wrapPathMethod(fs, name, [0, 1]);
}
for (const name of [
  "access", "appendFile", "chmod", "chown", "lchmod", "lchown", "lstat", "open", "opendir", "readFile",
  "readlink", "realpath", "rm", "rmdir", "stat", "truncate", "unlink", "utimes", "writeFile"
]) wrapPathMethod(fs.promises, name);
for (const name of ["copyFile", "cp", "link", "rename"]) wrapPathMethod(fs.promises, name, [0, 1]);

// Block direct access to Node's private syscall bindings. Reviewed built-ins use
// the public modules captured above; untrusted code must not bypass those
// guards by constructing raw TCP/UDP/DNS/process handles.
const deniedBindings = new Set(["tcp_wrap", "udp_wrap", "cares_wrap", "process_wrap", "spawn_sync", "pipe_wrap"]);
for (const property of ["binding", "_linkedBinding"]) {
  const original = process[property];
  if (typeof original !== "function") continue;
  process[property] = function localHarnessBinding(name, ...args) {
    if (deniedBindings.has(String(name))) throw securityError("Direct native binding access is disabled by Fulmar.", `process.${property}`, String(name));
    return original.call(this, name, ...args);
  };
}

const originalDlopen = process.dlopen;
if (typeof originalDlopen === "function") {
  process.dlopen = function localHarnessDlopen(module, filename, ...args) {
    const candidate = canonicalCandidate(filename);
    const root = allowedNativeRuntimeRoot === undefined ? undefined : canonicalCandidate(allowedNativeRuntimeRoot);
    if (!candidate || !root || (candidate !== root && !candidate.startsWith(`${root}/`))) {
      throw securityError("Native addons outside the signed Harness runtime are disabled.", "process.dlopen", String(candidate ?? filename));
    }
    return originalDlopen.call(this, module, filename, ...args);
  };
}

{
  wrapHTTPModule(http, "http");
  wrapHTTPModule(https, "https");

  for (const name of ["connect", "createConnection"]) {
    const original = net[name];
    net[name] = function localHarnessNet(...args) {
      const destination = numericConnectDestination(args, "tcp:", false);
      const capability = guardedFetchTLSContext.getStore();
      assertSafeConnectionOptions(connectionOptionsFromArgs(args), `net.${name}`, {
        allowReviewedAuxiliaryLookup: auxiliaryWebFetchContext.getStore() !== undefined,
        allowReviewedProviderLookup: capability?.kind === "provider"
      });
      assertRawTCPAllowed(destination, `net.${name}`);
      if (capability?.kind === "provider" && isGuardedFetchStreamDestination(destination)) {
        const reviewed = argumentsWithProviderLookup(args, capability);
        return enforceProviderPeer(
          original.apply(this, reviewed.arguments),
          "connect",
          capability,
          reviewed.state
        );
      }
      return original.apply(this, args);
    };
  }
  const originalSocketConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function localHarnessSocketConnect(...args) {
    const destination = numericConnectDestination(args, "tcp:", false);
    const capability = guardedFetchTLSContext.getStore();
    assertSafeConnectionOptions(connectionOptionsFromArgs(args), "net.Socket.connect", {
      allowReviewedAuxiliaryLookup: auxiliaryWebFetchContext.getStore() !== undefined,
      allowReviewedProviderLookup: capability?.kind === "provider"
    });
    assertRawTCPAllowed(destination, "net.Socket.connect");
    if (capability?.kind === "provider" && isGuardedFetchStreamDestination(destination)) {
      const reviewed = argumentsWithProviderLookup(args, capability);
      const result = originalSocketConnect.apply(this, reviewed.arguments);
      enforceProviderPeer(this, "connect", capability, reviewed.state);
      return result;
    }
    return originalSocketConnect.apply(this, args);
  };
  const originalTLSConnect = tls.connect;
  tls.connect = function localHarnessTLS(...args) {
    const destination = numericConnectDestination(args, "tls:", true);
    const auxiliaryCapability = auxiliaryWebCapabilityFor(destination, "tls:");
    const guardedCapability = guardedFetchTLSContext.getStore();
    assertSafeConnectionOptions(connectionOptionsFromArgs(args), "tls.connect", {
      tlsTransport: true,
      destination: destinationFromOptions(destination, "tls:"),
      allowReviewedAuxiliaryLookup: auxiliaryCapability !== undefined,
      allowReviewedProviderLookup: guardedCapability?.kind === "provider"
    });
    assertNetworkAllowed(destination, "tls.connect", "tls:");
    if (isGuardedFetchTLSDestination(destination)) {
      let reviewedArguments = args;
      let providerResolution;
      if (auxiliaryCapability !== undefined) {
        reviewedArguments = tlsArgumentsWithAuxiliaryLookup(args, auxiliaryCapability);
      } else if (guardedCapability?.kind === "provider") {
        providerResolution = argumentsWithProviderLookup(args, guardedCapability);
        reviewedArguments = providerResolution.arguments;
      }
      const socket = originalTLSConnect.apply(this, reviewedArguments);
      if (auxiliaryCapability !== undefined) {
        socket.prependOnceListener("secureConnect", () => {
          if (!isPublicIPAddress(socket.remoteAddress)) {
            socket.destroy(securityError(
              "The approved web request connected to a private or reserved network address.",
              "tls.connect",
              String(socket.remoteAddress ?? auxiliaryCapability.host)
            ));
          }
        });
      } else if (guardedCapability?.kind === "provider" && providerResolution !== undefined) {
        enforceProviderPeer(socket, "secureConnect", guardedCapability, providerResolution.state);
      }
      return socket;
    }
    throw securityError(
      "Direct TLS clients are disabled; use the guarded fetch transport.",
      "tls.connect",
      String(destinationFromOptions(destination, "tls:").host ?? "network destination")
    );
  };
  http2.connect = function localHarnessHTTP2(authority, ...args) {
    const options = isPlainRecord(args[0]) ? args[0] : undefined;
    let destination = authority;
    if (options) {
      const base = destinationFromOptions(authority, "https:");
      const overridesHost = Object.hasOwn(options, "hostname") || Object.hasOwn(options, "host");
      const overridesPort = Object.hasOwn(options, "port") || embeddedPortFromOptions(options) !== undefined;
      destination = options.socketPath ? { socketPath: options.socketPath } : {
        protocol: options.protocol ?? (base.scheme === undefined ? "https:" : `${base.scheme}:`),
        hostname: overridesHost ? hostnameFromOptions(options, "https:") : base.host,
        port: overridesPort ? (options.port ?? embeddedPortFromOptions(options)) : base.port
      };
    }
    const effectiveDestination = destinationFromOptions(destination, "https:");
    assertSafeConnectionOptions(options, "http2.connect", {
      tlsTransport: true,
      destination: effectiveDestination
    });
    assertNetworkAllowed(destination, "http2.connect", "https:");
    throw securityError(
      "Direct HTTP/2 clients are disabled; use the guarded fetch transport.",
      "http2.connect",
      String(effectiveDestination.host ?? "network destination")
    );
  };

  const originalDatagramConnect = dgram.Socket.prototype.connect;
  dgram.Socket.prototype.connect = function localHarnessDatagramConnect(port, address, callback) {
    assertDatagramAllowed({ host: typeof address === "string" ? address : "localhost" }, "dgram.connect");
    return originalDatagramConnect.call(this, port, address, callback);
  };
  const originalDatagramSend = dgram.Socket.prototype.send;
  dgram.Socket.prototype.send = function localHarnessDatagramSend(...sendArgs) {
    // All documented overloads place the optional destination address after
    // the message argument. A callback can be last, so inspect every remaining
    // string rather than just the final argument.
    const addresses = sendArgs.slice(1).filter((value) => typeof value === "string");
    assertDatagramAllowed({ host: addresses.at(-1) ?? "localhost" }, "dgram.send");
    return originalDatagramSend.apply(this, sendArgs);
  };
  const originalDatagramBind = dgram.Socket.prototype.bind;
  // Node routes even numeric bind addresses through dns.lookup internally.
  // This depth is raised only around an already-validated literal loopback
  // bind, so the internal numeric normalization can run without reopening a
  // public DNS escape hatch in Strict Local mode.
  let validatedLiteralLoopbackBindDepth = 0;
  dgram.Socket.prototype.bind = function localHarnessDatagramBind(...bindArgs) {
    assertLoopbackDatagramBind(bindArgs);
    validatedLiteralLoopbackBindDepth += 1;
    try {
      return originalDatagramBind.apply(this, bindArgs);
    } finally {
      validatedLiteralLoopbackBindDepth -= 1;
    }
  };

  const originalServerListen = net.Server?.prototype?.listen;
  if (typeof originalServerListen === "function") {
    net.Server.prototype.listen = function localHarnessServerListen(...listenArgs) {
      assertLoopbackListener(listenArgs, "net.Server.listen");
      validatedLiteralLoopbackBindDepth += 1;
      try {
        return originalServerListen.apply(this, listenArgs);
      } finally {
        validatedLiteralLoopbackBindDepth -= 1;
      }
    };
  }

  function wrapDNSMethod(object, name, hostnameIndex = 0) {
    const original = object?.[name];
    if (typeof original !== "function") return;
    object[name] = function localHarnessDNS(...args) {
      if (validatedLiteralLoopbackBindDepth > 0 && isLiteralLoopbackHost(args[hostnameIndex])) {
        return original.apply(this, args);
      }
      // Provider and auxiliary transports resolve through the captured
      // `originalDNSLookup` capability injected into one guarded connection.
      // Public DNS APIs remain unavailable to plugins, tools, and model code,
      // including while an asynchronous provider request is in flight.
      throw securityError(
        "Direct DNS APIs are disabled; reviewed transports resolve their exact hostname internally.",
        `dns.${name}`,
        String(args[hostnameIndex] ?? "DNS destination")
      );
    };
  }
  for (const name of ["lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"]) {
    wrapDNSMethod(dns, name);
    wrapDNSMethod(dns.promises, name);
    wrapDNSMethod(dns.Resolver?.prototype, name);
    wrapDNSMethod(dns.promises?.Resolver?.prototype, name);
  }
  for (const target of [dns, dns.Resolver?.prototype, dns.promises?.Resolver?.prototype]) {
    if (typeof target?.setServers !== "function") continue;
    target.setServers = function localHarnessDNSSetServers() {
      throw securityError("Custom DNS resolver destinations are disabled by Fulmar.", "dns.setServers");
    };
  }

  if (typeof process.execve === "function") {
    process.execve = function localHarnessExecve() {
      throw securityError("Direct process replacement is disabled by Fulmar Strict Local mode.", "execve");
    };
  }

  function providerResponseSizeError() {
    const error = new Error(`Provider response exceeded the Fulmar ${maximumProviderResponseBytes}-byte limit.`);
    error.code = "EMSGSIZE";
    error.syscall = "fetch";
    return error;
  }

  async function boundProviderResponse(response) {
    const declaredText = response.headers.get("content-length");
    const declared = declaredText === null ? undefined : Number(declaredText);
    if (Number.isSafeInteger(declared) && declared > maximumProviderResponseBytes) {
      try { await response.body?.cancel(); } catch {}
      throw providerResponseSizeError();
    }
    if (!response.body) return response;

    let received = 0;
    const boundedBody = response.body.pipeThrough(new TransformStream({
      transform(chunk, controller) {
        const size = chunk instanceof Uint8Array ? chunk.byteLength : Buffer.byteLength(String(chunk));
        if (size > maximumProviderResponseBytes - received) {
          controller.error(providerResponseSizeError());
          return;
        }
        received += size;
        controller.enqueue(chunk);
      }
    }));
    const bounded = new Response(boundedBody, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
    for (const property of ["url", "redirected", "type"]) {
      Object.defineProperty(bounded, property, { value: response[property] });
    }
    return bounded;
  }

  if (typeof globalThis.fetch === "function") {
    const originalFetch = globalThis.fetch;
    const OriginalRequest = globalThis.Request;
    globalThis.fetch = function localHarnessFetch(resource, ...args) {
      if (args.length > 1) {
        throw securityError("Fetch accepts only one reviewed options record.", "fetch");
      }
      const reviewedOptions = reviewedFetchOptions(args[0]);
      if (Object.hasOwn(reviewedOptions, "body")
          && reviewedOptions.body !== undefined
          && reviewedOptions.body !== null
          && typeof reviewedOptions.body !== "string") {
        throw securityError("Fetch bodies must be immutable reviewed text.", "fetch");
      }
      if (resource instanceof OriginalRequest
          && resource.body !== null
          && !Object.hasOwn(reviewedOptions, "body")) {
        throw securityError("Request-carried streaming fetch bodies are disabled by Fulmar.", "fetch");
      }
      const request = new OriginalRequest(resource, reviewedOptions);
      assertNetworkAllowed(request.url, "fetch", "http:");
      if (containsAuthorityHeader(request.headers)) {
        throw securityError("Caller-controlled HTTP authority headers are disabled by Fulmar.", "fetch");
      }
      // Defense in depth for current and future adapters: Fulmar does
      // not disclose a stable installation identifier or its internal session
      // identifier to a model provider. The pinned DeepSeek adapter is patched
      // not to create them; this boundary also strips an accidental reintroduction.
      for (const header of privacyFilteredProviderHeaders) request.headers.delete(header);
      const tlsOrigin = guardedFetchTLSOrigin(request.url);
      return guardedFetchTLSContext.run(
        tlsOrigin,
        () => originalFetch.call(this, request).then(boundProviderResponse)
      );
    };
  }

  const auxiliaryBridgeSymbol = Symbol.for("com.fulmar.runtime.approved-web-fetch.v1");
  const auxiliaryBridge = Object.freeze({
    normalize(value) {
      return normalizeAuxiliaryWebURL(value).href;
    },
    fetch(value, signal) {
      const url = normalizeAuxiliaryWebURL(value);
      const capability = Object.freeze({ host: url.hostname });
      return auxiliaryWebFetchContext.run(capability, () => globalThis.fetch(url, {
        method: "GET",
        headers: {
          Accept: "text/html,application/xhtml+xml,text/plain,application/json;q=0.8",
          "User-Agent": "Fulmar/1 approved-web-fetch"
        },
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        referrerPolicy: "no-referrer",
        signal
      }));
    }
  });
  Object.defineProperty(globalThis, auxiliaryBridgeSymbol, {
    value: auxiliaryBridge,
    enumerable: false,
    writable: false,
    configurable: true
  });
  if (typeof globalThis.WebSocket === "function") {
    // All qualified provider adapters use the reviewed, bounded fetch path.
    // A generic WebSocket would bypass response/frame/queue limits and the
    // provider privacy-header filter, so even an otherwise approved origin is
    // denied until a separately bounded protocol is implemented and qualified.
    class LocalHarnessDisabledWebSocket {
      constructor() {
        throw securityError(
          "Outbound provider WebSocket transport is not a reviewed Fulmar protocol.",
          "WebSocket"
        );
      }
    }
    Object.defineProperties(LocalHarnessDisabledWebSocket, {
      CONNECTING: { value: 0 },
      OPEN: { value: 1 },
      CLOSING: { value: 2 },
      CLOSED: { value: 3 }
    });
    globalThis.WebSocket = LocalHarnessDisabledWebSocket;
  }
}

const originalCreateServer = http.createServer;
const cookieName = "LocalHarnessSession";
const healthPath = "/_local_harness/health";
const bootstrapPath = "/_local_harness/bootstrap";

function constantTimeEqual(candidate) {
  if (typeof candidate !== "string") return false;
  // Avoid allocating attacker-controlled buffers for malformed or oversized
  // loopback headers. Tokens generated by the app are far smaller than this.
  if (candidate.length > 512) return false;
  const expected = Buffer.from(token, "utf8");
  const actual = Buffer.from(candidate, "utf8");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function cookieValue(request) {
  const raw = request.headers.cookie;
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > 8_192) return undefined;
  for (const item of raw.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    if (item.slice(0, separator).trim() === cookieName) {
      const encoded = item.slice(separator + 1).trim();
      if (encoded.length > 512) return undefined;
      try { return decodeURIComponent(encoded); }
      catch { return undefined; }
    }
  }
  return undefined;
}

function headerValue(request) {
  const value = request.headers["x-local-harness-token"];
  return Array.isArray(value) ? value[0] : value;
}

function isLoopbackRequest(request) {
  const remote = request.socket?.remoteAddress;
  if (remote !== "127.0.0.1" && remote !== "::1" && remote !== "::ffff:127.0.0.1") return false;
  return /^127\.0\.0\.1:\d{1,5}$/.test(request.headers.host ?? "");
}

function isAuthorized(request) {
  if (!isLoopbackRequest(request)) return false;
  return constantTimeEqual(headerValue(request)) || constantTimeEqual(cookieValue(request));
}

function pathname(request) {
  try { return new URL(request.url ?? "/", "http://127.0.0.1").pathname; }
  catch { return ""; }
}

function harden(request, response) {
  const webSocketOrigin = /^127\.0\.0\.1:\d{1,5}$/.test(request?.headers?.host ?? "")
    ? `ws://${request.headers.host}`
    : "'none'";
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Content-Security-Policy", `default-src 'self' blob: data:; connect-src 'self' ${webSocketOrigin}; img-src 'self' blob: data:; media-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; worker-src 'self' blob:; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`);
}

function rejectHTTP(request, response) {
  harden(request, response);
  response.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Fulmar authentication required.");
}

function handleBootstrap(request, response) {
  if (!isLoopbackRequest(request) || !constantTimeEqual(headerValue(request))) return rejectHTTP(request, response);
  harden(request, response);
  response.writeHead(303, {
    Location: "/",
    "Set-Cookie": `${cookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/`
  });
  response.end();
}

function handleHealth(request, response) {
  if (!isAuthorized(request)) return rejectHTTP(request, response);
  const body = JSON.stringify({ service: "app.localharness.runtime", protocolVersion: 1, nonce, pid: process.pid });
  harden(request, response);
  response.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  response.end(body);
}

function allowRequest(request, response) {
  const path = pathname(request);
  if (path === bootstrapPath) { handleBootstrap(request, response); return false; }
  if (path === healthPath) { handleHealth(request, response); return false; }
  if (!isAuthorized(request)) { rejectHTTP(request, response); return false; }
  harden(request, response);
  return true;
}

function wrapUpgradeListener(listener) {
  return function localHarnessUpgrade(request, socket, head) {
    if (!isAuthorized(request)) {
      socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    return listener.call(this, request, socket, head);
  };
}

const guardedServerPrototype = Symbol("LocalHarnessGuardedServerPrototype");

function guardServerPrototype(prototype) {
  if (!prototype || prototype[guardedServerPrototype]) return;
  const originalEmit = prototype.emit;
  if (typeof originalEmit !== "function") return;
  Object.defineProperty(prototype, guardedServerPrototype, { value: true });
  prototype.emit = function localHarnessServerEmit(eventName, ...eventArgs) {
    if (eventName === "request" && !allowRequest(eventArgs[0], eventArgs[1])) return false;
    if (eventName === "upgrade" && !isAuthorized(eventArgs[0])) {
      eventArgs[1]?.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      return false;
    }
    return originalEmit.call(this, eventName, ...eventArgs);
  };
}

// Protect both callback-style and server.on("request") servers, including
// direct `new http.Server()` construction. This closes the gap left by wrapping
// only createServer's optional callback.
guardServerPrototype(http.Server?.prototype);
guardServerPrototype(https.Server?.prototype);

function guardHTTP2Server(server) {
  const originalEmit = server?.emit?.bind(server);
  if (!originalEmit || server[guardedServerPrototype]) return server;
  Object.defineProperty(server, guardedServerPrototype, { value: true });
  server.emit = function localHarnessHTTP2Emit(eventName, ...eventArgs) {
    if (eventName === "stream") {
      const stream = eventArgs[0];
      const headers = eventArgs[1] ?? {};
      const request = {
        headers: { ...headers, host: headers[":authority"] ?? headers.host },
        socket: stream?.session?.socket,
        url: headers[":path"] ?? "/"
      };
      if (!isAuthorized(request)) {
        try { stream.respond({ ":status": 401, "cache-control": "no-store" }); stream.end(); } catch {}
        return false;
      }
    }
    return originalEmit(eventName, ...eventArgs);
  };
  return server;
}

for (const factoryName of ["createServer", "createSecureServer"]) {
  const original = http2[factoryName];
  if (typeof original === "function") {
    http2[factoryName] = function localHarnessHTTP2Server(...args) {
      return guardHTTP2Server(original.apply(this, args));
    };
  }
}

// The reviewed Standard preset does not require worker threads. A Worker can
// otherwise deliberately drop execArgv and escape this preload's controls.
if (typeof workerThreads.Worker === "function") {
  workerThreads.Worker = new Proxy(workerThreads.Worker, {
    construct() {
      throw securityError("Worker threads are disabled by Fulmar because they bypass the reviewed runtime boundary.", "Worker");
    }
  });
}

syncBuiltinESMExports();
